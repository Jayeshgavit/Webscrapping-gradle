

#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import requests
from bs4 import BeautifulSoup
import time
import json
import psycopg2
from dotenv import load_dotenv
import os
from concurrent.futures import ThreadPoolExecutor, as_completed

# ---------------------------
# DB config
# ---------------------------
load_dotenv()
DB_CONFIG = {
    "host": os.getenv("DB_HOST", "localhost"),
    "dbname": os.getenv("DB_NAME", "Gradle"),
    "user": os.getenv("DB_USER", "postgres"),
    "password": os.getenv("DB_PASS", "623809"),
    "port": int(os.getenv("DB_PORT", 5432)),
}
TABLE_NAME = "staging_table"

# ---------------------------
# DB helper functions
# ---------------------------
def get_conn():
    return psycopg2.connect(**DB_CONFIG)

def create_table():
    ddl = f"""
    CREATE TABLE IF NOT EXISTS {TABLE_NAME} (
        staging_id SERIAL PRIMARY KEY,
        vendor_name TEXT NOT NULL DEFAULT 'Gradle',
        source_url TEXT UNIQUE,
        raw_data JSONB NOT NULL,
        processed BOOLEAN DEFAULT FALSE,
        processed_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
    );
    """
    conn = get_conn()
    cursor = conn.cursor()
    cursor.execute(ddl)
    conn.commit()
    cursor.close()
    conn.close()
    print(f"Table '{TABLE_NAME}' ready.")

def insert_advisory(source_url, raw_data):
    try:
        conn = get_conn()
        cursor = conn.cursor()
        cursor.execute(
            f"""
            INSERT INTO {TABLE_NAME} (source_url, raw_data)
            VALUES (%s, %s)
            ON CONFLICT (source_url) DO NOTHING;
            """,
            (source_url, json.dumps(raw_data))
        )
        conn.commit()
        cursor.close()
        conn.close()
        print(f"Inserted advisory: {source_url}")
    except Exception as e:
        print(f"DB insert error: {e}")

# ---------------------------
# Web scraping
# ---------------------------
BASE_URL = "https://github.com/gradle/gradle/security/advisories"
GITHUB_BASE = "https://github.com"
HEADERS = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}

def fetch_page(page_num):
    url = f"{BASE_URL}?state=published&page={page_num}"
    response = requests.get(url, headers=HEADERS)
    if response.status_code != 200:
        print(f"Failed to fetch page {page_num}: {response.status_code}")
        return None
    return BeautifulSoup(response.text, "html.parser")

def fetch_advisory_details(link):
    """Fetch detailed advisory info from the advisory page"""
    try:
        response = requests.get(link, headers=HEADERS, timeout=15)
        if response.status_code != 200:
            print(f"Failed to fetch advisory page: {link}")
            return {}

        soup = BeautifulSoup(response.text, "html.parser")
        data = {}

        # ------------------ CVE ID ------------------
        cve_tag = soup.find("h3", string="CVE ID")
        data["CVE_ID"] = cve_tag.find_next("div").text.strip() if cve_tag and cve_tag.find_next("div") else None

        # ------------------ Severity ------------------
        sev_tag = soup.find("span", class_="Label", title=lambda x: x and x.startswith("Severity:"))
        data["Severity"] = sev_tag.text.strip() if sev_tag else None

        # ------------------ CVSS Score ------------------
        cvss_div = soup.find("div", class_="d-flex flex-items-baseline pb-1")
        cvss_score = None
        if cvss_div:
            button_span = cvss_div.find("span", class_="Button-label")
            if button_span:
                cvss_score = button_span.text.strip()
        data["CVSS_Score"] = cvss_score

        # ------------------ CVSS Vector ------------------
        cvss_vector_tag = soup.find(string=lambda t: t and t.startswith("CVSS:"))
        data["CVSS_Vector"] = cvss_vector_tag.strip() if cvss_vector_tag else None

        # ------------------ CWE IDs ------------------
        cwe_data = []

        weaknesses_div = soup.find("div", class_="discussion-sidebar-item js-repository-advisory-details")
        if weaknesses_div:
            for details in weaknesses_div.find_all("details"):
                summary_span = details.find("summary").find("span", recursive=False)
                cwe_id = summary_span.text.strip() if summary_span else None

                desc_div = details.find("div", class_="px-2 pb-2")
                if desc_div:
                    desc_text_tag = desc_div.find("span")
                    desc_text = desc_text_tag.text.strip() if desc_text_tag else ""
                    mitre_link_tag = desc_div.find("a", href=lambda h: h and "cwe.mitre.org" in h)
                    mitre_link = mitre_link_tag["href"] if mitre_link_tag else None
                else:
                    desc_text = ""
                    mitre_link = None

                if cwe_id:
                    cwe_data.append({
                        "CWE": cwe_id,
                        "Description": desc_text,
                        "MITRE_Link": mitre_link
                    })

        # Fallback: find all text starting with CWE-
        if not cwe_data:
            for span in soup.find_all(string=True):
                if span.strip().startswith("CWE-"):
                    cwe_data.append({"CWE": span.strip(), "Description": "", "MITRE_Link": None})

        data["CWEs"] = cwe_data

        # ------------------ CVSS v3 Base Metrics ------------------
        base_metrics = {}
        metrics_div = soup.find("div", class_="d-flex flex-column mt-2 p-2 border rounded-2")
        if metrics_div:
            for row in metrics_div.find_all("div", class_="d-flex p-1 flex-justify-between"):
                try:
                    key = row.contents[0].strip()
                    value_tag = row.find("div", class_="color-fg-default text-semibold ml-2")
                    value = value_tag.text.strip() if value_tag else None
                    if key and value:
                        base_metrics[key] = value
                except Exception:
                    continue
        data["CVSSv3_Base_Metrics"] = base_metrics

        # ------------------ Products / Versions ------------------
        products = []
        for box in soup.find_all("div", class_="Box Box--responsive"):
            try:
                name_tag = box.find("h2", string="Package")
                if not name_tag:
                    continue
                parent = name_tag.find_parent("div", class_="Box-body")
                package_name = parent.find("span", class_="f4 color-fg-default text-bold").text.strip()
                affected_tag = parent.find("h2", string="Affected versions")
                affected_ver = affected_tag.find_next("div").text.strip() if affected_tag else None
                patched_tag = parent.find("h2", string="Patched versions")
                patched_ver = patched_tag.find_next("div").text.strip() if patched_tag else None
                products.append({
                    "Package": package_name,
                    "Affected_Version": affected_ver,
                    "Patched_Version": patched_ver
                })
            except Exception:
                continue
        data["Products"] = products

        # ------------------ Description / Impact / Patches / Workarounds / Related Info ------------------
        description = {}
        other_info_links = []
        main_box = soup.find_all("div", class_="Box-body")
        for box in main_box:
            for h2 in box.find_all("h2"):
                title = h2.text.strip()
                parent = h2.find_parent("div", class_="Box-body")
                content = ""
                if parent:
                    for tag in parent.find_all(["p", "ul"], recursive=False):
                        if tag.name == "p":
                            content += tag.text.strip() + "\n"
                        elif tag.name == "ul":
                            for li in tag.find_all("li"):
                                content += li.text.strip() + "\n"
                    # Collect links
                    for a_tag in parent.find_all("a", href=True):
                        other_info_links.append(a_tag["href"])
                if content:
                    description[title] = content
        data["Description"] = description
        data["Other_Information_Links"] = list(set(other_info_links))

        return data

    except Exception as e:
        print(f"Error fetching {link}: {e}")
        return {}

# ---------------------------
# Parse advisories list page
# ---------------------------
def parse_advisories(soup):
    advisories = []
    rows = soup.find_all("li", class_="Box-row")
    for row in rows:
        try:
            title_tag = row.find("a", class_="Link--primary")
            title = title_tag.text.strip()
            link = GITHUB_BASE + title_tag["href"]

            ghsa_id = row.find("div", class_="mt-1 text-small color-fg-muted").text.strip().split()[0]
            date_tag = row.find("relative-time")
            date = date_tag["datetime"] if date_tag else "Unknown"
            author_tag = row.find("a", class_="author")
            author = author_tag.text.strip() if author_tag else "Unknown"
            severity_tag = row.find("span", class_="Label")
            severity = severity_tag.text.strip() if severity_tag else "Unknown"

            advisories.append({
                "Title": title,
                "Link": link,
                "GHSA_ID": ghsa_id,
                "Published_Date": date,
                "Author": author,
                "Severity": severity
            })
        except Exception as e:
            print(f"Error parsing row: {e}")
    return advisories

# ---------------------------
# Fetch all advisories with concurrency
# ---------------------------
def fetch_all_advisories(max_workers=10):
    all_advisories = []
    page_num = 1

    while True:
        print(f"Fetching page {page_num}...")
        soup = fetch_page(page_num)
        if not soup:
            break

        page_advisories = parse_advisories(soup)
        if not page_advisories:
            print("No more advisories found. Ending.")
            break

        # Fetch advisory details concurrently
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_adv = {executor.submit(fetch_advisory_details, adv["Link"]): adv for adv in page_advisories}
            for future in as_completed(future_to_adv):
                adv = future_to_adv[future]
                adv_details = future.result()
                adv["CVE_Details"] = adv_details
                insert_advisory(adv["Link"], adv)
                all_advisories.append(adv)

        page_num += 1
        time.sleep(0.5)

    return all_advisories

# ---------------------------
# Main
# ---------------------------
if __name__ == "__main__":
    create_table()
    advisories = fetch_all_advisories()
    print(f"\nTotal advisories stored: {len(advisories)}")
