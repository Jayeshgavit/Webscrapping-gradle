#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import re
import time
import json
import os
import warnings
from datetime import datetime, timezone
from urllib.parse import urljoin

import requests
from bs4 import BeautifulSoup
import psycopg2
from dotenv import load_dotenv
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry

# ---------------------------
# Suppress warnings
# ---------------------------
warnings.filterwarnings("ignore", category=ResourceWarning)
requests.packages.urllib3.disable_warnings()

# ---------------------------
# Load .env DB config
# ---------------------------
load_dotenv()
DB_CONFIG = {
    "host": os.getenv("DB_HOST", "localhost"),
    "dbname": os.getenv("DB_NAME", "Gradle"),
    "user": os.getenv("DB_USER", "postgres"),
    "password": os.getenv("DB_PASS", ""),
    "port": int(os.getenv("DB_PORT", 5432)),
}
TABLE_NAME = os.getenv("TABLE_NAME", "staging_table")
OWNER_REPO = os.getenv("OWNER_REPO", "gradle/gradle")
BASE_URL = f"https://github.com/{OWNER_REPO}/security/advisories"
GITHUB_BASE = "https://github.com"

# ---------------------------
# DB Helpers
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
        processed_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
    );
    """
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(ddl)
            conn.commit()

def insert_advisory(source_url, raw_data):
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                f"""
                INSERT INTO {TABLE_NAME} (source_url, raw_data)
                VALUES (%s, %s)
                ON CONFLICT (source_url) DO NOTHING;
                """,
                (source_url, json.dumps(raw_data))
            )
            conn.commit()

# ---------------------------
# Requests session
# ---------------------------
session = requests.Session()
retry = Retry(total=5, backoff_factor=0.5, status_forcelist=[500,502,503,504])
adapter = HTTPAdapter(max_retries=retry)
session.mount("https://", adapter)
session.mount("http://", adapter)
HEADERS = {"User-Agent": "Mozilla/5.0 (compatible; ghsa-scraper/1.0)"}

# ---------------------------
# Utilities
# ---------------------------
def normalize_href(href):
    if href and href.startswith("/"):
        return urljoin(GITHUB_BASE, href)
    return href

def get_h3_section_text(soup, heading):
    """Return text under <h3> heading until next heading"""
    for h in soup.find_all(["h2", "h3"]):
        if heading.lower() in h.get_text(" ", strip=True).lower():
            parts = []
            for sib in h.find_next_siblings():
                if sib.name in ["h1","h2","h3"]:
                    break
                if sib.name == "p":
                    parts.append(sib.get_text(" ", strip=True))
                elif sib.name == "ul":
                    for li in sib.find_all("li"):
                        parts.append(li.get_text(" ", strip=True))
            return "\n".join(parts).strip() if parts else None
    return None

def get_links_section_after_h3(soup, heading_text):
    """Return li text+href under h3 heading (for 'Other Information')"""
    for h in soup.find_all(["h2","h3"]):
        if heading_text.lower() in h.get_text(" ", strip=True).lower():
            links = []
            for sib in h.find_next_siblings():
                if sib.name in ["h1","h2","h3"]:
                    break
                for li in sib.find_all("li"):
                    a = li.find("a", href=True)
                    if a:
                        links.append({
                            "text": a.get_text(" ", strip=True),
                            "href": normalize_href(a["href"])
                        })
            return links
    return []

# ---------------------------
# Extract CWE IDs
# ---------------------------
def extract_cwes(soup):
    cwes = []
    seen = set()
    for span in soup.select("div.js-repository-advisory-details details summary span"):
        text = span.get_text(strip=True)
        if text.upper().startswith("CWE-") and text not in seen:
            cwes.append(text)
            seen.add(text)
    return cwes

def extract_cwe_data(soup):
    cwe_list = []
    seen = set()
    for a in soup.find_all("a", href=True):
        text = a.get_text(" ", strip=True)
        if re.match(r"CWE-\d+", text) and text not in seen:
            cwe_list.append({
                "CWE_ID": text,
                "Text": text,
                "URL": normalize_href(a["href"])
            })
            seen.add(text)
    return cwe_list

# ---------------------------
# Extract Sidebar Data (CVE, CVSS, CWE)
# ---------------------------
def extract_sidebar_data(soup):
    sidebar_data = {}
    for item in soup.select("div.discussion-sidebar-item"):
        header_tag = item.find("h3")
        key = header_tag.get_text(" ", strip=True) if header_tag else None
        value = None
        # CVE ID
        if key and key.lower() == "cve id":
            cve_div = item.find("div", class_="color-fg-muted")
            if cve_div:
                sidebar_data["CVE ID"] = cve_div.get_text(" ", strip=True)
        # Severity / CVSS
        elif key and key.lower() == "severity":
            score_btn = item.select_one("span.Button-label")
            if score_btn and re.match(r"^\d+(\.\d+)?$", score_btn.text.strip()):
                sidebar_data["CVSS Score"] = score_btn.text.strip()
            vector_tag = item.find(lambda t: t.name=="div" and t.get_text(strip=True).startswith("CVSS:"))
            if vector_tag:
                sidebar_data["CVSS Vector"] = vector_tag.get_text(strip=True)
            label_tag = item.select_one("span.Label")
            if label_tag:
                sidebar_data["Severity"] = label_tag.get_text(strip=True)
        # Weaknesses / CWE IDs
        elif key and key.lower() == "weaknesses":
            cwe_list = []
            for a_tag in item.select("a[href]"):
                if re.match(r"CWE-\d+", a_tag.text.strip()):
                    cwe_list.append(a_tag.text.strip())
            if cwe_list:
                sidebar_data["Weaknesses"] = ", ".join(cwe_list)
    return sidebar_data

# ---------------------------
# Extract Products with multiple versions and extra info
# ---------------------------
def extract_products(soup):
    products = {}
    for box in soup.select("div.Box-body"):
        for row in box.select("div.Bow-row"):
            # Package name
            pkg_tag = row.select_one("span.f4.color-fg-default.text-bold")
            extra_tag = row.select_one("span.color-fg-muted")
            if pkg_tag:
                pkg_name = pkg_tag.get_text(strip=True)
                extra_info = extra_tag.get_text(strip=True) if extra_tag else ""
            else:
                pkg_name = "No package listed"
                extra_tag = row.select_one("span.f4.color-fg-muted")
                extra_info = extra_tag.get_text(strip=True) if extra_tag else ""
            # Affected versions
            affected_divs = row.select("div.col-6.col-md-3.py-2.py-md-0.pr-2 div.f4.color-fg-default")
            affected_versions = [v.get_text(strip=True) for v in affected_divs]
            # Patched versions
            patched_divs = row.select("div.col-6.col-md-3.py-2.py-md-0:not(.pr-2) div.f4.color-fg-default")
            patched_versions = [v.get_text(strip=True) for v in patched_divs]
            # Store
            products[pkg_name] = {
                "Info": extra_info,
                "Affected": affected_versions,
                "Patched": patched_versions
            }
    return products

# ---------------------------
# Fetch advisory details
# # ---------------------------
# def fetch_advisory_details(link):
#     try:
#         resp = session.get(link, headers=HEADERS, timeout=20)
#         resp.raise_for_status()
#         soup = BeautifulSoup(resp.text, "html.parser")
#         data = {}
#         data["Sidebar_Data"] = extract_sidebar_data(soup)
#         data["CVE_ID"] = data["Sidebar_Data"].get("CVE ID") or re.search(r"(CVE-\d{4}-\d{4,7})", resp.text)
#         data["CWEs"] = extract_cwes(soup)
#         data["CWE_Data"] = extract_cwe_data(soup)
#         data["Patched"] = get_h3_section_text(soup, "Patches")
#         data["Description"] = get_h3_section_text(soup, "description") or get_h3_section_text(soup, "impact")
#         data["Impact"] = get_h3_section_text(soup, "impact")
#         data["Workarounds"] = get_h3_section_text(soup, "workaround")
#         data["References"] = get_links_section_after_h3(soup, "references")
#         data["Other_Information_Links"] = get_links_section_after_h3(soup, "for more information")
#         data["Products"] = extract_products(soup)
#         return data
#     except Exception as e:
#         return {"error": str(e)}

def fetch_advisory_details(link):
    try:
        resp = session.get(link, headers=HEADERS, timeout=20)
        resp.raise_for_status()
        soup = BeautifulSoup(resp.text, "html.parser")
        data = {}
        data["Sidebar_Data"] = extract_sidebar_data(soup)
        data["CVE_ID"] = (
            data["Sidebar_Data"].get("CVE ID")
            or re.search(r"(CVE-\d{4}-\d{4,7})", resp.text)
        )
        data["CWEs"] = extract_cwes(soup)
        data["CWE_Data"] = extract_cwe_data(soup)
        data["Patched"] = get_h3_section_text(soup, "Patches")

        # ✅ No fallback: only store Description if heading is present
        data["Description"] = get_h3_section_text(soup, "description")

        # ✅ Impact stored separately
        data["Impact"] = get_h3_section_text(soup, "impact")

        data["Workarounds"] = get_h3_section_text(soup, "workaround")
        data["References"] = get_links_section_after_h3(soup, "references")
        data["Other_Information_Links"] = get_links_section_after_h3(
            soup, "for more information"
        )
        data["Products"] = extract_products(soup)
        return data
    except Exception as e:
        return {"error": str(e)}

# ---------------------------
# Parse advisory listing page
# ---------------------------
def parse_advisories(soup):
    advisories = []
    for row in soup.find_all("li", class_=re.compile(r"Box-row", re.I)):
        try:
            title_tag = row.find("a", class_=re.compile(r"Link--primary|link-primary", re.I)) or row.find("a", href=True)
            if not title_tag: continue
            link = urljoin(GITHUB_BASE, title_tag["href"])
            ghsa_id = row.find("div", class_=re.compile(r"text-small", re.I))
            ghsa_id = ghsa_id.get_text(" ", strip=True).split()[0] if ghsa_id else None
            date_tag = row.find("relative-time")
            date = date_tag["datetime"] if date_tag else None
            severity = row.find("span", class_=re.compile(r"Label", re.I)).get_text(strip=True) if row.find("span", class_=re.compile(r"Label", re.I)) else None
            advisories.append({
                "Title": title_tag.get_text(" ", strip=True),
                "Link": link,
                "GHSA_ID": ghsa_id,
                "Published_Date": date,
                "Severity": severity
            })
        except Exception:
            continue
    return advisories

# ---------------------------
# Fetch page
# ---------------------------
def fetch_page(page_num):
    try:
        resp = session.get(f"{BASE_URL}?state=published&page={page_num}", headers=HEADERS, timeout=15)
        resp.raise_for_status()
        return BeautifulSoup(resp.text, "html.parser")
    except Exception:
        return None

# ---------------------------
# Fetch all advisories
# ---------------------------
def fetch_all_advisories(pages_limit=None, delay=0.5):
    all_advs, page_num = [], 1
    while True:
        soup = fetch_page(page_num)
        if not soup: break
        page_advs = parse_advisories(soup)
        if not page_advs: break
        print(f"Page {page_num}")
        for adv in page_advs:
            adv["CVE_Details"] = fetch_advisory_details(adv["Link"])
            insert_advisory(adv["Link"], adv)
            print(f"  --> inserted {adv.get('Link')}")
            all_advs.append(adv)
            time.sleep(delay)
        page_num += 1
        if pages_limit and page_num > pages_limit: break
    return all_advs

# ---------------------------
# Main
# ---------------------------
if __name__ == "__main__":
    create_table()
    start = datetime.now(timezone.utc)
    advisories = fetch_all_advisories(pages_limit=None, delay=0.75)
    end = datetime.now(timezone.utc)
    print(f"[Done] Total advisories stored: {len(advisories)} in {(end-start).total_seconds():.1f}s")
