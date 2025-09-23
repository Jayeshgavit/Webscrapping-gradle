#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import requests
from bs4 import BeautifulSoup
import time

BASE_URL = "https://github.com/gradle/gradle/security/advisories"
GITHUB_BASE = "https://github.com"

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
}

def fetch_page(page_num):
    url = f"{BASE_URL}?state=published&page={page_num}"
    response = requests.get(url, headers=HEADERS)
    if response.status_code != 200:
        print(f"Failed to fetch page {page_num}: {response.status_code}")
        return None
    return BeautifulSoup(response.text, "html.parser")

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
                "GHSA_ID": ghsa_id,
                "Link": link,
                "Published_Date": date,
                "Author": author,
                "Severity": severity
            })
        except Exception as e:
            print(f"Error parsing row: {e}")
    return advisories

def fetch_all_advisories():
    all_advisories = []
    page_num = 1

    while True:
        print(f"Fetching page {page_num}...")
        soup = fetch_page(page_num)
        if soup is None:
            break

        advisories = parse_advisories(soup)
        if not advisories:
            print("No more advisories found. Ending.")
            break

        all_advisories.extend(advisories)
        page_num += 1
        time.sleep(1)  # polite delay to avoid rate limiting

    return all_advisories

if __name__ == "__main__":
    advisories = fetch_all_advisories()
    print(f"\nTotal advisories found: {len(advisories)}\n")
    for adv in advisories:
        print(f"Title: {adv['Title']}")
        print(f"GHSA ID: {adv['GHSA_ID']}")
        print(f"Link: {adv['Link']}")
        print(f"Published Date: {adv['Published_Date']}")
        print(f"Author: {adv['Author']}")
        print(f"Severity: {adv['Severity']}")
        print("-" * 80)
