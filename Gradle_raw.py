# # #!/usr/bin/env python3
# # # -*- coding: utf-8 -*-

# # import requests
# # from bs4 import BeautifulSoup
# # import time
# # import json
# # import psycopg2
# # from dotenv import load_dotenv
# # import os
# # from requests.adapters import HTTPAdapter
# # from requests.packages.urllib3.util.retry import Retry

# # # ---------------------------
# # # DB config
# # # ---------------------------
# # load_dotenv()
# # DB_CONFIG = {
# #     "host": os.getenv("DB_HOST", "localhost"),
# #     "dbname": os.getenv("DB_NAME", "Gradle"),
# #     "user": os.getenv("DB_USER", "postgres"),
# #     "password": os.getenv("DB_PASS", "623809"),
# #     "port": int(os.getenv("DB_PORT", 5432)),
# # }
# # TABLE_NAME = "staging_table"

# # # ---------------------------
# # # DB helper functions
# # # ---------------------------
# # def get_conn():
# #     return psycopg2.connect(**DB_CONFIG)

# # def create_table():
# #     ddl = f"""
# #     CREATE TABLE IF NOT EXISTS {TABLE_NAME} (
# #         staging_id SERIAL PRIMARY KEY,
# #         vendor_name TEXT NOT NULL DEFAULT 'Gradle',
# #         source_url TEXT UNIQUE,
# #         raw_data JSONB NOT NULL,
# #         processed BOOLEAN DEFAULT FALSE,
# #         processed_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
# #     );
# #     """
# #     with get_conn() as conn:
# #         with conn.cursor() as cursor:
# #             cursor.execute(ddl)
# #             conn.commit()
# #     print(f"Table '{TABLE_NAME}' ready.")

# # def insert_advisory(source_url, raw_data):
# #     try:
# #         with get_conn() as conn:
# #             with conn.cursor() as cursor:
# #                 cursor.execute(
# #                     f"""
# #                     INSERT INTO {TABLE_NAME} (source_url, raw_data)
# #                     VALUES (%s, %s)
# #                     ON CONFLICT (source_url) DO NOTHING;
# #                     """,
# #                     (source_url, json.dumps(raw_data))
# #                 )
# #                 conn.commit()
# #         print(f"Inserted advisory: {source_url}")
# #     except Exception as e:
# #         print(f"DB insert error: {e}")

# # # ---------------------------
# # # Requests session
# # # ---------------------------
# # session = requests.Session()
# # retry = Retry(total=5, backoff_factor=0.5, status_forcelist=[500, 502, 503, 504])
# # adapter = HTTPAdapter(max_retries=retry)
# # session.mount("https://", adapter)
# # session.mount("http://", adapter)
# # HEADERS = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}

# # # ---------------------------
# # # URLs
# # # ---------------------------
# # BASE_URL = "https://github.com/gradle/gradle/security/advisories"
# # GITHUB_BASE = "https://github.com"

# # # ---------------------------
# # # Fetch page
# # # ---------------------------
# # def fetch_page(page_num):
# #     url = f"{BASE_URL}?state=published&page={page_num}"
# #     try:
# #         response = session.get(url, headers=HEADERS, timeout=15)
# #         response.raise_for_status()
# #         return BeautifulSoup(response.text, "html.parser")
# #     except Exception as e:
# #         print(f"Failed to fetch page {page_num}: {e}")
# #         return None

# # # ---------------------------
# # # Fetch advisory details
# # # ---------------------------
# # def fetch_advisory_details(link):
# #     try:
# #         response = session.get(link, headers=HEADERS, timeout=15)
# #         response.raise_for_status()
# #         soup = BeautifulSoup(response.text, "html.parser")
# #         data = {}

# #         # CVE ID
# #         cve_tag = soup.find("h3", string="CVE ID")
# #         data["CVE_ID"] = cve_tag.find_next("div").text.strip() if cve_tag and cve_tag.find_next("div") else None

# #         # Severity
# #         sev_tag = soup.find("span", class_="Label", title=lambda x: x and x.startswith("Severity:"))
# #         data["Severity"] = sev_tag.text.strip() if sev_tag else None

# #         # CVSS Score
# #         cvss_div = soup.find("div", class_="d-flex flex-items-baseline pb-1")
# #         cvss_score = None
# #         if cvss_div:
# #             button_span = cvss_div.find("span", class_="Button-label")
# #             if button_span:
# #                 cvss_score = button_span.text.strip()
# #         data["CVSS_Score"] = cvss_score

# #         # CVSS Vector
# #         cvss_vector_tag = soup.find(string=lambda t: t and t.startswith("CVSS:"))
# #         data["CVSS_Vector"] = cvss_vector_tag.strip() if cvss_vector_tag else None

# #         # ---------------------------
# #         # CWEs
# #         # ---------------------------
# #         cwe_data = []
# #         desc_box = soup.find("div", class_="markdown-body comment-body")
# #         if desc_box:
# #             for a_tag in desc_box.find_all("a", href=True):
# #                 if "cwe.mitre.org" in a_tag["href"] or "CWE-" in a_tag.get_text():
# #                     cwe_text = a_tag.get_text(strip=True)
# #                     cwe_data.append({
# #                         "CWE_ID": cwe_text.split(":")[0],
# #                         "Description": ":".join(cwe_text.split(":")[1:]).strip() if ":" in cwe_text else "",
# #                         "MITRE_Link": a_tag["href"]
# #                     })
# #         data["CWEs"] = cwe_data

# #         # ---------------------------
# #         # Description Sections
# #         # ---------------------------
# #         description_data = {}
# #         if desc_box:
# #             current_section = None
# #             for tag in desc_box.find_all(["h3", "p", "ul"], recursive=False):
# #                 if tag.name == "h3":
# #                     current_section = tag.get_text(strip=True)
# #                     description_data[current_section] = ""
# #                 elif tag.name == "p" and current_section:
# #                     description_data[current_section] += tag.get_text(separator="\n").strip() + "\n"
# #                 elif tag.name == "ul" and current_section:
# #                     for li in tag.find_all("li"):
# #                         description_data[current_section] += "- " + li.get_text(strip=True) + "\n"
# #         data["Description"] = description_data

# #         # ---------------------------
# #         # Products / Versions
# #         # ---------------------------
# #         products = []
# #         for box in soup.find_all("div", class_="Box Box--responsive"):
# #             name_tag = box.find("h2", string="Package")
# #             if not name_tag:
# #                 continue
# #             parent = name_tag.find_parent("div", class_="Box-body")
# #             if not parent:
# #                 continue
# #             package_name = parent.find("span", class_="f4 color-fg-default text-bold")
# #             package_name = package_name.text.strip() if package_name else None
# #             affected_ver_tag = parent.find("h2", string="Affected versions")
# #             patched_ver_tag = parent.find("h2", string="Patched versions")
# #             affected_ver = affected_ver_tag.find_next("div").text.strip() if affected_ver_tag else None
# #             patched_ver = patched_ver_tag.find_next("div").text.strip() if patched_ver_tag else None
# #             products.append({
# #                 "Package": package_name,
# #                 "Affected_Version": affected_ver,
# #                 "Patched_Version": patched_ver
# #             })
# #         data["Products"] = products

# #         # ---------------------------
# #         # Other Information / Links (only visible text)
# #         # ---------------------------
# #         other_links = []
# #         if desc_box:
# #             for a_tag in desc_box.find_all("a", href=True):
# #                 text = a_tag.get_text(strip=True)
# #                 if text:  # only store visible text
# #                     other_links.append(text)
# #         data["Other_Information_Links"] = other_links

# #         return data
# #     except Exception as e:
# #         print(f"Error fetching {link}: {e}")
# #         return {}

# # # ---------------------------
# # # Parse advisories list page
# # # ---------------------------
# # def parse_advisories(soup):
# #     advisories = []
# #     rows = soup.find_all("li", class_="Box-row")
# #     for row in rows:
# #         try:
# #             title_tag = row.find("a", class_="Link--primary")
# #             title = title_tag.text.strip()
# #             link = GITHUB_BASE + title_tag["href"]

# #             ghsa_id = row.find("div", class_="mt-1 text-small color-fg-muted").text.strip().split()[0]
# #             date_tag = row.find("relative-time")
# #             date = date_tag["datetime"] if date_tag else "Unknown"
# #             author_tag = row.find("a", class_="author")
# #             author = author_tag.text.strip() if author_tag else "Unknown"
# #             severity_tag = row.find("span", class_="Label")
# #             severity = severity_tag.text.strip() if severity_tag else "Unknown"

# #             advisories.append({
# #                 "Title": title,
# #                 "Link": link,
# #                 "GHSA_ID": ghsa_id,
# #                 "Published_Date": date,
# #                 "Author": author,
# #                 "Severity": severity
# #             })
# #         except Exception as e:
# #             print(f"Error parsing row: {e}")
# #     return advisories

# # # ---------------------------
# # # Fetch all advisories (single-threaded)
# # # ---------------------------
# # def fetch_all_advisories():
# #     all_advisories = []
# #     page_num = 1

# #     while True:
# #         print(f"Fetching page {page_num}...")
# #         soup = fetch_page(page_num)
# #         if not soup:
# #             break

# #         page_advisories = parse_advisories(soup)
# #         if not page_advisories:
# #             print("No more advisories found. Ending.")
# #             break

# #         for adv in page_advisories:
# #             adv_details = fetch_advisory_details(adv["Link"])
# #             adv["CVE_Details"] = adv_details
# #             insert_advisory(adv["Link"], adv)
# #             all_advisories.append(adv)
# #             time.sleep(0.5)

# #         page_num += 1

# #     return all_advisories

# # # ---------------------------
# # # Main
# # # ---------------------------
# # if __name__ == "__main__":
# #     create_table()
# #     advisories = fetch_all_advisories()
# #     print(f"\nTotal advisories stored: {len(advisories)}")




# #!/usr/bin/env python3
# # -*- coding: utf-8 -*-
# """
# GHSA advisories scraper for a single repository (Gradle example).
# Stores raw advisory JSON into a Postgres staging table as JSONB.

# Usage:
#     pip install requests beautifulsoup4 psycopg2-binary python-dotenv
#     python gradle_ghsa_scraper.py
# # """

# # import re
# # import time
# # import json
# # import os
# # from datetime import datetime

# # import requests
# # from bs4 import BeautifulSoup
# # import psycopg2
# # from dotenv import load_dotenv
# # from requests.adapters import HTTPAdapter
# # from requests.packages.urllib3.util.retry import Retry

# # # ---------------------------
# # # Load .env DB config
# # # ---------------------------
# # load_dotenv()
# # DB_CONFIG = {
# #     "host": os.getenv("DB_HOST", "localhost"),
# #     "dbname": os.getenv("DB_NAME", "Gradle"),
# #     "user": os.getenv("DB_USER", "postgres"),
# #     "password": os.getenv("DB_PASS", "623809"),
# #     "port": int(os.getenv("DB_PORT", 5432)),
# # }
# # TABLE_NAME = os.getenv("TABLE_NAME", "staging_table")

# # # ---------------------------
# # # Helper: DB connection & table
# # # ---------------------------
# # def get_conn():
# #     return psycopg2.connect(**DB_CONFIG)

# # def create_table():
# #     ddl = f"""
# #     CREATE TABLE IF NOT EXISTS {TABLE_NAME} (
# #         staging_id SERIAL PRIMARY KEY,
# #         vendor_name TEXT NOT NULL DEFAULT 'Gradle',
# #         source_url TEXT UNIQUE,
# #         raw_data JSONB NOT NULL,
# #         processed BOOLEAN DEFAULT FALSE,
# #         processed_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
# #     );
# #     """
# #     with get_conn() as conn:
# #         with conn.cursor() as cur:
# #             cur.execute(ddl)
# #             conn.commit()
# #     print(f"[DB] Table '{TABLE_NAME}' ready.")

# # def insert_advisory(source_url, raw_data):
# #     try:
# #         with get_conn() as conn:
# #             with conn.cursor() as cur:
# #                 cur.execute(
# #                     f"""
# #                     INSERT INTO {TABLE_NAME} (source_url, raw_data)
# #                     VALUES (%s, %s)
# #                     ON CONFLICT (source_url) DO NOTHING;
# #                     """,
# #                     (source_url, json.dumps(raw_data))
# #                 )
# #                 conn.commit()
# #         print(f"[DB] Inserted advisory: {source_url}")
# #     except Exception as e:
# #         print(f"[DB] insert error: {e}")

# # # ---------------------------
# # # Requests session + retries
# # # ---------------------------
# # session = requests.Session()
# # retry = Retry(total=5, backoff_factor=0.5, status_forcelist=[500, 502, 503, 504])
# # adapter = HTTPAdapter(max_retries=retry)
# # session.mount("https://", adapter)
# # session.mount("http://", adapter)
# # HEADERS = {"User-Agent": "Mozilla/5.0 (compatible; ghsa-scraper/1.0)"}

# # # ---------------------------
# # # URLs / repo
# # # ---------------------------
# # OWNER_REPO = os.getenv("OWNER_REPO", "gradle/gradle")  # e.g., "gradle/gradle"
# # BASE_URL = f"https://github.com/{OWNER_REPO}/security/advisories"
# # GITHUB_BASE = "https://github.com"

# # # ---------------------------
# # # Utility: section extraction and CWE extraction
# # # ---------------------------
# # def get_section_by_heading(soup, keywords):
# #     """
# #     Find h1-h4 headings whose text contains any of the keywords (case-insensitive).
# #     Collect following siblings until next heading and return combined text.
# #     """
# #     for header in soup.find_all(re.compile(r"^h[1-4]$")):
# #         htxt = header.get_text(" ", strip=True).lower()
# #         for kw in keywords:
# #             if kw in htxt:
# #                 parts = []
# #                 for sib in header.find_next_siblings():
# #                     if sib.name and re.match(r"^h[1-4]$", sib.name):
# #                         break
# #                     parts.append(sib.get_text(" ", strip=True))
# #                 return "\n\n".join(p for p in parts if p)
# #     return None

# # def extract_cwes(soup):
# #     """
# #     Return list of dicts: {"CWE_ID":"CWE-22", "Description": "...", "Link": "..."}.
# #     Finds MITRE links first, then textual occurrences.
# #     """
# #     cwes = {}

# #     # 1) MITRE links
# #     for a in soup.find_all("a", href=True):
# #         href = a["href"].strip()
# #         if "cwe.mitre.org" in href.lower():
# #             # try to parse ID from URL
# #             m = re.search(r"/cwe/index\.cfm\?id=(\d+)", href) or re.search(r"/data/definitions/(\d+)\.html", href)
# #             if m:
# #                 cwe_id = f"CWE-{m.group(1)}"
# #             else:
# #                 txt = a.get_text(" ", strip=True)
# #                 m2 = re.search(r"CWE[-\u2011\s]?(\d{1,5})", txt)
# #                 cwe_id = f"CWE-{m2.group(1)}" if m2 else txt
# #             cwes[cwe_id] = {"CWE_ID": cwe_id, "Description": a.get_text(" ", strip=True), "Link": href}

# #     # 2) textual occurrences on page
# #     page_text = soup.get_text(" ", strip=True)
# #     for m in re.finditer(r"\bCWE[-\u2011\s]?(\d{1,5})\b", page_text, flags=re.IGNORECASE):
# #         cid = f"CWE-{m.group(1)}"
# #         if cid not in cwes:
# #             cwes[cid] = {"CWE_ID": cid, "Description": "", "Link": None}

# #     # return as sorted list
# #     def key_fn(item):
# #         try:
# #             return int(item["CWE_ID"].split("-")[1])
# #         except:
# #             return 999999
# #     return sorted(cwes.values(), key=key_fn)

# # # ---------------------------
# # # Fetch single advisory details (robust)
# # # ---------------------------
# # def fetch_advisory_details(link):
# #     try:
# #         response = session.get(link, headers=HEADERS, timeout=20)
# #         response.raise_for_status()
# #         soup = BeautifulSoup(response.text, "html.parser")
# #         data = {}
# #         page_text = soup.get_text(" ", strip=True)

# #         # CVE ID (heading or fallback regex)
# #         cve_id = None
# #         cve_tag = soup.find(lambda tag: tag.name in ("h3", "h4") and "CVE ID" in tag.get_text())
# #         if cve_tag:
# #             nxt = cve_tag.find_next()
# #             if nxt:
# #                 cve_id = nxt.get_text(" ", strip=True)
# #         if not cve_id:
# #             m = re.search(r"\b(CVE-\d{4}-\d{4,7})\b", page_text, flags=re.IGNORECASE)
# #             cve_id = m.group(1).upper() if m else None
# #         data["CVE_ID"] = cve_id

# #         # Severity
# #         sev = None
# #         sev_tag = soup.find("span", class_=re.compile(r"Label", re.I))
# #         if sev_tag:
# #             sev = sev_tag.get_text(" ", strip=True)
# #         else:
# #             s = soup.find(string=re.compile(r"Severity", re.I))
# #             if s:
# #                 parent = s.parent
# #                 if parent and parent.next_sibling:
# #                     nxt = parent.next_sibling
# #                     sev = nxt.get_text(" ", strip=True) if hasattr(nxt, "get_text") else str(nxt).strip()
# #         data["Severity"] = sev

# #         # CVSS Score & Vector (best-effort)
# #         cvss_score = None
# #         cvss_vector = None
# #         cvss_lbl = soup.find(string=re.compile(r"CVSS", re.I))
# #         if cvss_lbl:
# #             block = cvss_lbl.parent
# #             txt = block.get_text(" ", strip=True)
# #             m_score = re.search(r"\b([0-9]\.[0-9])\b", txt)
# #             if m_score:
# #                 cvss_score = m_score.group(1)
# #             mv = re.search(r"(AV:[ANCPLR\/].+?[\)\s])", txt)
# #             if mv:
# #                 cvss_vector = mv.group(1).strip()
# #             else:
# #                 mv2 = re.search(r"CVSS[:\s]*([^\s\)]+)", txt, flags=re.IGNORECASE)
# #                 if mv2:
# #                     cvss_vector = mv2.group(1).strip()
# #         if not cvss_vector:
# #             mv = re.search(r"(CVSS[:\s]*[^\)]+)", page_text, flags=re.IGNORECASE)
# #             cvss_vector = mv.group(1) if mv else cvss_vector
# #         if not cvss_score:
# #             ms = re.search(r"\bCVSS\s*[:\-]?\s*([0-9]\.[0-9])\b", page_text, flags=re.IGNORECASE)
# #             if ms:
# #                 cvss_score = ms.group(1)
# #         data["CVSS_Score"] = cvss_score
# #         data["CVSS_Vector"] = cvss_vector

# #         # CWEs
# #         data["CWEs"] = extract_cwes(soup)

# #         # Impact and other sections
# #         impact_text = get_section_by_heading(soup, ["impact", "impact and exploitability", "impact and mitigations"])
# #         if not impact_text:
# #             desc_box = soup.find("div", class_=re.compile(r"markdown-body|comment-body", re.I))
# #             if desc_box:
# #                 for hdr in desc_box.find_all(["strong", "b"]):
# #                     if "impact" in hdr.get_text(" ", strip=True).lower():
# #                         parts = []
# #                         for sib in hdr.parent.find_next_siblings():
# #                             if sib.name and re.match(r"^h[1-4]$", sib.name):
# #                                 break
# #                             parts.append(sib.get_text(" ", strip=True))
# #                         impact_text = "\n\n".join(p for p in parts if p)
# #                         break
# #         data["Impact_Text"] = impact_text

# #         # other named sections
# #         for sec in ["description", "remediation", "mitigation", "acknowledgements", "exploitability"]:
# #             val = get_section_by_heading(soup, [sec])
# #             if val:
# #                 data[sec.capitalize()] = val

# #         # Products / Affected / Patched versions (best-effort)
# #         products = []
# #         for box in soup.find_all("div", class_=re.compile(r"Box|box", re.I)):
# #             heading = box.find(lambda t: t.name in ("h2", "h3") and re.search(r"Package|Affected versions|Patched versions", t.get_text(" ", strip=True), re.I))
# #             if not heading:
# #                 continue
# #             pkg = {}
# #             pname = box.find("span", class_=re.compile(r"f4|package|text-bold", re.I))
# #             if pname:
# #                 pkg["Package"] = pname.get_text(" ", strip=True)
# #             aff = box.find(lambda t: t.name in ("h2", "h3") and "Affected versions" in t.get_text(" ", strip=True))
# #             if aff:
# #                 next_div = aff.find_next_sibling()
# #                 pkg["Affected_Version"] = next_div.get_text(" ", strip=True) if next_div else None
# #             pat = box.find(lambda t: t.name in ("h2", "h3") and "Patched versions" in t.get_text(" ", strip=True))
# #             if pat:
# #                 next_div = pat.find_next_sibling()
# #                 pkg["Patched_Version"] = next_div.get_text(" ", strip=True) if next_div else None
# #             if pkg:
# #                 products.append(pkg)
# #         if not products:
# #             m = re.search(r"Affected versions[:\s]*(.+?)(?:Patched versions|$)", page_text, flags=re.IGNORECASE | re.DOTALL)
# #             if m:
# #                 products.append({"Package": None, "Affected_Version": m.group(1).strip(), "Patched_Version": None})
# #         data["Products"] = products

# #         # Links inside description area (text+href)
# #         other_links = []
# #         desc_box = soup.find("div", class_=re.compile(r"markdown-body|comment-body", re.I))
# #         if desc_box:
# #             for a in desc_box.find_all("a", href=True):
# #                 text = a.get_text(" ", strip=True)
# #                 href = a["href"].strip()
# #                 if href.startswith("/"):
# #                     href = GITHUB_BASE + href
# #                 other_links.append({"text": text, "href": href})
# #         else:
# #             for a in soup.find_all("a", href=True):
# #                 text = a.get_text(" ", strip=True)
# #                 href = a["href"].strip()
# #                 if text:
# #                     if href.startswith("/"):
# #                         href = GITHUB_BASE + href
# #                     other_links.append({"text": text, "href": href})
# #         data["Other_Information_Links"] = other_links

# #         return data

# #     except Exception as e:
# #         print(f"[FetchDetail] Error fetching {link}: {e}")
# #         return {}

# # # ---------------------------
# # # Parse advisories listing page
# # # ---------------------------
# # def parse_advisories(soup):
# #     advisories = []
# #     # GitHub lists advisories as li.Box-row elements
# #     rows = soup.find_all("li", class_=re.compile(r"Box-row", re.I))
# #     for row in rows:
# #         try:
# #             title_tag = row.find("a", class_=re.compile(r"Link--primary|link-primary", re.I))
# #             if not title_tag:
# #                 # fallback: first <a> inside row
# #                 title_tag = row.find("a", href=True)
# #                 if not title_tag:
# #                     continue
# #             title = title_tag.get_text(" ", strip=True)
# #             link = GITHUB_BASE + title_tag["href"]

# #             ghsa_id = None
# #             meta_div = row.find("div", class_=re.compile(r"mt-1 text-small color-fg-muted|text-small", re.I))
# #             if meta_div:
# #                 text = meta_div.get_text(" ", strip=True)
# #                 ghsa_id = text.split()[0] if text else None

# #             date_tag = row.find("relative-time")
# #             date = date_tag["datetime"] if date_tag else None
# #             author_tag = row.find("a", class_=re.compile(r"author", re.I))
# #             author = author_tag.get_text(" ", strip=True) if author_tag else None
# #             severity_tag = row.find("span", class_=re.compile(r"Label", re.I))
# #             severity = severity_tag.get_text(" ", strip=True) if severity_tag else None

# #             advisories.append({
# #                 "Title": title,
# #                 "Link": link,
# #                 "GHSA_ID": ghsa_id,
# #                 "Published_Date": date,
# #                 "Author": author,
# #                 "Severity": severity
# #             })
# #         except Exception as e:
# #             print(f"[ParseRow] Error parsing row: {e}")
# #     return advisories

# # # ---------------------------
# # # Fetch page of advisories (list)
# # # ---------------------------
# # def fetch_page(page_num):
# #     url = f"{BASE_URL}?state=published&page={page_num}"
# #     try:
# #         resp = session.get(url, headers=HEADERS, timeout=15)
# #         resp.raise_for_status()
# #         return BeautifulSoup(resp.text, "html.parser")
# #     except Exception as e:
# #         print(f"[FetchPage] Failed to fetch page {page_num}: {e}")
# #         return None

# # # ---------------------------
# # # Orchestrator: fetch all advisories (single-threaded)
# # # ---------------------------
# # def fetch_all_advisories(pages_limit=None, delay=0.5):
# #     all_advisories = []
# #     page_num = 1
# #     while True:
# #         print(f"[FetchAll] Fetching page {page_num}...")
# #         soup = fetch_page(page_num)
# #         if not soup:
# #             break
# #         page_advisories = parse_advisories(soup)
# #         if not page_advisories:
# #             print("[FetchAll] No more advisories found on this page. Ending.")
# #             break

# #         for adv in page_advisories:
# #             print(f"[FetchAll] Processing {adv['Title']} -> {adv['Link']}")
# #             adv_details = fetch_advisory_details(adv["Link"])
# #             adv["CVE_Details"] = adv_details
# #             insert_advisory(adv["Link"], adv)
# #             all_advisories.append(adv)
# #             time.sleep(delay)

# #         page_num += 1
# #         if pages_limit and page_num > pages_limit:
# #             break

# #     return all_advisories

# # # ---------------------------
# # # Main
# # # ---------------------------
# # if __name__ == "__main__":
# #     create_table()
# #     start = datetime.utcnow()
# #     advisories = fetch_all_advisories(pages_limit=None, delay=0.75)  # increase delay if you prefer
# #     end = datetime.utcnow()
# #     print(f"\n[Done] Total advisories stored: {len(advisories)}")
# #     print(f"[Done] Time taken: {(end - start).total_seconds():.1f}s")











# #!/usr/bin/env python3
# # -*- coding: utf-8 -*-
# """
# Final GHSA scraper (Gradle example)
# - extracts CVE, Severity, CVSS, CWEs, Impact, Products, Patches, Workarounds, References
# - stores advisory JSON into Postgres staging_table
# """

# import re
# import time
# import json
# import os
# from datetime import datetime
# from urllib.parse import urljoin, urlparse

# import requests
# from bs4 import BeautifulSoup
# import psycopg2
# from dotenv import load_dotenv
# from requests.adapters import HTTPAdapter
# from requests.packages.urllib3.util.retry import Retry

# # ---------------------------
# # Load .env DB config
# # ---------------------------
# load_dotenv()
# DB_CONFIG = {
#     "host": os.getenv("DB_HOST", "localhost"),
#     "dbname": os.getenv("DB_NAME", "Gradle"),
#     "user": os.getenv("DB_USER", "postgres"),
#     "password": os.getenv("DB_PASS", "623809"),
#     "port": int(os.getenv("DB_PORT", 5432)),
# }
# TABLE_NAME = os.getenv("TABLE_NAME", "staging_table")

# # ---------------------------
# # Helper: DB connection & table
# # ---------------------------
# def get_conn():
#     return psycopg2.connect(**DB_CONFIG)

# def create_table():
#     ddl = f"""
#     CREATE TABLE IF NOT EXISTS {TABLE_NAME} (
#         staging_id SERIAL PRIMARY KEY,
#         vendor_name TEXT NOT NULL DEFAULT 'Gradle',
#         source_url TEXT UNIQUE,
#         raw_data JSONB NOT NULL,
#         processed BOOLEAN DEFAULT FALSE,
#         processed_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
#     );
#     """
#     with get_conn() as conn:
#         with conn.cursor() as cur:
#             cur.execute(ddl)
#             conn.commit()
#     print(f"[DB] Table '{TABLE_NAME}' ready.")

# def insert_advisory(source_url, raw_data):
#     try:
#         with get_conn() as conn:
#             with conn.cursor() as cur:
#                 cur.execute(
#                     f"""
#                     INSERT INTO {TABLE_NAME} (source_url, raw_data)
#                     VALUES (%s, %s)
#                     ON CONFLICT (source_url) DO NOTHING;
#                     """,
#                     (source_url, json.dumps(raw_data))
#                 )
#                 conn.commit()
#         print(f"[DB] Inserted advisory: {source_url}")
#     except Exception as e:
#         print(f"[DB] insert error: {e}")

# # ---------------------------
# # Requests session + retries
# # ---------------------------
# session = requests.Session()
# retry = Retry(total=5, backoff_factor=0.5, status_forcelist=[500, 502, 503, 504])
# adapter = HTTPAdapter(max_retries=retry)
# session.mount("https://", adapter)
# session.mount("http://", adapter)
# HEADERS = {"User-Agent": "Mozilla/5.0 (compatible; ghsa-scraper/1.0)"}

# # ---------------------------
# # URLs / repo
# # ---------------------------
# OWNER_REPO = os.getenv("OWNER_REPO", "gradle/gradle")  # e.g., "gradle/gradle"
# BASE_URL = f"https://github.com/{OWNER_REPO}/security/advisories"
# GITHUB_BASE = "https://github.com"

# # ---------------------------
# # Utility helpers
# # ---------------------------
# def get_section_by_heading_any(soup, headings, tag_name_regex=r"^h[1-6]$"):
#     """
#     Generic: find headings (h1..h6) that contain any of 'headings' (case-insensitive),
#     return combined text of following siblings until next heading of same or higher level.
#     """
#     pattern = re.compile(tag_name_regex)
#     for header in soup.find_all(pattern):
#         text = header.get_text(" ", strip=True).lower()
#         for target in headings:
#             if target.lower() in text:
#                 parts = []
#                 for sib in header.find_next_siblings():
#                     # stop at next heading of same level (h1-h6)
#                     if sib.name and re.match(r"^h[1-6]$", sib.name):
#                         break
#                     parts.append(sib.get_text(" ", strip=True))
#                 return "\n\n".join(p for p in parts if p)
#     return None

# def get_section_by_h3(soup, heading_text):
#     """
#     Specifically find <h3> tags (including with attributes like dir="auto") where heading_text is present,
#     then collect following siblings until next <h3> and return:
#       - text (combined)
#       - links in that section as list of {text, href}
#     """
#     for h3 in soup.find_all("h3"):
#         htxt = h3.get_text(" ", strip=True).lower()
#         if heading_text.lower() in htxt:
#             parts = []
#             links = []
#             for sib in h3.find_next_siblings():
#                 if sib.name and sib.name.lower() == "h3":
#                     break
#                 # collect visible text
#                 parts.append(sib.get_text(" ", strip=True))
#                 # collect links inside this sib
#                 for a in sib.find_all("a", href=True):
#                     text = a.get_text(" ", strip=True)
#                     href = a["href"].strip()
#                     if href.startswith("/"):
#                         href = urljoin(GITHUB_BASE, href)
#                     links.append({"text": text, "href": href})
#             full_text = "\n\n".join(p for p in parts if p)
#             return {"text": full_text, "links": links}
#     return {"text": None, "links": []}

# def normalize_href(href):
#     if not href:
#         return href
#     href = href.strip()
#     if href.startswith("/"):
#         return urljoin(GITHUB_BASE, href)
#     return href

# def extract_cwes(soup):
#     """
#     Return list of dicts: {"CWE_ID":"CWE-22", "Description": "...", "Link": "..."}.
#     Finds MITRE links first, then textual occurrences.
#     """
#     cwes = {}

#     # 1) MITRE links
#     for a in soup.find_all("a", href=True):
#         href = a["href"].strip()
#         if "cwe.mitre.org" in href.lower():
#             # try to parse ID from URL
#             m = re.search(r"/cwe/index\.cfm\?id=(\d+)", href) or re.search(r"/data/definitions/(\d+)\.html", href)
#             if m:
#                 cwe_id = f"CWE-{m.group(1)}"
#             else:
#                 txt = a.get_text(" ", strip=True)
#                 m2 = re.search(r"CWE[-\u2011\s]?(\d{1,5})", txt)
#                 cwe_id = f"CWE-{m2.group(1)}" if m2 else txt
#             cwes[cwe_id] = {"CWE_ID": cwe_id, "Description": a.get_text(" ", strip=True), "Link": normalize_href(href)}

#     # 2) textual occurrences on page
#     page_text = soup.get_text(" ", strip=True)
#     for m in re.finditer(r"\bCWE[-\u2011\s]?(\d{1,5})\b", page_text, flags=re.IGNORECASE):
#         cid = f"CWE-{m.group(1)}"
#         if cid not in cwes:
#             cwes[cid] = {"CWE_ID": cid, "Description": "", "Link": None}

#     # return as sorted list
#     def key_fn(item):
#         try:
#             return int(item["CWE_ID"].split("-")[1])
#         except:
#             return 999999
#     return sorted(cwes.values(), key=key_fn)

# # ---------------------------
# # Fetch single advisory details (robust + Patches/Workarounds/References)
# # ---------------------------
# def fetch_advisory_details(link):
#     try:
#         response = session.get(link, headers=HEADERS, timeout=20)
#         response.raise_for_status()
#         soup = BeautifulSoup(response.text, "html.parser")
#         data = {}
#         page_text = soup.get_text(" ", strip=True)

#         # Add path (path portion of the URL)
#         parsed = urlparse(link)
#         data["source_path"] = parsed.path

#         # CVE ID (heading or fallback regex)
#         cve_id = None
#         cve_tag = soup.find(lambda tag: tag.name in ("h3", "h4") and "CVE ID" in tag.get_text())
#         if cve_tag:
#             nxt = cve_tag.find_next()
#             if nxt:
#                 cve_id = nxt.get_text(" ", strip=True)
#         if not cve_id:
#             m = re.search(r"\b(CVE-\d{4}-\d{4,7})\b", page_text, flags=re.IGNORECASE)
#             cve_id = m.group(1).upper() if m else None
#         data["CVE_ID"] = cve_id

#         # Severity
#         sev = None
#         sev_tag = soup.find("span", class_=re.compile(r"Label", re.I))
#         if sev_tag:
#             sev = sev_tag.get_text(" ", strip=True)
#         else:
#             s = soup.find(string=re.compile(r"Severity", re.I))
#             if s:
#                 parent = s.parent
#                 if parent and parent.next_sibling:
#                     nxt = parent.next_sibling
#                     sev = nxt.get_text(" ", strip=True) if hasattr(nxt, "get_text") else str(nxt).strip()
#         data["Severity"] = sev

#         # CVSS Score & Vector (best-effort)
#         cvss_score = None
#         cvss_vector = None
#         cvss_lbl = soup.find(string=re.compile(r"CVSS", re.I))
#         if cvss_lbl:
#             block = cvss_lbl.parent
#             txt = block.get_text(" ", strip=True)
#             m_score = re.search(r"\b([0-9]\.[0-9])\b", txt)
#             if m_score:
#                 cvss_score = m_score.group(1)
#             mv = re.search(r"(AV:[ANCPLR\/].+?[\)\s])", txt)
#             if mv:
#                 cvss_vector = mv.group(1).strip()
#             else:
#                 mv2 = re.search(r"CVSS[:\s]*([^\s\)]+)", txt, flags=re.IGNORECASE)
#                 if mv2:
#                     cvss_vector = mv2.group(1).strip()
#         if not cvss_vector:
#             mv = re.search(r"(CVSS[:\s]*[^\)]+)", page_text, flags=re.IGNORECASE)
#             cvss_vector = mv.group(1) if mv else cvss_vector
#         if not cvss_score:
#             ms = re.search(r"\bCVSS\s*[:\-]?\s*([0-9]\.[0-9])\b", page_text, flags=re.IGNORECASE)
#             if ms:
#                 cvss_score = ms.group(1)
#         data["CVSS_Score"] = cvss_score
#         data["CVSS_Vector"] = cvss_vector

#         # CWEs
#         data["CWEs"] = extract_cwes(soup)

#         # Impact and other named sections (h1-h4 matching)
#         impact_text = get_section_by_heading_any(soup, ["impact", "impact and exploitability", "impact and mitigations"])
#         data["Impact_Text"] = impact_text

#         # other named sections
#         for sec in ["description", "remediation", "mitigation", "acknowledgements", "exploitability"]:
#             val = get_section_by_heading_any(soup, [sec])
#             if val:
#                 data[sec.capitalize()] = val

#         # Patches (explicit <h3> Patches ... until next h3)
#         patches = get_section_by_h3(soup, "Patches")
#         data["Patches"] = patches  # {"text":..., "links":[... ]}

#         # Workarounds (<h3> Workarounds ... until next h3)
#         workarounds = get_section_by_h3(soup, "Workarounds")
#         data["Workarounds"] = workarounds

#         # References (<h3> References ... until next h3) - store both text and links
#         references = get_section_by_h3(soup, "References")
#         # If references block contains no hrefs (rare), still keep text
#         data["References"] = references

#         # Products / Affected / Patched versions (best-effort)
#         products = []
#         for box in soup.find_all("div", class_=re.compile(r"Box|box", re.I)):
#             heading = box.find(lambda t: t.name in ("h2", "h3") and re.search(r"Package|Affected versions|Patched versions", t.get_text(" ", strip=True), re.I))
#             if not heading:
#                 continue
#             pkg = {}
#             pname = box.find("span", class_=re.compile(r"f4|package|text-bold", re.I))
#             if pname:
#                 pkg["Package"] = pname.get_text(" ", strip=True)
#             aff = box.find(lambda t: t.name in ("h2", "h3") and "Affected versions" in t.get_text(" ", strip=True))
#             if aff:
#                 next_div = aff.find_next_sibling()
#                 pkg["Affected_Version"] = next_div.get_text(" ", strip=True) if next_div else None
#             pat = box.find(lambda t: t.name in ("h2", "h3") and "Patched versions" in t.get_text(" ", strip=True))
#             if pat:
#                 next_div = pat.find_next_sibling()
#                 pkg["Patched_Version"] = next_div.get_text(" ", strip=True) if next_div else None
#             if pkg:
#                 products.append(pkg)
#         if not products:
#             m = re.search(r"Affected versions[:\s]*(.+?)(?:Patched versions|$)", page_text, flags=re.IGNORECASE | re.DOTALL)
#             if m:
#                 products.append({"Package": None, "Affected_Version": m.group(1).strip(), "Patched_Version": None})
#         data["Products"] = products

#         # Links inside description area (text+href)
#         other_links = []
#         desc_box = soup.find("div", class_=re.compile(r"markdown-body|comment-body", re.I))
#         if desc_box:
#             for a in desc_box.find_all("a", href=True):
#                 text = a.get_text(" ", strip=True)
#                 href = a["href"].strip()
#                 href = normalize_href(href)
#                 other_links.append({"text": text, "href": href})
#         else:
#             for a in soup.find_all("a", href=True):
#                 text = a.get_text(" ", strip=True)
#                 href = a["href"].strip()
#                 if text:
#                     href = normalize_href(href)
#                     other_links.append({"text": text, "href": href})
#         data["Other_Information_Links"] = other_links

#         return data

#     except Exception as e:
#         print(f"[FetchDetail] Error fetching {link}: {e}")
#         return {}

# # ---------------------------
# # Parse advisories listing page
# # ---------------------------
# def parse_advisories(soup):
#     advisories = []
#     # GitHub lists advisories as li.Box-row elements
#     rows = soup.find_all("li", class_=re.compile(r"Box-row", re.I))
#     for row in rows:
#         try:
#             title_tag = row.find("a", class_=re.compile(r"Link--primary|link-primary", re.I))
#             if not title_tag:
#                 # fallback: first <a> inside row
#                 title_tag = row.find("a", href=True)
#                 if not title_tag:
#                     continue
#             title = title_tag.get_text(" ", strip=True)
#             link = urljoin(GITHUB_BASE, title_tag["href"])

#             ghsa_id = None
#             meta_div = row.find("div", class_=re.compile(r"mt-1 text-small color-fg-muted|text-small", re.I))
#             if meta_div:
#                 text = meta_div.get_text(" ", strip=True)
#                 ghsa_id = text.split()[0] if text else None

#             date_tag = row.find("relative-time")
#             date = date_tag["datetime"] if date_tag else None
#             author_tag = row.find("a", class_=re.compile(r"author", re.I))
#             author = author_tag.get_text(" ", strip=True) if author_tag else None
#             severity_tag = row.find("span", class_=re.compile(r"Label", re.I))
#             severity = severity_tag.get_text(" ", strip=True) if severity_tag else None

#             advisories.append({
#                 "Title": title,
#                 "Link": link,
#                 "GHSA_ID": ghsa_id,
#                 "Published_Date": date,
#                 "Author": author,
#                 "Severity": severity
#             })
#         except Exception as e:
#             print(f"[ParseRow] Error parsing row: {e}")
#     return advisories

# # ---------------------------
# # Fetch page of advisories (list)
# # ---------------------------
# def fetch_page(page_num):
#     url = f"{BASE_URL}?state=published&page={page_num}"
#     try:
#         resp = session.get(url, headers=HEADERS, timeout=15)
#         resp.raise_for_status()
#         return BeautifulSoup(resp.text, "html.parser")
#     except Exception as e:
#         print(f"[FetchPage] Failed to fetch page {page_num}: {e}")
#         return None

# # ---------------------------
# # Orchestrator: fetch all advisories (single-threaded)
# # ---------------------------
# def fetch_all_advisories(pages_limit=None, delay=0.5):
#     all_advisories = []
#     page_num = 1
#     while True:
#         print(f"[FetchAll] Fetching page {page_num}...")
#         soup = fetch_page(page_num)
#         if not soup:
#             break
#         page_advisories = parse_advisories(soup)
#         if not page_advisories:
#             print("[FetchAll] No more advisories found on this page. Ending.")
#             break

#         for adv in page_advisories:
#             print(f"[FetchAll] Processing {adv['Title']} -> {adv['Link']}")
#             adv_details = fetch_advisory_details(adv["Link"])
#             adv["CVE_Details"] = adv_details
#             insert_advisory(adv["Link"], adv)
#             all_advisories.append(adv)
#             time.sleep(delay)

#         page_num += 1
#         if pages_limit and page_num > pages_limit:
#             break

#     return all_advisories

# # ---------------------------
# # Main
# # ---------------------------
# if __name__ == "__main__":
#     create_table()
#     start = datetime.utcnow()
#     advisories = fetch_all_advisories(pages_limit=None, delay=0.75)  # increase delay if you prefer
#     end = datetime.utcnow()
#     print(f"\n[Done] Total advisories stored: {len(advisories)}")
#     print(f"[Done] Time taken: {(end - start).total_seconds():.1f}s")




# import json
# import re
# import time

# import psycopg2
# import requests
# from bs4 import BeautifulSoup

# # --- DATABASE CONFIGURATION ---
# # IMPORTANT: Replace these values with your actual PostgreSQL credentials
# DB_CONFIG = {
#     "dbname": "php",
#     "user": "postgres",
#     "password": "root",
#     "host": "localhost",
#     "port": "5432"
# }

# def setup_database(cursor):
#     """Creates the staging_table if it doesn't already exist."""
#     cursor.execute("""
#         CREATE TABLE IF NOT EXISTS staging_table (
#             staging_id SERIAL PRIMARY KEY,
#             vendor_name VARCHAR(255),
#             raw_data JSONB,
#             processed_at TIMESTAMPTZ DEFAULT NOW()
#         );
#     """)
#     print("✅ Table 'staging_table' is ready.")

# def scrape_advisory_details(advisory_url, headers):
#     """
#     Scrapes detailed information using a two-pass method to find data in
#     both structured fields and unstructured text.
#     """
#     try:
#         response = requests.get(advisory_url, headers=headers)
#         response.raise_for_status()
#         detail_soup = BeautifulSoup(response.content, 'html.parser')

#         details = {
#             "product_info": "N/A", "description": "N/A", "affected_versions": "N/A",
#             "patched_versions": "N/A", "cvss_score": "N/A", "cvss_vector": "N/A",
#             "cve_id": "N/A", "cwe_id": "N/A", "references": "N/A"
#         }

#         # Scrape sidebar data
#         sidebar_items = detail_soup.select('div.discussion-sidebar-item')
#         for item in sidebar_items:
#             heading_element = item.find('h3')
#             if not heading_element: continue
#             heading = heading_element.text.strip().lower()

#             if heading == 'severity':
#                 score_el = item.select_one('button')
#                 if score_el: details['cvss_score'] = score_el.text.strip()
#                 vector_el = item.find('div', string=re.compile(r'^CVSS:'))
#                 if vector_el: details['cvss_vector'] = vector_el.text.strip()
#             elif heading == 'cve id':
#                 cve_div = heading_element.find_next_sibling('div')
#                 if cve_div: details['cve_id'] = cve_div.text.strip()
#             elif heading == 'weaknesses':
#                 # --- CORRECTED SELECTOR: Targets the span that is NOT screen-reader only ---
#                 cwe_span = item.select_one('summary > span:not(.sr-only)')
#                 if cwe_span:
#                     details['cwe_id'] = cwe_span.text.strip()

#         # Scrape main content structured fields
#         affected_elements = detail_soup.select('h2:-soup-contains("Affected versions") + div .f4')
#         if affected_elements: details['affected_versions'] = '; '.join([v.text.strip() for v in affected_elements])

#         patched_elements = detail_soup.select('h2:-soup-contains("Patched versions") + div .f4')
#         if patched_elements: details['patched_versions'] = '; '.join([p.text.strip() for p in patched_elements])

#         description_element = detail_soup.find('div', class_='markdown-body')
#         if description_element:
#             full_text_for_fallback = description_element.get_text()
            
#             # Fallback scan for missing data
#             if details['cwe_id'] == 'N/A':
#                 cwe_match = re.search(r'\((CWE-\d+)\)', full_text_for_fallback)
#                 if cwe_match: details['cwe_id'] = cwe_match.group(1)

#             if details['product_info'] == 'N/A':
#                 product_match = re.search(r'Product:([^\n]+)', full_text_for_fallback)
#                 if product_match: details['product_info'] = f"Product:{product_match.group(1).strip()}"

#             links = [a['href'] for a in description_element.find_all('a', href=True) if a['href'].startswith('http')]
#             if links: details['references'] = '; '.join(links)

#             for code_block in description_element.find_all('pre'):
#                 code_block.decompose()
#             details['description'] = description_element.get_text(separator=' ', strip=True)
            
#         return details

#     except Exception as e:
#         print(f"  ❌ Could not scrape details from {advisory_url}. Error: {e}")
#         return None

# # --- Main Script Logic ---
# base_url = "https://github.com/php/php-src/security/advisories"
# page_number = 1
# total_advisories_processed = 0
# vendor_name = "PHP"

# headers = {
#     'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
# }

# conn = None
# try:
#     print("🔄 Connecting to PostgreSQL database...")
#     conn = psycopg2.connect(**DB_CONFIG)
#     cur = conn.cursor()
#     print("✅ Database connection successful.")

#     setup_database(cur)
#     conn.commit()

#     while True:
#         paginated_url = f"{base_url}?page={page_number}"
#         print(f"🚀 Scraping list page {page_number}: {paginated_url}")

#         try:
#             response = requests.get(paginated_url, headers=headers)
#             response.raise_for_status()
#         except requests.exceptions.RequestException as e:
#             print(f"❌ Error fetching list page: {e}")
#             break

#         soup = BeautifulSoup(response.content, 'html.parser')
#         advisories_on_page = soup.find_all('li', class_='Box-row')

#         if not advisories_on_page:
#             print("✅ Found no more advisories on the list page. Ending process.")
#             break

#         print(f" Found {len(advisories_on_page)} advisories. Scraping details and inserting into database...")

#         for advisory in advisories_on_page:
#             title_element = advisory.find('a', class_='Link--primary')
#             advisory_link = "https://github.com" + title_element['href'] if title_element else None
            
#             if not advisory_link:
#                 continue

#             print(f"  -> Processing {advisory_link}...")
#             details = scrape_advisory_details(advisory_link, headers)
            
#             if details:
#                 id_container = advisory.find('div', class_='color-fg-muted')
#                 reporter_element = advisory.find('a', class_='author')
#                 date_element = advisory.find('relative-time')
#                 severity_element = advisory.find('span', class_='Label')

#                 raw_data_dict = {
#                     'advisory_title': title_element.text.strip() if title_element else 'N/A',
#                     'link': advisory_link,
#                     'ghsa_id': id_container.text.strip().split()[0] if id_container else 'N/A',
#                     'severity': severity_element.text.strip() if severity_element else 'N/A',
#                     'reporter': reporter_element.text.strip() if reporter_element else 'N/A',
#                     'date_published': date_element['datetime'] if date_element else 'N/A',
#                     **details
#                 }

#                 raw_data_json = json.dumps(raw_data_dict, indent=2)

#                 insert_query = """
#                     INSERT INTO staging_table (vendor_name, raw_data, processed_at)
#                     VALUES (%s, %s, NOW());
#                 """
#                 cur.execute(insert_query, (vendor_name, raw_data_json))
#                 total_advisories_processed += 1
            
#             time.sleep(0.5)

#         page_number += 1
#         time.sleep(1)

#     conn.commit()

# except (Exception, psycopg2.Error) as error:
#     print(f"❌ An error occurred: {error}")
#     if conn:
#         conn.rollback()

# finally:
#     if conn:
#         cur.close()
#         conn.close()
#         print("\n🔌 Database connection closed.")

# print(f"\n🎉 Scraping complete! Inserted a total of {total_advisories_processed} advisories into the database.")




#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
GHSA Scraper (Gradle example)
- extracts CVE, Severity, CVSS, CWEs, Impact, Products, Patches, Workarounds, References
- stores advisory JSON into Postgres staging_table
- minimal logging
"""

# import re
# import time
# import json
# import os
# import warnings
# from datetime import datetime
# from urllib.parse import urljoin, urlparse

# import requests
# from bs4 import BeautifulSoup
# import psycopg2
# from dotenv import load_dotenv
# from requests.adapters import HTTPAdapter
# from requests.packages.urllib3.util.retry import Retry

# # ---------------------------
# # Suppress warnings
# # ---------------------------
# warnings.filterwarnings("ignore", category=ResourceWarning)
# requests.packages.urllib3.disable_warnings()

# # ---------------------------
# # Load .env DB config
# # ---------------------------
# load_dotenv()
# DB_CONFIG = {
#     "host": os.getenv("DB_HOST", "localhost"),
#     "dbname": os.getenv("DB_NAME", "Gradle"),
#     "user": os.getenv("DB_USER", "postgres"),
#     "password": os.getenv("DB_PASS", ""),
#     "port": int(os.getenv("DB_PORT", 5432)),
# }
# TABLE_NAME = os.getenv("TABLE_NAME", "staging_table")

# # ---------------------------
# # DB Helpers
# # ---------------------------
# def get_conn():
#     return psycopg2.connect(**DB_CONFIG)

# def create_table():
#     ddl = f"""
#     CREATE TABLE IF NOT EXISTS {TABLE_NAME} (
#         staging_id SERIAL PRIMARY KEY,
#         vendor_name TEXT NOT NULL DEFAULT 'Gradle',
#         source_url TEXT UNIQUE,
#         raw_data JSONB NOT NULL,
#         processed BOOLEAN DEFAULT FALSE,
#         processed_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
#     );
#     """
#     with get_conn() as conn:
#         with conn.cursor() as cur:
#             cur.execute(ddl)
#             conn.commit()

# def insert_advisory(source_url, raw_data):
#     try:
#         with get_conn() as conn:
#             with conn.cursor() as cur:
#                 cur.execute(
#                     f"""
#                     INSERT INTO {TABLE_NAME} (source_url, raw_data)
#                     VALUES (%s, %s)
#                     ON CONFLICT (source_url) DO NOTHING;
#                     """,
#                     (source_url, json.dumps(raw_data))
#                 )
#                 conn.commit()
#     except Exception as e:
#         print(f"[DB] Error inserting {source_url}: {e}")

# # ---------------------------
# # Requests session
# # ---------------------------
# session = requests.Session()
# retry = Retry(total=5, backoff_factor=0.5, status_forcelist=[500,502,503,504])
# adapter = HTTPAdapter(max_retries=retry)
# session.mount("https://", adapter)
# session.mount("http://", adapter)
# HEADERS = {"User-Agent": "Mozilla/5.0 (compatible; ghsa-scraper/1.0)"}

# # ---------------------------
# # URLs / repo
# # ---------------------------
# OWNER_REPO = os.getenv("OWNER_REPO", "gradle/gradle")
# BASE_URL = f"https://github.com/{OWNER_REPO}/security/advisories"
# GITHUB_BASE = "https://github.com"

# # ---------------------------
# # Utilities
# # ---------------------------
# def normalize_href(href):
#     if href and href.startswith("/"):
#         return urljoin(GITHUB_BASE, href)
#     return href

# def get_section_by_heading_any(soup, headings, tag_regex=r"^h[1-6]$"):
#     pattern = re.compile(tag_regex)
#     for header in soup.find_all(pattern):
#         text = header.get_text(" ", strip=True).lower()
#         for h in headings:
#             if h.lower() in text:
#                 parts = []
#                 for sib in header.find_next_siblings():
#                     if sib.name and re.match(r"^h[1-6]$", sib.name):
#                         break
#                     parts.append(sib.get_text(" ", strip=True))
#                 return "\n\n".join(p for p in parts if p)
#     return None

# def get_section_by_h3(soup, heading_text):
#     for h3 in soup.find_all("h3"):
#         if heading_text.lower() in h3.get_text(" ", strip=True).lower():
#             parts, links = [], []
#             for sib in h3.find_next_siblings():
#                 if sib.name and sib.name.lower() == "h3":
#                     break
#                 parts.append(sib.get_text(" ", strip=True))
#                 for a in sib.find_all("a", href=True):
#                     links.append({"text": a.get_text(" ", strip=True), "href": normalize_href(a["href"])})
#             return {"text": "\n\n".join(p for p in parts if p), "links": links}
#     return {"text": None, "links": []}

# def extract_cwes(soup):
#     cwes = {}
#     for a in soup.find_all("a", href=True):
#         href = a["href"].strip()
#         if "cwe.mitre.org" in href.lower():
#             m = re.search(r"/cwe/index\.cfm\?id=(\d+)", href) or re.search(r"/data/definitions/(\d+)\.html", href)
#             cwe_id = f"CWE-{m.group(1)}" if m else a.get_text(" ", strip=True)
#             cwes[cwe_id] = {"CWE_ID": cwe_id, "Description": a.get_text(" ", strip=True), "Link": normalize_href(href)}
#     page_text = soup.get_text(" ", strip=True)
#     for m in re.finditer(r"\bCWE[-\u2011\s]?(\d{1,5})\b", page_text, flags=re.IGNORECASE):
#         cid = f"CWE-{m.group(1)}"
#         if cid not in cwes:
#             cwes[cid] = {"CWE_ID": cid, "Description": "", "Link": None}
#     return sorted(cwes.values(), key=lambda x: int(x["CWE_ID"].split("-")[1]) if x["CWE_ID"].split("-")[1].isdigit() else 999999)

# # ---------------------------
# # Fetch advisory details
# # ---------------------------
# def fetch_advisory_details(link):
#     try:
#         resp = session.get(link, headers=HEADERS, timeout=20)
#         resp.raise_for_status()
#         soup = BeautifulSoup(resp.text, "html.parser")
#         data = {"source_path": urlparse(link).path}

#         # CVE
#         cve_tag = soup.find(lambda tag: tag.name in ("h3","h4") and "CVE ID" in tag.get_text())
#         cve_id = cve_tag.find_next().get_text(" ", strip=True) if cve_tag else None
#         if not cve_id:
#             m = re.search(r"(CVE-\d{4}-\d{4,7})", soup.get_text(" ", strip=True))
#             cve_id = m.group(1) if m else None
#         data["CVE_ID"] = cve_id

#         # Severity
#         sev_tag = soup.find("span", class_=re.compile(r"Label", re.I))
#         data["Severity"] = sev_tag.get_text(" ", strip=True) if sev_tag else None

#         # CVSS Score & Vector
#         txt = soup.get_text(" ", strip=True)
#         cvss_score = re.search(r"\bCVSS\s*[:\-]?\s*([0-9]\.[0-9])\b", txt)
#         data["CVSS_Score"] = cvss_score.group(1) if cvss_score else None
#         cvss_vector = re.search(r"(AV:[ANCPLR\/].+?[\)\s])", txt)
#         data["CVSS_Vector"] = cvss_vector.group(1).strip() if cvss_vector else None

#         # CWEs
#         data["CWEs"] = extract_cwes(soup)

#         # Sections
#         data["Impact_Text"] = get_section_by_heading_any(soup, ["impact"])
#         for sec in ["description", "remediation", "mitigation", "acknowledgements", "exploitability"]:
#             val = get_section_by_heading_any(soup, [sec])
#             if val: data[sec.capitalize()] = val

#         # Patches / Workarounds / References
#         data["Patches"] = get_section_by_h3(soup, "Patches")
#         data["Workarounds"] = get_section_by_h3(soup, "Workarounds")
#         data["References"] = get_section_by_h3(soup, "References")

#         # Products
#         products = []
#         for box in soup.find_all("div", class_=re.compile(r"Box|box", re.I)):
#             pkg = {}
#             pname = box.find("span", class_=re.compile(r"f4|package|text-bold", re.I))
#             if pname: pkg["Package"] = pname.get_text(" ", strip=True)
#             aff = box.find(lambda t: t.name in ("h2","h3") and "Affected versions" in t.get_text(" ", strip=True))
#             if aff: pkg["Affected_Version"] = aff.find_next_sibling().get_text(" ", strip=True) if aff.find_next_sibling() else None
#             pat = box.find(lambda t: t.name in ("h2","h3") and "Patched versions" in t.get_text(" ", strip=True))
#             if pat: pkg["Patched_Version"] = pat.find_next_sibling().get_text(" ", strip=True) if pat.find_next_sibling() else None
#             if pkg: products.append(pkg)
#         if not products:
#             m = re.search(r"Affected versions[:\s]*(.+?)(?:Patched versions|$)", txt, flags=re.IGNORECASE | re.DOTALL)
#             if m: products.append({"Package": None, "Affected_Version": m.group(1).strip(), "Patched_Version": None})
#         data["Products"] = products

#         # Links
#         links = []
#         for a in soup.find_all("a", href=True):
#             links.append({"text": a.get_text(" ", strip=True), "href": normalize_href(a["href"])})
#         data["Other_Information_Links"] = links

#         return data
#     except Exception as e:
#         return {"error": str(e)}

# # ---------------------------
# # Parse advisory listing page
# # ---------------------------
# def parse_advisories(soup):
#     advisories = []
#     for row in soup.find_all("li", class_=re.compile(r"Box-row", re.I)):
#         try:
#             title_tag = row.find("a", class_=re.compile(r"Link--primary|link-primary", re.I)) or row.find("a", href=True)
#             if not title_tag: continue
#             link = urljoin(GITHUB_BASE, title_tag["href"])
#             ghsa_id = row.find("div", class_=re.compile(r"text-small", re.I))
#             ghsa_id = ghsa_id.get_text(" ", strip=True).split()[0] if ghsa_id else None
#             date_tag = row.find("relative-time")
#             date = date_tag["datetime"] if date_tag else None
#             advisories.append({
#                 "Title": title_tag.get_text(" ", strip=True),
#                 "Link": link,
#                 "GHSA_ID": ghsa_id,
#                 "Published_Date": date,
#                 "Severity": row.find("span", class_=re.compile(r"Label", re.I)).get_text(" ", strip=True) if row.find("span", class_=re.compile(r"Label", re.I)) else None
#             })
#         except Exception: continue
#     return advisories

# # ---------------------------
# # Fetch page
# # ---------------------------
# def fetch_page(page_num):
#     try:
#         resp = session.get(f"{BASE_URL}?state=published&page={page_num}", headers=HEADERS, timeout=15)
#         resp.raise_for_status()
#         return BeautifulSoup(resp.text, "html.parser")
#     except Exception: return None

# # ---------------------------
# # Fetch all advisories
# # ---------------------------
# def fetch_all_advisories(pages_limit=None, delay=0.5):
#     all_advs, page_num = [], 1
#     while True:
#         soup = fetch_page(page_num)
#         if not soup: break
#         page_advs = parse_advisories(soup)
#         if not page_advs: break
#         for adv in page_advs:
#             adv["CVE_Details"] = fetch_advisory_details(adv["Link"])
#             insert_advisory(adv["Link"], adv)
#             all_advs.append(adv)
#             time.sleep(delay)
#         page_num += 1
#         if pages_limit and page_num > pages_limit: break
#     return all_advs

# # ---------------------------
# # Main
# # ---------------------------
# if __name__ == "__main__":
#     create_table()
#     start = datetime.utcnow()
#     advisories = fetch_all_advisories(pages_limit=None, delay=0.75)
#     end = datetime.utcnow()
#     print(f"[Done] Total advisories stored: {len(advisories)} in {(end-start).total_seconds():.1f}s")





# import re
# import time
# import json
# import os
# import warnings
# from datetime import datetime
# from urllib.parse import urljoin, urlparse

# import requests
# from bs4 import BeautifulSoup
# import psycopg2
# from dotenv import load_dotenv
# from requests.adapters import HTTPAdapter
# from requests.packages.urllib3.util.retry import Retry

# # ---------------------------
# # Suppress warnings
# # ---------------------------
# warnings.filterwarnings("ignore", category=ResourceWarning)
# requests.packages.urllib3.disable_warnings()

# # ---------------------------
# # Load .env DB config
# # ---------------------------
# load_dotenv()
# DB_CONFIG = {
#     "host": os.getenv("DB_HOST", "localhost"),
#     "dbname": os.getenv("DB_NAME", "Gradle"),
#     "user": os.getenv("DB_USER", "postgres"),
#     "password": os.getenv("DB_PASS", ""),
#     "port": int(os.getenv("DB_PORT", 5432)),
# }
# TABLE_NAME = os.getenv("TABLE_NAME", "staging_table")

# # ---------------------------
# # DB Helpers
# # ---------------------------
# def get_conn():
#     return psycopg2.connect(**DB_CONFIG)

# def create_table():
#     ddl = f"""
#     CREATE TABLE IF NOT EXISTS {TABLE_NAME} (
#         staging_id SERIAL PRIMARY KEY,
#         vendor_name TEXT NOT NULL DEFAULT 'Gradle',
#         source_url TEXT UNIQUE,
#         raw_data JSONB NOT NULL,
#         processed BOOLEAN DEFAULT FALSE,
#         processed_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
#     );
#     """
#     with get_conn() as conn:
#         with conn.cursor() as cur:
#             cur.execute(ddl)
#             conn.commit()

# def insert_advisory(source_url, raw_data):
#     try:
#         with get_conn() as conn:
#             with conn.cursor() as cur:
#                 cur.execute(
#                     f"""
#                     INSERT INTO {TABLE_NAME} (source_url, raw_data)
#                     VALUES (%s, %s)
#                     ON CONFLICT (source_url) DO NOTHING;
#                     """,
#                     (source_url, json.dumps(raw_data))
#                 )
#                 conn.commit()
#     except Exception as e:
#         print(f"[DB] Error inserting {source_url}: {e}")

# # ---------------------------
# # Requests session
# # ---------------------------
# session = requests.Session()
# retry = Retry(total=5, backoff_factor=0.5, status_forcelist=[500,502,503,504])
# adapter = HTTPAdapter(max_retries=retry)
# session.mount("https://", adapter)
# session.mount("http://", adapter)
# HEADERS = {"User-Agent": "Mozilla/5.0 (compatible; ghsa-scraper/1.0)"}

# # ---------------------------
# # URLs / repo
# # ---------------------------
# OWNER_REPO = os.getenv("OWNER_REPO", "gradle/gradle")
# BASE_URL = f"https://github.com/{OWNER_REPO}/security/advisories"
# GITHUB_BASE = "https://github.com"

# # ---------------------------
# # Utilities
# # ---------------------------
# def normalize_href(href):
#     if href and href.startswith("/"):
#         return urljoin(GITHUB_BASE, href)
#     return href

# def get_section_by_heading_any(soup, headings, tag_regex=r"^h[1-6]$"):
#     pattern = re.compile(tag_regex)
#     for header in soup.find_all(pattern):
#         text = header.get_text(" ", strip=True).lower()
#         for h in headings:
#             if h.lower() in text:
#                 parts = []
#                 for sib in header.find_next_siblings():
#                     if sib.name and re.match(r"^h[1-6]$", sib.name):
#                         break
#                     parts.append(sib.get_text(" ", strip=True))
#                 return "\n\n".join(p for p in parts if p)
#     return None

# def get_section_by_h3(soup, heading_text):
#     for h3 in soup.find_all("h3"):
#         if heading_text.lower() in h3.get_text(" ", strip=True).lower():
#             parts, links = [], []
#             for sib in h3.find_next_siblings():
#                 if sib.name and sib.name.lower() == "h3":
#                     break
#                 parts.append(sib.get_text(" ", strip=True))
#                 for a in sib.find_all("a", href=True):
#                     links.append({"text": a.get_text(" ", strip=True), "href": normalize_href(a["href"])})
#             return {"text": "\n\n".join(p for p in parts if p), "links": links}
#     return {"text": None, "links": []}

# def extract_cwes(soup):
#     cwes = {}
#     for a in soup.find_all("a", href=True):
#         href = a["href"].strip()
#         if "cwe.mitre.org" in href.lower():
#             m = re.search(r"/cwe/index\.cfm\?id=(\d+)", href) or re.search(r"/data/definitions/(\d+)\.html", href)
#             cwe_id = f"CWE-{m.group(1)}" if m else a.get_text(" ", strip=True)
#             cwes[cwe_id] = {"CWE_ID": cwe_id, "Description": a.get_text(" ", strip=True), "Link": normalize_href(href)}
#     page_text = soup.get_text(" ", strip=True)
#     for m in re.finditer(r"\bCWE[-\u2011\s]?(\d{1,5})\b", page_text, flags=re.IGNORECASE):
#         cid = f"CWE-{m.group(1)}"
#         if cid not in cwes:
#             cwes[cid] = {"CWE_ID": cid, "Description": "", "Link": None}
#     return sorted(cwes.values(), key=lambda x: int(x["CWE_ID"].split("-")[1]) if x["CWE_ID"].split("-")[1].isdigit() else 999999)

# # ---------------------------
# # Fetch advisory details
# # ---------------------------
# def fetch_advisory_details(link):
#     try:
#         resp = session.get(link, headers=HEADERS, timeout=20)
#         resp.raise_for_status()
#         soup = BeautifulSoup(resp.text, "html.parser")
#         data = {"source_path": urlparse(link).path}

#         # CVE
#         cve_tag = soup.find(lambda tag: tag.name in ("h3","h4") and "CVE ID" in tag.get_text())
#         cve_id = cve_tag.find_next().get_text(" ", strip=True) if cve_tag else None
#         if not cve_id:
#             m = re.search(r"(CVE-\d{4}-\d{4,7})", soup.get_text(" ", strip=True))
#             cve_id = m.group(1) if m else None
#         data["CVE_ID"] = cve_id

#         # Severity
#         sev_tag = soup.find("span", class_=re.compile(r"Label", re.I))
#         data["Severity"] = sev_tag.get_text(" ", strip=True) if sev_tag else None

#         # CVSS Score & Vector
#         txt = soup.get_text(" ", strip=True)
#         cvss_score = re.search(r"\bCVSS\s*[:\-]?\s*([0-9]\.[0-9])\b", txt)
#         data["CVSS_Score"] = cvss_score.group(1) if cvss_score else None
#         cvss_vector = re.search(r"(AV:[ANCPLR\/].+?[\)\s])", txt)
#         data["CVSS_Vector"] = cvss_vector.group(1).strip() if cvss_vector else None

#         # CWEs
#         data["CWEs"] = extract_cwes(soup)

#         # --- CWE Pattern Fallback ---
#         if not data["CWEs"]:
#             cwe_pattern = re.findall(r"\bCWE[-\u2011\s]?(\d{1,5})\b", txt, flags=re.IGNORECASE)
#             if cwe_pattern:
#                 for c in cwe_pattern:
#                     cid = f"CWE-{c}"
#                     data["CWEs"].append({"CWE_ID": cid, "Description": "", "Link": None})

#         # Sections
#         data["Impact_Text"] = get_section_by_heading_any(soup, ["impact"])
#         for sec in ["description", "remediation", "mitigation", "acknowledgements", "exploitability"]:
#             val = get_section_by_heading_any(soup, [sec])
#             if val: data[sec.capitalize()] = val

#         # Patches / Workarounds / References
#         data["Patches"] = get_section_by_h3(soup, "Patches")
#         data["Workarounds"] = get_section_by_h3(soup, "Workarounds")
#         data["References"] = get_section_by_h3(soup, "References")

#         # Products
#         products = []
#         for box in soup.find_all("div", class_=re.compile(r"Box|box", re.I)):
#             pkg = {}
#             pname = box.find("span", class_=re.compile(r"f4|package|text-bold", re.I))
#             if pname: pkg["Package"] = pname.get_text(" ", strip=True)
#             aff = box.find(lambda t: t.name in ("h2","h3") and "Affected versions" in t.get_text(" ", strip=True))
#             if aff: pkg["Affected_Version"] = aff.find_next_sibling().get_text(" ", strip=True) if aff.find_next_sibling() else None
#             pat = box.find(lambda t: t.name in ("h2","h3") and "Patched versions" in t.get_text(" ", strip=True))
#             if pat: pkg["Patched_Version"] = pat.find_next_sibling().get_text(" ", strip=True) if pat.find_next_sibling() else None
#             if pkg: products.append(pkg)
#         if not products:
#             m = re.search(r"Affected versions[:\s]*(.+?)(?:Patched versions|$)", txt, flags=re.IGNORECASE | re.DOTALL)
#             if m: products.append({"Package": None, "Affected_Version": m.group(1).strip(), "Patched_Version": None})
#         data["Products"] = products

#         # Links
#         links = []
#         for a in soup.find_all("a", href=True):
#             links.append({"text": a.get_text(" ", strip=True), "href": normalize_href(a["href"])})
#         data["Other_Information_Links"] = links

#         return data
#     except Exception as e:
#         return {"error": str(e)}

# # ---------------------------
# # Parse advisory listing page
# # ---------------------------
# def parse_advisories(soup):
#     advisories = []
#     for row in soup.find_all("li", class_=re.compile(r"Box-row", re.I)):
#         try:
#             title_tag = row.find("a", class_=re.compile(r"Link--primary|link-primary", re.I)) or row.find("a", href=True)
#             if not title_tag: continue
#             link = urljoin(GITHUB_BASE, title_tag["href"])
#             ghsa_id = row.find("div", class_=re.compile(r"text-small", re.I))
#             ghsa_id = ghsa_id.get_text(" ", strip=True).split()[0] if ghsa_id else None
#             date_tag = row.find("relative-time")
#             date = date_tag["datetime"] if date_tag else None
#             advisories.append({
#                 "Title": title_tag.get_text(" ", strip=True),
#                 "Link": link,
#                 "GHSA_ID": ghsa_id,
#                 "Published_Date": date,
#                 "Severity": row.find("span", class_=re.compile(r"Label", re.I)).get_text(" ", strip=True) if row.find("span", class_=re.compile(r"Label", re.I)) else None
#             })
#         except Exception: continue
#     return advisories

# # ---------------------------
# # Fetch page
# # ---------------------------
# def fetch_page(page_num):
#     try:
#         resp = session.get(f"{BASE_URL}?state=published&page={page_num}", headers=HEADERS, timeout=15)
#         resp.raise_for_status()
#         return BeautifulSoup(resp.text, "html.parser")
#     except Exception: return None

# # ---------------------------
# # Fetch all advisories
# # ---------------------------
# def fetch_all_advisories(pages_limit=None, delay=0.5):
#     all_advs, page_num = [], 1
#     while True:
#         soup = fetch_page(page_num)
#         if not soup: break
#         page_advs = parse_advisories(soup)
#         if not page_advs: break
#         for adv in page_advs:
#             adv["CVE_Details"] = fetch_advisory_details(adv["Link"])
#             insert_advisory(adv["Link"], adv)
#             all_advs.append(adv)
#             time.sleep(delay)
#         page_num += 1
#         if pages_limit and page_num > pages_limit: break
#     return all_advs

# # ---------------------------
# # Main
# # ---------------------------
# if __name__ == "__main__":
#     create_table()
#     start = datetime.utcnow()
#     advisories = fetch_all_advisories(pages_limit=None, delay=0.75)
#     end = datetime.utcnow()
#     print(f"[Done] Total advisories stored: {len(advisories)} in {(end-start).total_seconds():.1f}s")



# #!/usr/bin/env python3
# # -*- coding: utf-8 -*-

# import re
# import time
# import json
# import os
# import warnings
# from datetime import datetime
# from urllib.parse import urljoin, urlparse

# import requests
# from bs4 import BeautifulSoup
# import psycopg2
# from dotenv import load_dotenv
# from requests.adapters import HTTPAdapter
# from requests.packages.urllib3.util.retry import Retry

# # ---------------------------
# # Suppress warnings
# # ---------------------------
# warnings.filterwarnings("ignore", category=ResourceWarning)
# requests.packages.urllib3.disable_warnings()

# # ---------------------------
# # Load .env DB config
# # ---------------------------
# load_dotenv()
# DB_CONFIG = {
#     "host": os.getenv("DB_HOST", "localhost"),
#     "dbname": os.getenv("DB_NAME", "Gradle"),
#     "user": os.getenv("DB_USER", "postgres"),
#     "password": os.getenv("DB_PASS", ""),
#     "port": int(os.getenv("DB_PORT", 5432)),
# }
# TABLE_NAME = os.getenv("TABLE_NAME", "staging_table")

# # ---------------------------
# # DB Helpers
# # ---------------------------
# def get_conn():
#     return psycopg2.connect(**DB_CONFIG)

# def create_table():
#     ddl = f"""
#     CREATE TABLE IF NOT EXISTS {TABLE_NAME} (
#         staging_id SERIAL PRIMARY KEY,
#         vendor_name TEXT NOT NULL DEFAULT 'Gradle',
#         source_url TEXT UNIQUE,
#         raw_data JSONB NOT NULL,
#         processed BOOLEAN DEFAULT FALSE,
#         processed_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
#     );
#     """
#     with get_conn() as conn:
#         with conn.cursor() as cur:
#             cur.execute(ddl)
#             conn.commit()

# def insert_advisory(source_url, raw_data):
#     try:
#         with get_conn() as conn:
#             with conn.cursor() as cur:
#                 cur.execute(
#                     f"""
#                     INSERT INTO {TABLE_NAME} (source_url, raw_data)
#                     VALUES (%s, %s)
#                     ON CONFLICT (source_url) DO NOTHING;
#                     """,
#                     (source_url, json.dumps(raw_data))
#                 )
#                 conn.commit()
#                 return True
#     except Exception as e:
#         print(f"[DB] Error inserting {source_url}: {e}")
#     return False

# # ---------------------------
# # Requests session
# # ---------------------------
# session = requests.Session()
# retry = Retry(total=5, backoff_factor=0.5, status_forcelist=[500,502,503,504])
# adapter = HTTPAdapter(max_retries=retry)
# session.mount("https://", adapter)
# session.mount("http://", adapter)
# HEADERS = {"User-Agent": "Mozilla/5.0 (compatible; ghsa-scraper/1.0)"}

# # ---------------------------
# # URLs / repo
# # ---------------------------
# OWNER_REPO = os.getenv("OWNER_REPO", "gradle/gradle")
# BASE_URL = f"https://github.com/{OWNER_REPO}/security/advisories"
# GITHUB_BASE = "https://github.com"

# # ---------------------------
# # Utility helpers
# # ---------------------------
# def normalize_href(href):
#     if href and href.startswith("/"):
#         return urljoin(GITHUB_BASE, href)
#     return href

# def extract_cvss(soup):
#     """Extract CVSS score, vector, and base metrics cleanly"""
#     cvss_data = {"Score": None, "Vector": None, "BaseMetrics": {}}

#     # Score
#     score_tag = soup.find("div", {"data-show-dialog-id": re.compile("cvss-overall-score-id")})
#     if score_tag:
#         score_btn = score_tag.find("span", class_="Button-label")
#         if score_btn:
#             cvss_data["Score"] = score_btn.get_text(strip=True)

#     # Vector
#     vector_div = soup.find("div", string=re.compile(r"^CVSS:\d+\.\d+/"))
#     if vector_div:
#         cvss_data["Vector"] = vector_div.get_text(strip=True)

#     # Base metrics
#     base_section = soup.find("h4", string=re.compile("CVSS v3 base metrics", re.I))
#     if base_section:
#         for row in base_section.find_all_next("div", class_=re.compile("d-flex p-1")):
#             parts = row.get_text(" ", strip=True).split()
#             if len(parts) >= 2:
#                 key = parts[0].capitalize()
#                 val = " ".join(parts[1:])
#                 cvss_data["BaseMetrics"][key] = val

#     return cvss_data

# def extract_products(soup):
#     """Extract product/package + affected/patched versions"""
#     products = []
#     for box in soup.find_all("div", class_=re.compile(r"Box|box", re.I)):
#         pkg = {}
#         pname = box.find("span", class_=re.compile(r"f4|package|text-bold", re.I))
#         if pname: pkg["Package"] = pname.get_text(" ", strip=True)
#         aff = box.find(lambda t: t.name in ("h2","h3") and "Affected versions" in t.get_text(" ", strip=True))
#         if aff:
#             sibling = aff.find_next_sibling()
#             pkg["Affected_Version"] = sibling.get_text(" ", strip=True) if sibling else None
#         pat = box.find(lambda t: t.name in ("h2","h3") and "Patched versions" in t.get_text(" ", strip=True))
#         if pat:
#             sibling = pat.find_next_sibling()
#             pkg["Patched_Version"] = sibling.get_text(" ", strip=True) if sibling else None
#         if pkg: products.append(pkg)
#     return products

# # ---------------------------
# # Advisory details
# # ---------------------------
# def fetch_advisory_details(link):
#     resp = session.get(link, headers=HEADERS, timeout=20)
#     resp.raise_for_status()
#     soup = BeautifulSoup(resp.text, "html.parser")

#     data = {"source_path": urlparse(link).path}

#     # Title
#     title_tag = soup.find("h1")
#     data["Title"] = title_tag.get_text(" ", strip=True) if title_tag else None

#     # CVE
#     cve_id = None
#     txt = soup.get_text(" ", strip=True)
#     m = re.search(r"(CVE-\d{4}-\d{4,7})", txt)
#     if m:
#         cve_id = m.group(1)
#     data["CVE_ID"] = cve_id

#     # Severity
#     sev_tag = soup.find("span", class_=re.compile(r"Label", re.I))
#     data["Severity"] = sev_tag.get_text(" ", strip=True) if sev_tag else None

#     # CVSS
#     data["CVSS"] = extract_cvss(soup)

#     # Products
#     data["Products"] = extract_products(soup)

#     return data

# # ---------------------------
# # Advisory listing
# # ---------------------------
# def parse_advisories(soup):
#     advisories = []
#     for row in soup.find_all("li", class_=re.compile(r"Box-row", re.I)):
#         title_tag = row.find("a", class_=re.compile(r"Link--primary|link-primary", re.I))
#         if not title_tag: continue
#         link = urljoin(GITHUB_BASE, title_tag["href"])
#         advisories.append({
#             "Title": title_tag.get_text(" ", strip=True),
#             "Link": link,
#         })
#     return advisories

# def fetch_page(page_num):
#     resp = session.get(f"{BASE_URL}?state=published&page={page_num}", headers=HEADERS, timeout=15)
#     if resp.status_code != 200:
#         return None
#     return BeautifulSoup(resp.text, "html.parser")

# # ---------------------------
# # Fetch all advisories
# # ---------------------------
# def fetch_all_advisories(pages_limit=None, delay=0.5):
#     all_advs, page_num, total_inserted = [], 1, 0
#     while True:
#         soup = fetch_page(page_num)
#         if not soup: break
#         page_advs = parse_advisories(soup)
#         if not page_advs: break

#         print(f"\n[Page {page_num}] Found {len(page_advs)} advisories")
#         page_count = 0

#         for adv in page_advs:
#             adv["CVE_Details"] = fetch_advisory_details(adv["Link"])
#             inserted = insert_advisory(adv["Link"], adv)
#             if inserted:
#                 print(f"  [OK] Inserted: {adv['Link']}")
#                 page_count += 1
#                 total_inserted += 1
#             else:
#                 print(f"  [SKIP] Already exists: {adv['Link']}")
#             time.sleep(delay)

#         print(f"[Page {page_num}] Inserted: {page_count}")
#         page_num += 1
#         if pages_limit and page_num > pages_limit: break

#     print(f"\n[Done] Total advisories inserted: {total_inserted}")
#     return all_advs

# # ---------------------------
# # Main
# # ---------------------------
# if __name__ == "__main__":
#     create_table()
#     start = datetime.utcnow()
#     advisories = fetch_all_advisories(pages_limit=2, delay=1.0)  # limit pages for testing
#     end = datetime.utcnow()
#     print(f"[Finished] Runtime: {(end-start).total_seconds():.1f}s")





# #!/usr/bin/env python3
# # -*- coding: utf-8 -*-

# import re
# import time
# import json
# import os
# import warnings
# from datetime import datetime
# from urllib.parse import urljoin, urlparse

# import requests
# from bs4 import BeautifulSoup
# import psycopg2
# from dotenv import load_dotenv
# from requests.adapters import HTTPAdapter
# from requests.packages.urllib3.util.retry import Retry

# # ---------------------------
# # Suppress warnings
# # ---------------------------
# warnings.filterwarnings("ignore", category=ResourceWarning)
# requests.packages.urllib3.disable_warnings()

# # ---------------------------
# # Load .env DB config
# # ---------------------------
# load_dotenv()
# DB_CONFIG = {
#     "host": os.getenv("DB_HOST", "localhost"),
#     "dbname": os.getenv("DB_NAME", "Gradle"),
#     "user": os.getenv("DB_USER", "postgres"),
#     "password": os.getenv("DB_PASS", ""),
#     "port": int(os.getenv("DB_PORT", 5432)),
# }
# TABLE_NAME = os.getenv("TABLE_NAME", "staging_table")

# # ---------------------------
# # DB Helpers
# # ---------------------------
# def get_conn():
#     return psycopg2.connect(**DB_CONFIG)

# def create_table():
#     ddl = f"""
#     CREATE TABLE IF NOT EXISTS {TABLE_NAME} (
#         staging_id SERIAL PRIMARY KEY,
#         vendor_name TEXT NOT NULL DEFAULT 'Gradle',
#         source_url TEXT UNIQUE,
#         raw_data JSONB NOT NULL,
#         processed BOOLEAN DEFAULT FALSE,
#         processed_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
#     );
#     """
#     with get_conn() as conn:
#         with conn.cursor() as cur:
#             cur.execute(ddl)
#             conn.commit()

# def insert_advisory(source_url, raw_data):
#     try:
#         with get_conn() as conn:
#             with conn.cursor() as cur:
#                 cur.execute(
#                     f"""
#                     INSERT INTO {TABLE_NAME} (source_url, raw_data)
#                     VALUES (%s, %s)
#                     ON CONFLICT (source_url) DO NOTHING;
#                     """,
#                     (source_url, json.dumps(raw_data))
#                 )
#                 conn.commit()
#                 return True
#     except Exception as e:
#         print(f"[DB] Error inserting {source_url}: {e}")
#     return False

# # ---------------------------
# # Requests session
# # ---------------------------
# session = requests.Session()
# retry = Retry(total=5, backoff_factor=0.5, status_forcelist=[500,502,503,504])
# adapter = HTTPAdapter(max_retries=retry)
# session.mount("https://", adapter)
# session.mount("http://", adapter)
# HEADERS = {"User-Agent": "Mozilla/5.0 (compatible; ghsa-scraper/1.0)"}

# # ---------------------------
# # URLs / repo
# # ---------------------------
# OWNER_REPO = os.getenv("OWNER_REPO", "gradle/gradle")
# BASE_URL = f"https://github.com/{OWNER_REPO}/security/advisories"
# GITHUB_BASE = "https://github.com"

# # ---------------------------
# # Utilities
# # ---------------------------
# def normalize_href(href):
#     if href and href.startswith("/"):
#         return urljoin(GITHUB_BASE, href)
#     return href

# def get_section_by_heading_any(soup, headings, tag_regex=r"^h[1-6]$"):
#     pattern = re.compile(tag_regex)
#     for header in soup.find_all(pattern):
#         text = header.get_text(" ", strip=True).lower()
#         for h in headings:
#             if h.lower() in text:
#                 parts = []
#                 for sib in header.find_next_siblings():
#                     if sib.name and re.match(r"^h[1-6]$", sib.name):
#                         break
#                     parts.append(sib.get_text(" ", strip=True))
#                 return "\n\n".join(p for p in parts if p)
#     return None

# def get_section_by_h3(soup, heading_text):
#     for h3 in soup.find_all("h3"):
#         if heading_text.lower() in h3.get_text(" ", strip=True).lower():
#             parts, links = [], []
#             for sib in h3.find_next_siblings():
#                 if sib.name and sib.name.lower() == "h3":
#                     break
#                 parts.append(sib.get_text(" ", strip=True))
#                 for a in sib.find_all("a", href=True):
#                     links.append({"text": a.get_text(" ", strip=True), "href": normalize_href(a["href"])})
#             return {"text": "\n\n".join(p for p in parts if p), "links": links}
#     return {"text": None, "links": []}

# def extract_cwes(soup):
#     cwes = {}
#     for a in soup.find_all("a", href=True):
#         href = a["href"].strip()
#         if "cwe.mitre.org" in href.lower():
#             m = re.search(r"/cwe/index\.cfm\?id=(\d+)", href) or re.search(r"/data/definitions/(\d+)\.html", href)
#             cwe_id = f"CWE-{m.group(1)}" if m else a.get_text(" ", strip=True)
#             cwes[cwe_id] = {"CWE_ID": cwe_id, "Description": a.get_text(" ", strip=True), "Link": normalize_href(href)}
#     page_text = soup.get_text(" ", strip=True)
#     for m in re.finditer(r"\bCWE[-\u2011\s]?(\d{1,5})\b", page_text, flags=re.IGNORECASE):
#         cid = f"CWE-{m.group(1)}"
#         if cid not in cwes:
#             cwes[cid] = {"CWE_ID": cid, "Description": "", "Link": None}
#     return sorted(cwes.values(), key=lambda x: int(x["CWE_ID"].split("-")[1]) if x["CWE_ID"].split("-")[1].isdigit() else 999999)

# def extract_cvss(soup):
#     """Extract CVSS score, vector, and base metrics cleanly"""
#     cvss_data = {"Score": None, "Vector": None, "BaseMetrics": {}}
#     # Score
#     score_tag = soup.find("div", {"data-show-dialog-id": re.compile("cvss-overall-score-id")})
#     if score_tag:
#         score_btn = score_tag.find("span", class_="Button-label")
#         if score_btn:
#             cvss_data["Score"] = score_btn.get_text(strip=True)
#     # Vector
#     vector_div = soup.find("div", string=re.compile(r"^CVSS:\d+\.\d+/"))
#     if vector_div:
#         cvss_data["Vector"] = vector_div.get_text(strip=True)
#     # Base metrics
#     base_section = soup.find("h4", string=re.compile("CVSS v3 base metrics", re.I))
#     if base_section:
#         for row in base_section.find_all_next("div", class_=re.compile("d-flex p-1")):
#             parts = row.get_text(" ", strip=True).split()
#             if len(parts) >= 2:
#                 key = parts[0].capitalize()
#                 val = " ".join(parts[1:])
#                 cvss_data["BaseMetrics"][key] = val
#     return cvss_data

# # ---------------------------
# # Fetch advisory details
# # ---------------------------
# def fetch_advisory_details(link):
#     try:
#         resp = session.get(link, headers=HEADERS, timeout=20)
#         resp.raise_for_status()
#         soup = BeautifulSoup(resp.text, "html.parser")
#         data = {"source_path": urlparse(link).path}

#         # CVE
#         cve_tag = soup.find(lambda tag: tag.name in ("h3","h4") and "CVE ID" in tag.get_text())
#         cve_id = cve_tag.find_next().get_text(" ", strip=True) if cve_tag else None
#         if not cve_id:
#             m = re.search(r"(CVE-\d{4}-\d{4,7})", soup.get_text(" ", strip=True))
#             cve_id = m.group(1) if m else None
#         data["CVE_ID"] = cve_id

#         # Severity
#         sev_tag = soup.find("span", class_=re.compile(r"Label", re.I))
#         data["Severity"] = sev_tag.get_text(" ", strip=True) if sev_tag else None

#         # CVSS
#         data["CVSS"] = extract_cvss(soup)

#         # CWEs
#         data["CWEs"] = extract_cwes(soup)

#         # Sections
#         data["Impact_Text"] = get_section_by_heading_any(soup, ["impact"])
#         for sec in ["description", "remediation", "mitigation", "acknowledgements", "exploitability"]:
#             val = get_section_by_heading_any(soup, [sec])
#             if val: data[sec.capitalize()] = val

#         # Patches / Workarounds / References
#         data["Patches"] = get_section_by_h3(soup, "Patches")
#         data["Workarounds"] = get_section_by_h3(soup, "Workarounds")
#         data["References"] = get_section_by_h3(soup, "References")

#         # Products
#         products = []
#         for box in soup.find_all("div", class_=re.compile(r"Box|box", re.I)):
#             pkg = {}
#             pname = box.find("span", class_=re.compile(r"f4|package|text-bold", re.I))
#             if pname: pkg["Package"] = pname.get_text(" ", strip=True)
#             aff = box.find(lambda t: t.name in ("h2","h3") and "Affected versions" in t.get_text(" ", strip=True))
#             if aff: pkg["Affected_Version"] = aff.find_next_sibling().get_text(" ", strip=True) if aff.find_next_sibling() else None
#             pat = box.find(lambda t: t.name in ("h2","h3") and "Patched versions" in t.get_text(" ", strip=True))
#             if pat: pkg["Patched_Version"] = pat.find_next_sibling().get_text(" ", strip=True) if pat.find_next_sibling() else None
#             if pkg: products.append(pkg)
#         data["Products"] = products

#         # Links
#         links = []
#         for a in soup.find_all("a", href=True):
#             links.append({"text": a.get_text(" ", strip=True), "href": normalize_href(a["href"])})
#         data["Other_Information_Links"] = links

#         return data
#     except Exception as e:
#         return {"error": str(e)}

# # ---------------------------
# # Parse advisory listing page
# # ---------------------------
# def parse_advisories(soup):
#     advisories = []
#     for row in soup.find_all("li", class_=re.compile(r"Box-row", re.I)):
#         try:
#             title_tag = row.find("a", class_=re.compile(r"Link--primary|link-primary", re.I)) or row.find("a", href=True)
#             if not title_tag: continue
#             link = urljoin(GITHUB_BASE, title_tag["href"])
#             ghsa_id = row.find("div", class_=re.compile(r"text-small", re.I))
#             ghsa_id = ghsa_id.get_text(" ", strip=True).split()[0] if ghsa_id else None
#             date_tag = row.find("relative-time")
#             date = date_tag["datetime"] if date_tag else None
#             advisories.append({
#                 "Title": title_tag.get_text(" ", strip=True),
#                 "Link": link,
#                 "GHSA_ID": ghsa_id,
#                 "Published_Date": date,
#                 "Severity": row.find("span", class_=re.compile(r"Label", re.I)).get_text(" ", strip=True) if row.find("span", class_=re.compile(r"Label", re.I)) else None
#             })
#         except Exception:
#             continue
#     return advisories

# # ---------------------------
# # Fetch page
# # ---------------------------
# def fetch_page(page_num):
#     try:
#         resp = session.get(f"{BASE_URL}?state=published&page={page_num}", headers=HEADERS, timeout=15)
#         resp.raise_for_status()
#         return BeautifulSoup(resp.text, "html.parser")
#     except Exception:
#         return None

# # ---------------------------
# # Fetch all advisories
# # ---------------------------
# def fetch_all_advisories(pages_limit=None, delay=0.5):
#     all_advs, page_num, total_inserted = [], 1, 0
#     while True:
#         soup = fetch_page(page_num)
#         if not soup: break
#         page_advs = parse_advisories(soup)
#         if not page_advs: break
#         print(f"\n[Page {page_num}] Found {len(page_advs)} advisories")
#         page_count = 0
#         for adv in page_advs:
#             adv["CVE_Details"] = fetch_advisory_details(adv["Link"])
#             inserted = insert_advisory(adv["Link"], adv)
#             if inserted:
#                 print(f"  [OK] Inserted: {adv['Link']}")
#                 page_count += 1
#                 total_inserted += 1
#             else:
#                 print(f"  [SKIP] Already exists: {adv['Link']}")
#             time.sleep(delay)
#         print(f"[Page {page_num}] Inserted: {page_count}")
#         page_num += 1
#         if pages_limit and page_num > pages_limit: break
#     print(f"\n[Done] Total advisories inserted: {total_inserted}")
#     return all_advs

# # ---------------------------
# # Main
# # ---------------------------
# if __name__ == "__main__":
#     create_table()
#     start = datetime.utcnow()
#     advisories = fetch_all_advisories(pages_limit=2, delay=0.75)  # limit for testing
#     end = datetime.utcnow()
#     print(f"[Finished] Runtime: {(end-start).total_seconds():.1f}s")



# #!/usr/bin/env python3
# # -*- coding: utf-8 -*-

# import re
# import time
# import json
# import os
# import warnings
# from datetime import datetime
# from urllib.parse import urljoin, urlparse

# import requests
# from bs4 import BeautifulSoup
# import psycopg2
# from dotenv import load_dotenv
# from requests.adapters import HTTPAdapter
# from requests.packages.urllib3.util.retry import Retry

# # ---------------------------
# # Suppress warnings
# # ---------------------------
# warnings.filterwarnings("ignore", category=ResourceWarning)
# requests.packages.urllib3.disable_warnings()

# # ---------------------------
# # Load .env DB config
# # ---------------------------
# load_dotenv()
# DB_CONFIG = {
#     "host": os.getenv("DB_HOST", "localhost"),
#     "dbname": os.getenv("DB_NAME", "Gradle"),
#     "user": os.getenv("DB_USER", "postgres"),
#     "password": os.getenv("DB_PASS", ""),
#     "port": int(os.getenv("DB_PORT", 5432)),
# }
# TABLE_NAME = os.getenv("TABLE_NAME", "staging_table")

# # ---------------------------
# # DB Helpers
# # ---------------------------
# def get_conn():
#     return psycopg2.connect(**DB_CONFIG)

# def create_table():
#     ddl = f"""
#     CREATE TABLE IF NOT EXISTS {TABLE_NAME} (
#         staging_id SERIAL PRIMARY KEY,
#         vendor_name TEXT NOT NULL DEFAULT 'Gradle',
#         source_url TEXT UNIQUE,
#         raw_data JSONB NOT NULL,
#         processed BOOLEAN DEFAULT FALSE,
#         processed_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
#     );
#     """
#     with get_conn() as conn:
#         with conn.cursor() as cur:
#             cur.execute(ddl)
#             conn.commit()

# def insert_advisory(source_url, raw_data):
#     try:
#         with get_conn() as conn:
#             with conn.cursor() as cur:
#                 cur.execute(
#                     f"""
#                     INSERT INTO {TABLE_NAME} (source_url, raw_data)
#                     VALUES (%s, %s)
#                     ON CONFLICT (source_url) DO NOTHING;
#                     """,
#                     (source_url, json.dumps(raw_data))
#                 )
#                 conn.commit()
#     except Exception as e:
#         print(f"[DB] Error inserting {source_url}: {e}")

# # ---------------------------
# # Requests session
# # ---------------------------
# session = requests.Session()
# retry = Retry(total=5, backoff_factor=0.5, status_forcelist=[500,502,503,504])
# adapter = HTTPAdapter(max_retries=retry)
# session.mount("https://", adapter)
# session.mount("http://", adapter)
# HEADERS = {"User-Agent": "Mozilla/5.0 (compatible; ghsa-scraper/1.0)"}

# # ---------------------------
# # URLs / repo
# # ---------------------------
# OWNER_REPO = os.getenv("OWNER_REPO", "gradle/gradle")
# BASE_URL = f"https://github.com/{OWNER_REPO}/security/advisories"
# GITHUB_BASE = "https://github.com"

# # ---------------------------
# # Utilities
# # ---------------------------
# def normalize_href(href):
#     if href and href.startswith("/"):
#         return urljoin(GITHUB_BASE, href)
#     return href

# def get_text_section(soup, heading_text):
#     """Extract <p> text under a given heading until the next heading"""
#     for h in soup.find_all(["h2","h3","h4"]):
#         if heading_text.lower() in h.get_text(" ", strip=True).lower():
#             parts = []
#             for sib in h.find_next_siblings():
#                 if sib.name in ["h2","h3","h4"]:
#                     break
#                 if sib.name == "p":
#                     parts.append(sib.get_text(" ", strip=True))
#             return "\n\n".join(parts) if parts else None
#     return None

# def get_links_section(soup, heading_text):
#     """Extract only <li><a> links under a given heading"""
#     for h in soup.find_all(["h2","h3","h4"]):
#         if heading_text.lower() in h.get_text(" ", strip=True).lower():
#             links = []
#             for sib in h.find_next_siblings():
#                 if sib.name in ["h2","h3","h4"]:
#                     break
#                 for li in sib.find_all("li"):
#                     a = li.find("a", href=True)
#                     if a:
#                         links.append({"text": a.get_text(" ", strip=True), "href": normalize_href(a["href"])})
#             return links
#     return []

# def extract_cwes(soup):
#     cwes = {}
#     for a in soup.find_all("a", href=True):
#         href = a["href"].strip()
#         if "cwe.mitre.org" in href.lower():
#             m = re.search(r"/cwe/index\.cfm\?id=(\d+)", href) or re.search(r"/data/definitions/(\d+)\.html", href)
#             cwe_id = f"CWE-{m.group(1)}" if m else a.get_text(" ", strip=True)
#             cwes[cwe_id] = {"CWE_ID": cwe_id, "Description": a.get_text(" ", strip=True), "Link": normalize_href(href)}
#     return list(cwes.values())

# # ---------------------------
# # Fetch advisory details
# # ---------------------------
# def fetch_advisory_details(link):
#     try:
#         resp = session.get(link, headers=HEADERS, timeout=20)
#         resp.raise_for_status()
#         soup = BeautifulSoup(resp.text, "html.parser")
#         data = {"source_path": urlparse(link).path}

#         # CVE
#         m = re.search(r"(CVE-\d{4}-\d{4,7})", soup.get_text(" ", strip=True))
#         data["CVE_ID"] = m.group(1) if m else None

#         # Severity
#         sev_tag = soup.find("span", class_=re.compile(r"Label", re.I))
#         data["Severity"] = sev_tag.get_text(" ", strip=True) if sev_tag else None

#         # CVSS Score
#         txt = soup.get_text(" ", strip=True)
#         cvss_score = re.search(r"\bCVSS\s*[:\-]?\s*([0-9]\.[0-9])\b", txt)
#         data["CVSS_Score"] = cvss_score.group(1) if cvss_score else None

#         # CWEs
#         data["CWEs"] = extract_cwes(soup)

#         # Sections (only <p> text)
#         data["Description"] = get_text_section(soup, "description")
#         data["Impact"] = get_text_section(soup, "impact")
#         data["Workarounds"] = get_text_section(soup, "workaround")

#         # References (only li > a)
#         data["References"] = get_links_section(soup, "references")
#         data["Other_Information_Links"] = get_links_section(soup, "other")

#         # Products block
#         products = []
#         for box in soup.find_all("div", class_=re.compile(r"Box|box", re.I)):
#             pkg = {}
#             pname = box.find("span", class_=re.compile(r"f4|package|text-bold", re.I))
#             if pname:
#                 pkg["Package"] = pname.get_text(" ", strip=True)
#             aff = box.find(lambda t: t.name in ("h2","h3") and "Affected versions" in t.get_text(" ", strip=True))
#             if aff:
#                 pkg["Affected"] = aff.find_next_sibling().get_text(" ", strip=True) if aff.find_next_sibling() else None
#             pat = box.find(lambda t: t.name in ("h2","h3") and "Patched versions" in t.get_text(" ", strip=True))
#             if pat:
#                 pkg["Patched"] = pat.find_next_sibling().get_text(" ", strip=True) if pat.find_next_sibling() else None
#             if pkg:
#                 products.append(pkg)
#         data["Products"] = products

#         return data
#     except Exception as e:
#         return {"error": str(e)}

# # ---------------------------
# # Parse advisory listing page
# # ---------------------------
# def parse_advisories(soup):
#     advisories = []
#     for row in soup.find_all("li", class_=re.compile(r"Box-row", re.I)):
#         try:
#             title_tag = row.find("a", class_=re.compile(r"Link--primary|link-primary", re.I)) or row.find("a", href=True)
#             if not title_tag: continue
#             link = urljoin(GITHUB_BASE, title_tag["href"])
#             ghsa_id = row.find("div", class_=re.compile(r"text-small", re.I))
#             ghsa_id = ghsa_id.get_text(" ", strip=True).split()[0] if ghsa_id else None
#             date_tag = row.find("relative-time")
#             date = date_tag["datetime"] if date_tag else None
#             advisories.append({
#                 "Title": title_tag.get_text(" ", strip=True),
#                 "Link": link,
#                 "GHSA_ID": ghsa_id,
#                 "Published_Date": date,
#                 "Severity": row.find("span", class_=re.compile(r"Label", re.I)).get_text(" ", strip=True) if row.find("span", class_=re.compile(r"Label", re.I)) else None
#             })
#         except Exception:
#             continue
#     return advisories

# # ---------------------------
# # Fetch page
# # ---------------------------
# def fetch_page(page_num):
#     try:
#         resp = session.get(f"{BASE_URL}?state=published&page={page_num}", headers=HEADERS, timeout=15)
#         resp.raise_for_status()
#         return BeautifulSoup(resp.text, "html.parser")
#     except Exception:
#         return None

# # ---------------------------
# # Fetch all advisories
# # ---------------------------
# def fetch_all_advisories(pages_limit=None, delay=0.5):
#     all_advs, page_num = [], 1
#     while True:
#         soup = fetch_page(page_num)
#         if not soup: break
#         page_advs = parse_advisories(soup)
#         if not page_advs: break
#         for adv in page_advs:
#             adv["CVE_Details"] = fetch_advisory_details(adv["Link"])
#             insert_advisory(adv["Link"], adv)
#             all_advs.append(adv)
#             time.sleep(delay)
#         page_num += 1
#         if pages_limit and page_num > pages_limit: break
#     return all_advs

# # ---------------------------
# # Main
# # ---------------------------
# if __name__ == "__main__":
#     create_table()
#     start = datetime.utcnow()
#     advisories = fetch_all_advisories(pages_limit=None, delay=0.75)
#     end = datetime.utcnow()
#     print(f"[Done] Total advisories stored: {len(advisories)} in {(end-start).total_seconds():.1f}s")



# #!/usr/bin/env python3
# # -*- coding: utf-8 -*-

# import re
# import time
# import json
# import os
# import warnings
# from datetime import datetime
# from urllib.parse import urljoin, urlparse

# import requests
# from bs4 import BeautifulSoup
# import psycopg2
# from dotenv import load_dotenv
# from requests.adapters import HTTPAdapter
# from requests.packages.urllib3.util.retry import Retry

# # ---------------------------
# # Suppress warnings
# # ---------------------------
# warnings.filterwarnings("ignore", category=ResourceWarning)
# requests.packages.urllib3.disable_warnings()

# # ---------------------------
# # Load .env DB config
# # ---------------------------
# load_dotenv()
# DB_CONFIG = {
#     "host": os.getenv("DB_HOST", "localhost"),
#     "dbname": os.getenv("DB_NAME", "Gradle"),
#     "user": os.getenv("DB_USER", "postgres"),
#     "password": os.getenv("DB_PASS", ""),
#     "port": int(os.getenv("DB_PORT", 5432)),
# }
# TABLE_NAME = os.getenv("TABLE_NAME", "staging_table")
# OWNER_REPO = os.getenv("OWNER_REPO", "gradle/gradle")
# BASE_URL = f"https://github.com/{OWNER_REPO}/security/advisories"
# GITHUB_BASE = "https://github.com"

# # ---------------------------
# # DB Helpers
# # ---------------------------
# def get_conn():
#     return psycopg2.connect(**DB_CONFIG)

# def create_table():
#     ddl = f"""
#     CREATE TABLE IF NOT EXISTS {TABLE_NAME} (
#         staging_id SERIAL PRIMARY KEY,
#         vendor_name TEXT NOT NULL DEFAULT 'Gradle',
#         source_url TEXT UNIQUE,
#         raw_data JSONB NOT NULL,
#         processed BOOLEAN DEFAULT FALSE,
#         processed_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
#     );
#     """
#     with get_conn() as conn:
#         with conn.cursor() as cur:
#             cur.execute(ddl)
#             conn.commit()

# def insert_advisory(source_url, raw_data):
#     try:
#         with get_conn() as conn:
#             with conn.cursor() as cur:
#                 cur.execute(
#                     f"""
#                     INSERT INTO {TABLE_NAME} (source_url, raw_data)
#                     VALUES (%s, %s)
#                     ON CONFLICT (source_url) DO NOTHING;
#                     """,
#                     (source_url, json.dumps(raw_data))
#                 )
#                 conn.commit()
#     except Exception as e:
#         print(f"[DB] Error inserting {source_url}: {e}")

# def mark_processed(staging_id, data):
#     with get_conn() as conn:
#         with conn.cursor() as cur:
#             cur.execute(f"""
#                 UPDATE {TABLE_NAME} 
#                 SET raw_data=%s, processed=true, processed_at=NOW() 
#                 WHERE staging_id=%s
#             """, (json.dumps(data), staging_id))
#             conn.commit()

# # ---------------------------
# # Requests session
# # ---------------------------
# session = requests.Session()
# retry = Retry(total=5, backoff_factor=0.5, status_forcelist=[500,502,503,504])
# adapter = HTTPAdapter(max_retries=retry)
# session.mount("https://", adapter)
# session.mount("http://", adapter)
# HEADERS = {"User-Agent": "Mozilla/5.0 (compatible; ghsa-scraper/1.0)"}

# # ---------------------------
# # Utilities
# # ---------------------------
# def normalize_href(href):
#     if href and href.startswith("/"):
#         return urljoin(GITHUB_BASE, href)
#     return href

# def get_text_section(soup, heading_text):
#     for h in soup.find_all(["h2","h3","h4"]):
#         if heading_text.lower() in h.get_text(" ", strip=True).lower():
#             parts = []
#             for sib in h.find_next_siblings():
#                 if sib.name in ["h2","h3","h4"]:
#                     break
#                 if sib.name == "p":
#                     parts.append(sib.get_text(" ", strip=True))
#             return "\n\n".join(parts) if parts else None
#     return None

# def get_links_section(soup, heading_text):
#     for h in soup.find_all(["h2","h3","h4"]):
#         if heading_text.lower() in h.get_text(" ", strip=True).lower():
#             links = []
#             for sib in h.find_next_siblings():
#                 if sib.name in ["h2","h3","h4"]:
#                     break
#                 for li in sib.find_all("li"):
#                     a = li.find("a", href=True)
#                     if a:
#                         links.append({"text": a.get_text(" ", strip=True), "href": normalize_href(a["href"])})
#             return links
#     return []

# def extract_cwes(soup):
#     cwes = {}
#     for a in soup.find_all("a", href=True):
#         href = a["href"].strip()
#         if "cwe.mitre.org" in href.lower():
#             m = re.search(r"/cwe/index\.cfm\?id=(\d+)", href) or re.search(r"/data/definitions/(\d+)\.html", href)
#             cwe_id = f"CWE-{m.group(1)}" if m else a.get_text(" ", strip=True)
#             cwes[cwe_id] = {"CWE_ID": cwe_id, "Description": a.get_text(" ", strip=True), "Link": normalize_href(href)}
#     return list(cwes.values())

# # ---------------------------
# # Fetch advisory details
# # ---------------------------
# def fetch_advisory_details(link):
#     try:
#         resp = session.get(link, headers=HEADERS, timeout=20)
#         resp.raise_for_status()
#         soup = BeautifulSoup(resp.text, "html.parser")
#         data = {"source_path": urlparse(link).path}

#         # CVE
#         m = re.search(r"(CVE-\d{4}-\d{4,7})", soup.get_text(" ", strip=True))
#         data["CVE_ID"] = m.group(1) if m else None

#         # Severity
#         sev_tag = soup.find("span", class_=re.compile(r"Label", re.I))
#         data["Severity"] = sev_tag.get_text(" ", strip=True) if sev_tag else None

#         # CVSS Score
#         score_tag = soup.find("span", class_=re.compile(r"Button-label", re.I))
#         try:
#             data["CVSS_Score"] = float(score_tag.get_text(strip=True)) if score_tag else None
#         except ValueError:
#             data["CVSS_Score"] = None

#         # CVSS Vector
#         vector_tag = soup.find("div", string=re.compile(r"CVSS:", re.I))
#         if vector_tag:
#             vec_match = re.search(r"CVSS[:\s]*(.+)", vector_tag.get_text(strip=True))
#             data["CVSS_Vector"] = vec_match.group(1).strip() if vec_match else None
#         else:
#             data["CVSS_Vector"] = None

#         # CWEs
#         data["CWEs"] = extract_cwes(soup)

#         # Sections
#         data["Description"] = get_text_section(soup, "impact")  # store impact as description
#         data["Impact"] = get_text_section(soup, "impact")
#         data["Workarounds"] = get_text_section(soup, "workaround")

#         # References
#         data["References"] = get_links_section(soup, "references")
#         data["Other_Information_Links"] = get_links_section(soup, "other")

#         # Products
#         products = []
#         for box in soup.find_all("div", class_=re.compile(r"Box|box", re.I)):
#             pkg = {}
#             pname = box.find("span", class_=re.compile(r"f4|package|text-bold", re.I))
#             if pname:
#                 pkg["Package"] = pname.get_text(" ", strip=True)
#             aff = box.find(lambda t: t.name in ("h2","h3") and "Affected versions" in t.get_text(" ", strip=True))
#             if aff:
#                 pkg["Affected"] = aff.find_next_sibling().get_text(" ", strip=True) if aff.find_next_sibling() else None
#             pat = box.find(lambda t: t.name in ("h2","h3") and "Patched versions" in t.get_text(" ", strip=True))
#             if pat:
#                 pkg["Patched"] = pat.find_next_sibling().get_text(" ", strip=True) if pat.find_next_sibling() else None
#             if pkg:
#                 products.append(pkg)
#         data["Products"] = products

#         return data
#     except Exception as e:
#         return {"error": str(e)}

# # ---------------------------
# # Parse advisory listing page
# # ---------------------------
# def parse_advisories(soup):
#     advisories = []
#     for row in soup.find_all("li", class_=re.compile(r"Box-row", re.I)):
#         try:
#             title_tag = row.find("a", class_=re.compile(r"Link--primary|link-primary", re.I)) or row.find("a", href=True)
#             if not title_tag: continue
#             link = urljoin(GITHUB_BASE, title_tag["href"])
#             ghsa_id = row.find("div", class_=re.compile(r"text-small", re.I))
#             ghsa_id = ghsa_id.get_text(" ", strip=True).split()[0] if ghsa_id else None
#             date_tag = row.find("relative-time")
#             date = date_tag["datetime"] if date_tag else None
#             advisories.append({
#                 "Title": title_tag.get_text(" ", strip=True),
#                 "Link": link,
#                 "GHSA_ID": ghsa_id,
#                 "Published_Date": date,
#                 "Severity": row.find("span", class_=re.compile(r"Label", re.I)).get_text(" ", strip=True) if row.find("span", class_=re.compile(r"Label", re.I)) else None
#             })
#         except Exception:
#             continue
#     return advisories

# # ---------------------------
# # Fetch page
# # ---------------------------
# def fetch_page(page_num):
#     try:
#         resp = session.get(f"{BASE_URL}?state=published&page={page_num}", headers=HEADERS, timeout=15)
#         resp.raise_for_status()
#         return BeautifulSoup(resp.text, "html.parser")
#     except Exception:
#         return None

# # ---------------------------
# # Fetch all advisories
# # ---------------------------
# def fetch_all_advisories(pages_limit=None, delay=0.5):
#     all_advs, page_num = [], 1
#     while True:
#         soup = fetch_page(page_num)
#         if not soup: break
#         page_advs = parse_advisories(soup)
#         if not page_advs: break
#         for adv in page_advs:
#             adv["CVE_Details"] = fetch_advisory_details(adv["Link"])
#             insert_advisory(adv["Link"], adv)
#             all_advs.append(adv)
#             time.sleep(delay)
#         page_num += 1
#         if pages_limit and page_num > pages_limit: break
#     return all_advs

# # ---------------------------
# # Normalize staging
# # ---------------------------
# def normalize_gradle():
#     with get_conn() as conn:
#         with conn.cursor() as cur:
#             cur.execute(f"""
#                 SELECT staging_id, raw_data FROM {TABLE_NAME}
#                 WHERE vendor_name='Gradle' AND processed=false
#                 ORDER BY staging_id
#             """)
#             rows = cur.fetchall()
#             for staging_id, raw_json in rows:
#                 data = raw_json if isinstance(raw_json, dict) else json.loads(raw_json)
#                 details = fetch_advisory_details(data.get("Link"))
#                 data["CVE_Details"] = details
#                 mark_processed(staging_id, data)
#                 print(f"[Processed] {data.get('Link')}")

# # ---------------------------
# # Main
# # ---------------------------
# if __name__ == "__main__":
#     create_table()
#     start = datetime.utcnow()
#     advisories = fetch_all_advisories(pages_limit=None, delay=0.75)
#     end = datetime.utcnow()
#     print(f"[Done] Total advisories stored: {len(advisories)} in {(end-start).total_seconds():.1f}s")

# #!/usr/bin/env python3
# # -*- coding: utf-8 -*-

# import re
# import time
# import json
# import os
# import warnings
# from datetime import datetime
# from urllib.parse import urljoin, urlparse

# import requests
# from bs4 import BeautifulSoup
# import psycopg2
# from dotenv import load_dotenv
# from requests.adapters import HTTPAdapter
# from requests.packages.urllib3.util.retry import Retry

# # ---------------------------
# # Suppress warnings
# # ---------------------------
# warnings.filterwarnings("ignore", category=ResourceWarning)
# requests.packages.urllib3.disable_warnings()

# # ---------------------------
# # Load .env DB config
# # ---------------------------
# load_dotenv()
# DB_CONFIG = {
#     "host": os.getenv("DB_HOST", "localhost"),
#     "dbname": os.getenv("DB_NAME", "Gradle"),
#     "user": os.getenv("DB_USER", "postgres"),
#     "password": os.getenv("DB_PASS", ""),
#     "port": int(os.getenv("DB_PORT", 5432)),
# }
# TABLE_NAME = os.getenv("TABLE_NAME", "staging_table")
# OWNER_REPO = os.getenv("OWNER_REPO", "gradle/gradle")
# BASE_URL = f"https://github.com/{OWNER_REPO}/security/advisories"
# GITHUB_BASE = "https://github.com"

# # ---------------------------
# # DB Helpers
# # ---------------------------
# def get_conn():
#     return psycopg2.connect(**DB_CONFIG)

# def create_table():
#     ddl = f"""
#     CREATE TABLE IF NOT EXISTS {TABLE_NAME} (
#         staging_id SERIAL PRIMARY KEY,
#         vendor_name TEXT NOT NULL DEFAULT 'Gradle',
#         source_url TEXT UNIQUE,
#         raw_data JSONB NOT NULL,
#         processed BOOLEAN DEFAULT FALSE,
#         processed_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
#     );
#     """
#     with get_conn() as conn:
#         with conn.cursor() as cur:
#             cur.execute(ddl)
#             conn.commit()

# def insert_advisory(source_url, raw_data):
#     try:
#         with get_conn() as conn:
#             with conn.cursor() as cur:
#                 cur.execute(
#                     f"""
#                     INSERT INTO {TABLE_NAME} (source_url, raw_data)
#                     VALUES (%s, %s)
#                     ON CONFLICT (source_url) DO NOTHING;
#                     """,
#                     (source_url, json.dumps(raw_data))
#                 )
#                 conn.commit()
#     except Exception as e:
#         print(f"[DB Error] {source_url}: {e}")

# def mark_processed(staging_id, data):
#     with get_conn() as conn:
#         with conn.cursor() as cur:
#             cur.execute(f"""
#                 UPDATE {TABLE_NAME} 
#                 SET raw_data=%s, processed=true, processed_at=NOW() 
#                 WHERE staging_id=%s
#             """, (json.dumps(data), staging_id))
#             conn.commit()

# # ---------------------------
# # Requests session
# # ---------------------------
# session = requests.Session()
# retry = Retry(total=5, backoff_factor=0.5, status_forcelist=[500,502,503,504])
# adapter = HTTPAdapter(max_retries=retry)
# session.mount("https://", adapter)
# session.mount("http://", adapter)
# HEADERS = {"User-Agent": "Mozilla/5.0 (compatible; ghsa-scraper/1.0)"}

# # ---------------------------
# # Utilities
# # ---------------------------
# def normalize_href(href):
#     if href and href.startswith("/"):
#         return urljoin(GITHUB_BASE, href)
#     return href

# def get_text_section(soup, heading_text):
#     for h in soup.find_all(["h2","h3","h4"]):
#         if heading_text.lower() in h.get_text(" ", strip=True).lower():
#             parts = []
#             for sib in h.find_next_siblings():
#                 if sib.name in ["h2","h3","h4"]:
#                     break
#                 if sib.name == "p":
#                     parts.append(sib.get_text(" ", strip=True))
#             return "\n\n".join(parts) if parts else None
#     return None

# def get_links_section(soup, heading_text):
#     for h in soup.find_all(["h2","h3","h4"]):
#         if heading_text.lower() in h.get_text(" ", strip=True).lower():
#             links = []
#             for sib in h.find_next_siblings():
#                 if sib.name in ["h2","h3","h4"]:
#                     break
#                 for li in sib.find_all("li"):
#                     a = li.find("a", href=True)
#                     if a:
#                         links.append({
#                             "text": a.get_text(" ", strip=True),
#                             "href": normalize_href(a["href"])
#                         })
#             return links
#     return []

# def extract_cwes(soup):
#     cwes = []
#     seen = set()
#     for a in soup.find_all("a", href=True):
#         href = a["href"].strip()
#         if "cwe.mitre.org" in href.lower():
#             m = re.search(r"/cwe/index\.cfm\?id=(\d+)", href) or re.search(r"/data/definitions/(\d+)\.html", href)
#             cwe_id = f"CWE-{m.group(1)}" if m else a.get_text(strip=True)
#             if cwe_id not in seen:
#                 cwes.append(cwe_id)
#                 seen.add(cwe_id)
#     return cwes

# # ---------------------------
# # Fetch advisory details
# # ---------------------------
# def fetch_advisory_details(link):
#     try:
#         resp = session.get(link, headers=HEADERS, timeout=20)
#         resp.raise_for_status()
#         soup = BeautifulSoup(resp.text, "html.parser")
#         data = {"source_path": urlparse(link).path}

#         # CVE
#         m = re.search(r"(CVE-\d{4}-\d{4,7})", soup.get_text(" ", strip=True))
#         data["CVE_ID"] = m.group(1) if m else None

#         # Severity
#         sev_tag = soup.select_one('span[title^="Severity"]')
#         data["Severity"] = sev_tag.get_text(strip=True) if sev_tag else None

#         # CVSS Score
#         score_tag = soup.select_one("span.Button-label")
#         try:
#             data["CVSS_Score"] = float(score_tag.get_text(strip=True)) if score_tag else None
#         except ValueError:
#             data["CVSS_Score"] = None

#         # CVSS Vector
#         vector_tag = soup.find(string=re.compile(r"CVSS:\d", re.I))
#         if vector_tag:
#             data["CVSS_Vector"] = vector_tag.strip()
#         else:
#             div_tag = soup.find("div", string=re.compile(r"CVSS:", re.I))
#             data["CVSS_Vector"] = div_tag.get_text(strip=True) if div_tag else None

#         # CWEs
#         cwes_list = extract_cwes(soup)
#         data["CWE_IDs"] = ",".join(cwes_list) if cwes_list else None

#         # Sections
#         data["Description"] = get_text_section(soup, "impact")
#         data["Impact"] = get_text_section(soup, "impact")
#         data["Workarounds"] = get_text_section(soup, "workaround")

#         # References & Other Information
#         data["References"] = get_links_section(soup, "references")
#         data["Other_Information_Links"] = get_links_section(soup, "other")

#         # Products
#         products = []
#         for box in soup.find_all("div", class_=re.compile(r"Box|box", re.I)):
#             pkg = {}
#             pname = box.find("span", class_=re.compile(r"f4|package|text-bold", re.I))
#             if pname:
#                 pkg["Package"] = pname.get_text(" ", strip=True)
#             aff = box.find(lambda t: t.name in ("h2","h3") and "Affected versions" in t.get_text(" ", strip=True))
#             if aff:
#                 pkg["Affected"] = aff.find_next_sibling().get_text(" ", strip=True) if aff.find_next_sibling() else None
#             pat = box.find(lambda t: t.name in ("h2","h3") and "Patched versions" in t.get_text(" ", strip=True))
#             if pat:
#                 pkg["Patched"] = pat.find_next_sibling().get_text(" ", strip=True) if pat.find_next_sibling() else None
#             if pkg:
#                 products.append(pkg)
#         data["Products"] = products

#         return data
#     except Exception as e:
#         return {"error": str(e)}

# # ---------------------------
# # Parse advisory listing page
# # ---------------------------
# def parse_advisories(soup):
#     advisories = []
#     for row in soup.find_all("li", class_=re.compile(r"Box-row", re.I)):
#         try:
#             title_tag = row.find("a", class_=re.compile(r"Link--primary|link-primary", re.I)) or row.find("a", href=True)
#             if not title_tag: continue
#             link = urljoin(GITHUB_BASE, title_tag["href"])
#             ghsa_id = row.find("div", class_=re.compile(r"text-small", re.I))
#             ghsa_id = ghsa_id.get_text(" ", strip=True).split()[0] if ghsa_id else None
#             date_tag = row.find("relative-time")
#             date = date_tag["datetime"] if date_tag else None
#             advisories.append({
#                 "Title": title_tag.get_text(" ", strip=True),
#                 "Link": link,
#                 "GHSA_ID": ghsa_id,
#                 "Published_Date": date,
#                 "Severity": row.find("span", class_=re.compile(r"Label", re.I)).get_text(strip=True) if row.find("span", class_=re.compile(r"Label", re.I)) else None
#             })
#         except Exception:
#             continue
#     return advisories

# # ---------------------------
# # Fetch page
# # ---------------------------
# def fetch_page(page_num):
#     try:
#         resp = session.get(f"{BASE_URL}?state=published&page={page_num}", headers=HEADERS, timeout=15)
#         resp.raise_for_status()
#         return BeautifulSoup(resp.text, "html.parser")
#     except Exception:
#         return None

# # ---------------------------
# # Fetch all advisories
# # ---------------------------
# def fetch_all_advisories(pages_limit=None, delay=0.5):
#     all_advs, page_num = [], 1
#     while True:
#         soup = fetch_page(page_num)
#         if not soup: break
#         page_advs = parse_advisories(soup)
#         if not page_advs: break
#         for adv in page_advs:
#             adv["CVE_Details"] = fetch_advisory_details(adv["Link"])
#             insert_advisory(adv["Link"], adv)
#             print(f"[Stored] {adv.get('Link')}")
#             all_advs.append(adv)
#             time.sleep(delay)
#         page_num += 1
#         if pages_limit and page_num > pages_limit: break
#     return all_advs

# # ---------------------------
# # Normalize staging
# # ---------------------------
# def normalize_gradle():
#     with get_conn() as conn:
#         with conn.cursor() as cur:
#             cur.execute(f"""
#                 SELECT staging_id, raw_data FROM {TABLE_NAME}
#                 WHERE vendor_name='Gradle' AND processed=false
#                 ORDER BY staging_id
#             """)
#             rows = cur.fetchall()
#             for staging_id, raw_json in rows:
#                 data = raw_json if isinstance(raw_json, dict) else json.loads(raw_json)
#                 details = fetch_advisory_details(data.get("Link"))
#                 data["CVE_Details"] = details
#                 mark_processed(staging_id, data)
#                 print(f"[Processed] {data.get('Link')}")

# # ---------------------------
# # Main
# # ---------------------------
# if __name__ == "__main__":
#     create_table()
#     start = datetime.utcnow()
#     advisories = fetch_all_advisories(pages_limit=None, delay=0.75)
#     end = datetime.utcnow()
#     print(f"[Done] Total advisories stored: {len(advisories)} in {(end-start).total_seconds():.1f}s")













# #!/usr/bin/env python3
# # -*- coding: utf-8 -*-

# import re
# import time
# import json
# import os
# import warnings
# from datetime import datetime, timezone
# from urllib.parse import urljoin

# import requests
# from bs4 import BeautifulSoup
# import psycopg2
# from dotenv import load_dotenv
# from requests.adapters import HTTPAdapter
# from requests.packages.urllib3.util.retry import Retry

# # ---------------------------
# # Suppress warnings
# # ---------------------------
# warnings.filterwarnings("ignore", category=ResourceWarning)
# requests.packages.urllib3.disable_warnings()

# # ---------------------------
# # Load .env DB config
# # ---------------------------
# load_dotenv()
# DB_CONFIG = {
#     "host": os.getenv("DB_HOST", "localhost"),
#     "dbname": os.getenv("DB_NAME", "Gradle"),
#     "user": os.getenv("DB_USER", "postgres"),
#     "password": os.getenv("DB_PASS", ""),
#     "port": int(os.getenv("DB_PORT", 5432)),
# }
# TABLE_NAME = os.getenv("TABLE_NAME", "staging_table")
# OWNER_REPO = os.getenv("OWNER_REPO", "gradle/gradle")
# BASE_URL = f"https://github.com/{OWNER_REPO}/security/advisories"
# GITHUB_BASE = "https://github.com"

# # ---------------------------
# # DB Helpers
# # ---------------------------
# def get_conn():
#     return psycopg2.connect(**DB_CONFIG)

# def create_table():
#     ddl = f"""
#     CREATE TABLE IF NOT EXISTS {TABLE_NAME} (
#         staging_id SERIAL PRIMARY KEY,
#         vendor_name TEXT NOT NULL DEFAULT 'Gradle',
#         source_url TEXT UNIQUE,
#         raw_data JSONB NOT NULL,
#         processed BOOLEAN DEFAULT FALSE,
#         processed_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
#     );
#     """
#     with get_conn() as conn:
#         with conn.cursor() as cur:
#             cur.execute(ddl)
#             conn.commit()

# def insert_advisory(source_url, raw_data):
#     with get_conn() as conn:
#         with conn.cursor() as cur:
#             cur.execute(
#                 f"""
#                 INSERT INTO {TABLE_NAME} (source_url, raw_data)
#                 VALUES (%s, %s)
#                 ON CONFLICT (source_url) DO NOTHING;
#                 """,
#                 (source_url, json.dumps(raw_data))
#             )
#             conn.commit()

# def mark_processed(staging_id, data):
#     with get_conn() as conn:
#         with conn.cursor() as cur:
#             cur.execute(f"""
#                 UPDATE {TABLE_NAME} 
#                 SET raw_data=%s, processed=true, processed_at=NOW() 
#                 WHERE staging_id=%s
#             """, (json.dumps(data), staging_id))
#             conn.commit()

# # ---------------------------
# # Requests session
# # ---------------------------
# session = requests.Session()
# retry = Retry(total=5, backoff_factor=0.5, status_forcelist=[500,502,503,504])
# adapter = HTTPAdapter(max_retries=retry)
# session.mount("https://", adapter)
# session.mount("http://", adapter)
# HEADERS = {"User-Agent": "Mozilla/5.0 (compatible; ghsa-scraper/1.0)"}

# # ---------------------------
# # Utilities
# # ---------------------------
# def normalize_href(href):
#     if href and href.startswith("/"):
#         return urljoin(GITHUB_BASE, href)
#     return href

# def get_text_section(soup, heading_text):
#     for h in soup.find_all(["h2","h3","h4"]):
#         if heading_text.lower() in h.get_text(" ", strip=True).lower():
#             parts = []
#             for sib in h.find_next_siblings():
#                 if sib.name in ["h2","h3","h4"]:
#                     break
#                 if sib.name == "p":
#                     parts.append(sib.get_text(" ", strip=True))
#             return "\n\n".join(parts) if parts else None
#     return None

# def get_links_section(soup, heading_text):
#     for h in soup.find_all(["h2","h3","h4"]):
#         if heading_text.lower() in h.get_text(" ", strip=True).lower():
#             links = []
#             for sib in h.find_next_siblings():
#                 if sib.name in ["h2","h3","h4"]:
#                     break
#                 for li in sib.find_all("li"):
#                     a = li.find("a", href=True)
#                     if a:
#                         links.append({
#                             "text": a.get_text(" ", strip=True),
#                             "href": normalize_href(a["href"])
#                         })
#             return links
#     return []

# def extract_cwes(soup):
#     cwes = []
#     seen = set()
#     for a in soup.find_all("a", href=True):
#         href = a["href"].strip()
#         if "cwe.mitre.org" in href.lower():
#             m = re.search(r"/cwe/index\.cfm\?id=(\d+)", href) or re.search(r"/data/definitions/(\d+)\.html", href)
#             cwe_id = f"CWE-{m.group(1)}" if m else a.get_text(strip=True)
#             if cwe_id not in seen:
#                 cwes.append({
#                     "cwe_id": cwe_id,
#                     "text": a.get_text(strip=True),
#                     "url": normalize_href(href),
#                     "description": None  # placeholder, can add scraping later if needed
#                 })
#                 seen.add(cwe_id)
#     return cwes

# # ---------------------------
# # Fetch advisory details
# # ---------------------------
# def fetch_advisory_details(link):
#     try:
#         resp = session.get(link, headers=HEADERS, timeout=20)
#         resp.raise_for_status()
#         soup = BeautifulSoup(resp.text, "html.parser")
#         data = {}

#         # CVE
#         m = re.search(r"(CVE-\d{4}-\d{4,7})", soup.get_text(" ", strip=True))
#         data["CVE_ID"] = m.group(1) if m else None

#         # Severity (from page labels)
#         sev_tag = soup.find("span", class_=re.compile(r"Label", re.I))
#         data["Severity"] = sev_tag.get_text(strip=True) if sev_tag else None

#         # CVSS Score
#         cvss_tag = soup.find(string=re.compile(r"CVSS.*", re.I))
#         if cvss_tag:
#             score_match = re.search(r"([0-9]+\.[0-9]+)", cvss_tag)
#             data["CVSS_Score"] = float(score_match.group(1)) if score_match else None
#         else:
#             data["CVSS_Score"] = None

#         # CWEs
#         data["CWEs"] = extract_cwes(soup)

#         # Sections
#         data["Description"] = get_text_section(soup, "impact")
#         data["Impact"] = get_text_section(soup, "impact")
#         data["Workarounds"] = get_text_section(soup, "workaround")

#         # References & Other Information
#         data["References"] = get_links_section(soup, "references")
#         data["Other_Information_Links"] = get_links_section(soup, "other")

#         # Products
#         products = []
#         for box in soup.find_all("div", class_=re.compile(r"Box|box", re.I)):
#             pkg = {}
#             pname = box.find("span", class_=re.compile(r"f4|package|text-bold", re.I))
#             if pname:
#                 pkg["Package"] = pname.get_text(" ", strip=True)
#             aff = box.find(lambda t: t.name in ("h2","h3") and "Affected versions" in t.get_text(" ", strip=True))
#             if aff:
#                 pkg["Affected"] = aff.find_next_sibling().get_text(" ", strip=True) if aff.find_next_sibling() else None
#             pat = box.find(lambda t: t.name in ("h2","h3") and "Patched versions" in t.get_text(" ", strip=True))
#             if pat:
#                 pkg["Patched"] = pat.find_next_sibling().get_text(" ", strip=True) if pat.find_next_sibling() else None
#             if pkg:
#                 products.append(pkg)
#         data["Products"] = products

#         return data
#     except Exception as e:
#         return {"error": str(e)}

# # ---------------------------
# # Parse advisory listing page
# # ---------------------------
# def parse_advisories(soup):
#     advisories = []
#     for row in soup.find_all("li", class_=re.compile(r"Box-row", re.I)):
#         try:
#             title_tag = row.find("a", class_=re.compile(r"Link--primary|link-primary", re.I)) or row.find("a", href=True)
#             if not title_tag: continue
#             link = urljoin(GITHUB_BASE, title_tag["href"])
#             ghsa_id = row.find("div", class_=re.compile(r"text-small", re.I))
#             ghsa_id = ghsa_id.get_text(" ", strip=True).split()[0] if ghsa_id else None
#             date_tag = row.find("relative-time")
#             date = date_tag["datetime"] if date_tag else None
#             advisories.append({
#                 "Title": title_tag.get_text(" ", strip=True),
#                 "Link": link,
#                 "GHSA_ID": ghsa_id,
#                 "Published_Date": date,
#                 "Severity": row.find("span", class_=re.compile(r"Label", re.I)).get_text(strip=True) if row.find("span", class_=re.compile(r"Label", re.I)) else None
#             })
#         except Exception:
#             continue
#     return advisories

# # ---------------------------
# # Fetch page
# # ---------------------------
# def fetch_page(page_num):
#     try:
#         resp = session.get(f"{BASE_URL}?state=published&page={page_num}", headers=HEADERS, timeout=15)
#         resp.raise_for_status()
#         return BeautifulSoup(resp.text, "html.parser")
#     except Exception:
#         return None

# # ---------------------------
# # Fetch all advisories
# # ---------------------------
# def fetch_all_advisories(pages_limit=None, delay=0.5):
#     all_advs, page_num = [], 1
#     while True:
#         soup = fetch_page(page_num)
#         if not soup: break
#         page_advs = parse_advisories(soup)
#         if not page_advs: break

#         print(f"Page {page_num}")
#         for adv in page_advs:
#             adv["CVE_Details"] = fetch_advisory_details(adv["Link"])
#             insert_advisory(adv["Link"], adv)
#             print(f"  --> inserted {adv.get('Link')}")
#             all_advs.append(adv)
#             time.sleep(delay)

#         page_num += 1
#         if pages_limit and page_num > pages_limit: break
#     return all_advs

# # ---------------------------
# # Main
# # ---------------------------
# if __name__ == "__main__":
#     create_table()
#     start = datetime.now(timezone.utc)
#     advisories = fetch_all_advisories(pages_limit=None, delay=0.75)
#     end = datetime.now(timezone.utc)
#     print(f"[Done] Total advisories stored: {len(advisories)} in {(end-start).total_seconds():.1f}s")

# #!/usr/bin/env python3
# # -*- coding: utf-8 -*-

# import re
# import time
# import json
# import os
# import warnings
# from datetime import datetime, timezone
# from urllib.parse import urljoin

# import requests
# from bs4 import BeautifulSoup
# import psycopg2
# from dotenv import load_dotenv
# from requests.adapters import HTTPAdapter
# from requests.packages.urllib3.util.retry import Retry

# # ---------------------------
# # Suppress warnings
# # ---------------------------
# warnings.filterwarnings("ignore", category=ResourceWarning)
# requests.packages.urllib3.disable_warnings()

# # ---------------------------
# # Load .env DB config
# # ---------------------------
# load_dotenv()
# DB_CONFIG = {
#     "host": os.getenv("DB_HOST", "localhost"),
#     "dbname": os.getenv("DB_NAME", "Gradle"),
#     "user": os.getenv("DB_USER", "postgres"),
#     "password": os.getenv("DB_PASS", ""),
#     "port": int(os.getenv("DB_PORT", 5432)),
# }
# TABLE_NAME = os.getenv("TABLE_NAME", "staging_table")
# OWNER_REPO = os.getenv("OWNER_REPO", "gradle/gradle")
# BASE_URL = f"https://github.com/{OWNER_REPO}/security/advisories"
# GITHUB_BASE = "https://github.com"

# # ---------------------------
# # DB Helpers
# # ---------------------------
# def get_conn():
#     return psycopg2.connect(**DB_CONFIG)

# def create_table():
#     ddl = f"""
#     CREATE TABLE IF NOT EXISTS {TABLE_NAME} (
#         staging_id SERIAL PRIMARY KEY,
#         vendor_name TEXT NOT NULL DEFAULT 'Gradle',
#         source_url TEXT UNIQUE,
#         raw_data JSONB NOT NULL,
#         processed BOOLEAN DEFAULT FALSE,
#         processed_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
#     );
#     """
#     with get_conn() as conn:
#         with conn.cursor() as cur:
#             cur.execute(ddl)
#             conn.commit()

# def insert_advisory(source_url, raw_data):
#     with get_conn() as conn:
#         with conn.cursor() as cur:
#             cur.execute(
#                 f"""
#                 INSERT INTO {TABLE_NAME} (source_url, raw_data)
#                 VALUES (%s, %s)
#                 ON CONFLICT (source_url) DO NOTHING;
#                 """,
#                 (source_url, json.dumps(raw_data))
#             )
#             conn.commit()

# # ---------------------------
# # Requests session
# # ---------------------------
# session = requests.Session()
# retry = Retry(total=5, backoff_factor=0.5, status_forcelist=[500,502,503,504])
# adapter = HTTPAdapter(max_retries=retry)
# session.mount("https://", adapter)
# session.mount("http://", adapter)
# HEADERS = {"User-Agent": "Mozilla/5.0 (compatible; ghsa-scraper/1.0)"}

# # ---------------------------
# # Utilities
# # ---------------------------
# def normalize_href(href):
#     if href and href.startswith("/"):
#         return urljoin(GITHUB_BASE, href)
#     return href

# def get_h3_section_text(soup, heading):
#     """Return text under <h3> heading until next heading"""
#     for h in soup.find_all(["h2", "h3"]):
#         if heading.lower() in h.get_text(" ", strip=True).lower():
#             parts = []
#             for sib in h.find_next_siblings():
#                 if sib.name in ["h2", "h3"]:
#                     break
#                 if sib.name == "p":
#                     parts.append(sib.get_text(" ", strip=True))
#                 elif sib.name == "ul":
#                     for li in sib.find_all("li"):
#                         parts.append(li.get_text(" ", strip=True))
#             return "\n".join(parts).strip() if parts else None
#     return None

# def get_links_section(soup, heading_text):
#     for h in soup.find_all(["h2","h3"]):
#         if heading_text.lower() in h.get_text(" ", strip=True).lower():
#             links = []
#             for sib in h.find_next_siblings():
#                 if sib.name in ["h2","h3"]:
#                     break
#                 for li in sib.find_all("li"):
#                     a = li.find("a", href=True)
#                     if a:
#                         links.append({
#                             "text": a.get_text(" ", strip=True),
#                             "href": normalize_href(a["href"])
#                         })
#             return links
#     return []

# # ---------------------------
# # Extract CWE IDs (original)
# # ---------------------------
# def extract_cwes(soup):
#     cwes = []
#     seen = set()
#     for span in soup.select("div.js-repository-advisory-details details summary span"):
#         text = span.get_text(strip=True)
#         if text.upper().startswith("CWE-") and text not in seen:
#             cwes.append(text)
#             seen.add(text)
#     return cwes

# # ---------------------------
# # Extract CWE Data (new)
# # ---------------------------
# def extract_cwe_data(soup):
#     cwe_list = []
#     seen = set()
#     for a in soup.find_all("a", href=True):
#         text = a.get_text(" ", strip=True)
#         if re.match(r"CWE-\d+", text) and text not in seen:
#             cwe_list.append({
#                 "CWE_ID": text,
#                 "Text": text,
#                 "URL": normalize_href(a["href"])
#             })
#             seen.add(text)
#     return cwe_list

# # ---------------------------
# # Fetch advisory details
# # ---------------------------
# def fetch_advisory_details(link):
#     try:
#         resp = session.get(link, headers=HEADERS, timeout=20)
#         resp.raise_for_status()
#         soup = BeautifulSoup(resp.text, "html.parser")
#         html = resp.text
#         data = {}

#         # CVE ID from sidebar
#         cve_div = soup.find("div", class_="discussion-sidebar-item", string=re.compile("CVE ID"))
#         if cve_div:
#             sibling = cve_div.find_next_sibling("div")
#             data["CVE_ID"] = sibling.get_text(strip=True) if sibling else None
#         else:
#             m = re.search(r"(CVE-\d{4}-\d{4,7})", html)
#             data["CVE_ID"] = m.group(1) if m else None

#         # Severity
#         sev_tag = soup.select_one('span[title^="Severity"]')
#         if sev_tag:
#             data["Severity"] = sev_tag.get("title", "").replace("Severity:", "").strip()
#         else:
#             m = re.search(r'Severity[:\s]*([A-Za-z]+)', html, re.I)
#             data["Severity"] = m.group(1) if m else None

#         # CVSS Score
#         score_tag = soup.select_one("span.Button-label")
#         data["CVSS_Score"] = score_tag.text.strip() if score_tag else None

#         # CVSS Vector
#         cvss_vector_tag = soup.find(string=re.compile(r"CVSS:\d\.\d"))
#         data["CVSS_Vector"] = cvss_vector_tag.strip() if cvss_vector_tag else None

#         # CWEs
#         data["CWEs"] = extract_cwes(soup)
#         data["CWE_Data"] = extract_cwe_data(soup)

#         # Patched, Description, Impact, Workarounds
#         data["Patched"] = get_h3_section_text(soup, "Patches")
#         data["Description"] = get_h3_section_text(soup, "impact")
#         data["Impact"] = get_h3_section_text(soup, "impact")
#         data["Workarounds"] = get_h3_section_text(soup, "workaround")

#         # References / Other Links
#         data["References"] = get_links_section(soup, "references")
#         data["Other_Information_Links"] = get_links_section(soup, "other")

#         # Products
#         products = {}
#         for box in soup.find_all("div", class_=re.compile(r"Box-body")):
#             pkg_name_tag = box.find("span", class_=re.compile(r"f4 color-fg-default text-bold"))
#             if not pkg_name_tag:
#                 continue
#             pkg_name = pkg_name_tag.get_text(strip=True)
#             affected_tag = box.find(lambda t: t.name in ["h2","h3"] and "Affected versions" in t.get_text())
#             patched_tag = box.find(lambda t: t.name in ["h2","h3"] and "Patched versions" in t.get_text())
#             affected = affected_tag.find_next_sibling().get_text(strip=True) if affected_tag and affected_tag.find_next_sibling() else ""
#             patched = patched_tag.find_next_sibling().get_text(strip=True) if patched_tag and patched_tag.find_next_sibling() else ""
#             if pkg_name not in products:
#                 products[pkg_name] = {"Affected": [], "Patched": []}
#             products[pkg_name]["Affected"].extend([v.strip() for v in re.split(r"[,\[\]]+", affected) if v.strip()])
#             products[pkg_name]["Patched"].extend([v.strip() for v in re.split(r"[,\[\]]+", patched) if v.strip()])
#         # Convert lists to comma-separated strings
#         data["Products"] = {k: {"Affected": ",".join(sorted(set(v["Affected"]))),
#                                 "Patched": ",".join(sorted(set(v["Patched"])))}
#                             for k, v in products.items()}

#         return data
#     except Exception as e:
#         return {"error": str(e)}

# # ---------------------------
# # Parse advisory listing page
# # ---------------------------
# def parse_advisories(soup):
#     advisories = []
#     for row in soup.find_all("li", class_=re.compile(r"Box-row", re.I)):
#         try:
#             title_tag = row.find("a", class_=re.compile(r"Link--primary|link-primary", re.I)) or row.find("a", href=True)
#             if not title_tag: continue
#             link = urljoin(GITHUB_BASE, title_tag["href"])
#             ghsa_id = row.find("div", class_=re.compile(r"text-small", re.I))
#             ghsa_id = ghsa_id.get_text(" ", strip=True).split()[0] if ghsa_id else None
#             date_tag = row.find("relative-time")
#             date = date_tag["datetime"] if date_tag else None
#             severity = row.find("span", class_=re.compile(r"Label", re.I)).get_text(strip=True) if row.find("span", class_=re.compile(r"Label", re.I)) else None

#             advisories.append({
#                 "Title": title_tag.get_text(" ", strip=True),
#                 "Link": link,
#                 "GHSA_ID": ghsa_id,
#                 "Published_Date": date,
#                 "Severity": severity
#             })
#         except Exception:
#             continue
#     return advisories

# # ---------------------------
# # Fetch page
# # ---------------------------
# def fetch_page(page_num):
#     try:
#         resp = session.get(f"{BASE_URL}?state=published&page={page_num}", headers=HEADERS, timeout=15)
#         resp.raise_for_status()
#         return BeautifulSoup(resp.text, "html.parser")
#     except Exception:
#         return None

# # ---------------------------
# # Fetch all advisories
# # ---------------------------
# def fetch_all_advisories(pages_limit=None, delay=0.5):
#     all_advs, page_num = [], 1
#     while True:
#         soup = fetch_page(page_num)
#         if not soup: break
#         page_advs = parse_advisories(soup)
#         if not page_advs: break

#         print(f"Page {page_num}")
#         for adv in page_advs:
#             adv["CVE_Details"] = fetch_advisory_details(adv["Link"])
#             insert_advisory(adv["Link"], adv)
#             print(f"  --> inserted {adv.get('Link')}")
#             all_advs.append(adv)
#             time.sleep(delay)

#         page_num += 1
#         if pages_limit and page_num > pages_limit: break
#     return all_advs

# # ---------------------------
# # Main
# # ---------------------------
# if __name__ == "__main__":
#     create_table()
#     start = datetime.now(timezone.utc)
#     advisories = fetch_all_advisories(pages_limit=None, delay=0.75)
#     end = datetime.now(timezone.utc)
#     print(f"[Done] Total advisories stored: {len(advisories)} in {(end-start).total_seconds():.1f}s")


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
                if sib.name in ["h2", "h3"]:
                    break
                if sib.name == "p":
                    parts.append(sib.get_text(" ", strip=True))
                elif sib.name == "ul":
                    for li in sib.find_all("li"):
                        parts.append(li.get_text(" ", strip=True))
            return "\n".join(parts).strip() if parts else None
    return None

def get_links_section(soup, heading_text):
    for h in soup.find_all(["h2","h3"]):
        if heading_text.lower() in h.get_text(" ", strip=True).lower():
            links = []
            for sib in h.find_next_siblings():
                if sib.name in ["h2","h3"]:
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
# Extract Sidebar Data
# ---------------------------
# def extract_sidebar_data(soup):
#     sidebar_data = {}
#     for item in soup.select("div.discussion-sidebar-item"):
#         header = item.find("h3")
#         content = item.find("div", class_="color-fg-muted")
#         key = header.get_text(" ", strip=True) if header else None
#         value = content.get_text(" ", strip=True) if content else None
#         if key:
#             sidebar_data[key] = value
#     return sidebar_data
# ---------------------------
# Extract Sidebar Data (updated for CVE, CVSS, CWE)
# ---------------------------
def extract_sidebar_data(soup):
    sidebar_data = {}

    for item in soup.select("div.discussion-sidebar-item"):
        # Header/title
        header_tag = item.find("h3")
        key = header_tag.get_text(" ", strip=True) if header_tag else None

        # Initialize value
        value = None

        # 1. CVE ID
        if key and key.lower() == "cve id":
            cve_div = item.find("div", class_="color-fg-muted")
            if cve_div:
                value = cve_div.get_text(" ", strip=True)
                sidebar_data["CVE ID"] = value

        # 2. Severity / CVSS Score
        elif key and key.lower() == "severity":
            # CVSS Score from button
            score_btn = item.select_one("span.Button-label")
            if score_btn and re.match(r"^\d+(\.\d+)?$", score_btn.text.strip()):
                sidebar_data["CVSS Score"] = score_btn.text.strip()
            # CVSS Vector
            vector_tag = item.find(lambda t: t.name == "div" and t.get_text(strip=True).startswith("CVSS:"))
            if vector_tag:
                sidebar_data["CVSS Vector"] = vector_tag.get_text(strip=True)
            # Severity label fallback
            label_tag = item.select_one("span.Label")
            if label_tag:
                sidebar_data["Severity"] = label_tag.get_text(strip=True)

        # 3. Weaknesses / CWE IDs
        elif key and key.lower() == "weaknesses":
            cwe_list = []
            # Grab all CWE links
            for a_tag in item.select("a[href]"):
                if re.match(r"CWE-\d+", a_tag.text.strip()):
                    cwe_list.append(a_tag.text.strip())
            if cwe_list:
                sidebar_data["Weaknesses"] = ", ".join(cwe_list)

    return sidebar_data


# ---------------------------
# Fetch advisory details
# ---------------------------
def fetch_advisory_details(link):
    try:
        resp = session.get(link, headers=HEADERS, timeout=20)
        resp.raise_for_status()
        soup = BeautifulSoup(resp.text, "html.parser")
        data = {}

        # Sidebar Data
        data["Sidebar_Data"] = extract_sidebar_data(soup)

        # CVE ID fallback
        if "CVE ID" in data["Sidebar_Data"]:
            data["CVE_ID"] = data["Sidebar_Data"]["CVE ID"]
        else:
            m = re.search(r"(CVE-\d{4}-\d{4,7})", resp.text)
            data["CVE_ID"] = m.group(1) if m else None

        # CWEs
        data["CWEs"] = extract_cwes(soup)
        data["CWE_Data"] = extract_cwe_data(soup)

        # Patched, Description, Impact, Workarounds
        data["Patched"] = get_h3_section_text(soup, "Patches")
        data["Description"] = get_h3_section_text(soup, "description") or get_h3_section_text(soup, "impact")
        data["Impact"] = get_h3_section_text(soup, "impact")
        data["Workarounds"] = get_h3_section_text(soup, "workaround")

        # References / Other Links
        data["References"] = get_links_section(soup, "references")
        data["Other_Information_Links"] = get_links_section(soup, "other")

        # Products
        products = {}
        for box in soup.find_all("div", class_=re.compile(r"Box-body")):
            pkg_name_tag = box.find("span", class_=re.compile(r"f4 color-fg-default text-bold"))
            if not pkg_name_tag:
                continue
            pkg_name = pkg_name_tag.get_text(strip=True)
            affected_tag = box.find(lambda t: t.name in ["h2","h3"] and "Affected versions" in t.get_text())
            patched_tag = box.find(lambda t: t.name in ["h2","h3"] and "Patched versions" in t.get_text())
            affected = affected_tag.find_next_sibling().get_text(strip=True) if affected_tag and affected_tag.find_next_sibling() else ""
            patched = patched_tag.find_next_sibling().get_text(strip=True) if patched_tag and patched_tag.find_next_sibling() else ""
            if pkg_name not in products:
                products[pkg_name] = {"Affected": [], "Patched": []}
            products[pkg_name]["Affected"].extend([v.strip() for v in re.split(r"[,\[\]]+", affected) if v.strip()])
            products[pkg_name]["Patched"].extend([v.strip() for v in re.split(r"[,\[\]]+", patched) if v.strip()])
        # Convert lists to comma-separated strings
        data["Products"] = {k: {"Affected": ",".join(sorted(set(v["Affected"]))),
                                "Patched": ",".join(sorted(set(v["Patched"])))}
                            for k, v in products.items()}

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
