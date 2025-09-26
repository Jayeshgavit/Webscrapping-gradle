# #!/usr/bin/env python3
# # -*- coding: utf-8 -*-
# """
# Secure Gradle advisory normalizer.
# - Minimal logging
# - Only unprocessed rows are normalized
# - CWEs, References, Recommendations handled as per requirement
# - Description fallback to Impact if absent
# """

# import os
# import json
# import psycopg2
# from datetime import datetime
# from dotenv import load_dotenv
# import traceback

# # ------------------------- DB Config -------------------------
# load_dotenv()
# DB_CONFIG = {
#     "host": os.getenv("DB_HOST", "localhost"),
#     "dbname": os.getenv("DB_NAME", "Gradle"),
#     "user": os.getenv("DB_USER", "postgres"),
#     "password": os.getenv("DB_PASS", ""),
#     "port": int(os.getenv("DB_PORT", 5432)),
# }

# STAGING_TABLE = "staging_table"
# TABLE_VENDORS = "vendors"
# TABLE_ADVISORIES = "advisories"
# TABLE_CVES = "cves"
# TABLE_ADV_CVE_MAP = "advisory_cve_map"
# TABLE_CVE_PRODUCT_MAP = "cve_product_map"

# # ------------------------- DB Helpers -------------------------
# def get_connection():
#     return psycopg2.connect(**DB_CONFIG)

# def ensure_tables():
#     cmds = [
#         f"""CREATE TABLE IF NOT EXISTS {TABLE_VENDORS} (
#                 vendor_id SERIAL PRIMARY KEY,
#                 vendor_name TEXT NOT NULL UNIQUE
#             );""",
#         f"""CREATE TABLE IF NOT EXISTS {TABLE_ADVISORIES} (
#                 advisory_id TEXT PRIMARY KEY,
#                 vendor_id INTEGER REFERENCES {TABLE_VENDORS}(vendor_id),
#                 title TEXT,
#                 severity TEXT,
#                 initial_release_date DATE,
#                 latest_update_date DATE,
#                 advisory_url TEXT
#             );""",
#         f"""CREATE TABLE IF NOT EXISTS {TABLE_CVES} (
#                 cve_id TEXT PRIMARY KEY,
#                 cwe_id TEXT,
#                 description TEXT,
#                 severity TEXT,
#                 cvss_score NUMERIC(3,1),
#                 cvss_vector TEXT,
#                 initial_release_date DATE,
#                 latest_update_date DATE,
#                 reference_url TEXT
#             );""",
#         f"""CREATE TABLE IF NOT EXISTS {TABLE_ADV_CVE_MAP} (
#                 advisory_id TEXT REFERENCES {TABLE_ADVISORIES}(advisory_id) ON DELETE CASCADE,
#                 cve_id TEXT REFERENCES {TABLE_CVES}(cve_id) ON DELETE CASCADE,
#                 PRIMARY KEY (advisory_id, cve_id)
#             );""",
#         f"""CREATE TABLE IF NOT EXISTS {TABLE_CVE_PRODUCT_MAP} (
#                 qs_id SERIAL NOT NULL UNIQUE,
#                 cve_id TEXT PRIMARY KEY REFERENCES {TABLE_CVES}(cve_id) ON DELETE CASCADE,
#                 affected_products_cpe JSONB,
#                 recommendations TEXT
#             );""",
#         f"CREATE INDEX IF NOT EXISTS idx_cpe_gin ON {TABLE_CVE_PRODUCT_MAP} USING GIN (affected_products_cpe);"
#     ]
#     with get_connection() as conn, conn.cursor() as cur:
#         for c in cmds:
#             cur.execute(c)
#         conn.commit()

# # ------------------------- Utilities -------------------------
# def clean_text(txt):
#     if txt is None:
#         return None
#     return str(txt).strip()

# def parse_date(d):
#     if not d:
#         return None
#     try:
#         return datetime.strptime(d[:10], "%Y-%m-%d").date()
#     except:
#         return None

# def next_advisory_id(created_at, last_id_num):
#     return f"GRD-{created_at.strftime('%Y%m%d')}-{last_id_num+1:03d}"

# def get_last_advisory_number_for_date(cur, created_at):
#     cur.execute(f"""
#         SELECT advisory_id FROM {TABLE_ADVISORIES}
#         WHERE initial_release_date=%s
#         ORDER BY advisory_id DESC LIMIT 1
#     """, (created_at,))
#     row = cur.fetchone()
#     if not row:
#         return 0
#     try:
#         return int(row[0].split("-")[-1])
#     except:
#         return 0

# def get_or_create_vendor_id(cur, vendor_name):
#     cur.execute("SELECT vendor_id FROM vendors WHERE vendor_name=%s", (vendor_name,))
#     r = cur.fetchone()
#     if r:
#         return r[0]
#     cur.execute("INSERT INTO vendors (vendor_name) VALUES (%s) ON CONFLICT (vendor_name) DO NOTHING RETURNING vendor_id", (vendor_name,))
#     r = cur.fetchone()
#     if r:
#         return r[0]
#     cur.execute("SELECT vendor_id FROM vendors WHERE vendor_name=%s", (vendor_name,))
#     return cur.fetchone()[0]

# # ------------------------- Row Processing -------------------------
# def process_staging_row(cur, staging_id, raw_json):
#     try:
#         data = json.loads(raw_json) if isinstance(raw_json, str) else raw_json
#         cve_details = data.get("CVE_Details") or {}

#         created_at = parse_date(data.get("Published_Date")) or datetime.today().date()
#         title = clean_text(data.get("Title"))
#         advisory_url = data.get("Link")
#         last_id_num = get_last_advisory_number_for_date(cur, created_at)
#         advisory_id = next_advisory_id(created_at, last_id_num)
#         vendor_id = get_or_create_vendor_id(cur, "Gradle")

#         # Advisory severity
#         adv_severity = data.get("Severity") or cve_details.get("Severity")
#         if not adv_severity:
#             adv_severity = None

#         # Insert Advisory
#         cur.execute(f"""
#             INSERT INTO {TABLE_ADVISORIES} 
#             (advisory_id, vendor_id, title, severity, initial_release_date, advisory_url)
#             VALUES (%s, %s, %s, %s, %s, %s)
#             ON CONFLICT (advisory_id) DO NOTHING
#         """, (advisory_id, vendor_id, title, adv_severity, created_at, advisory_url))

#         # CWE list
#         cwe_list = cve_details.get("CWEs") or []
#         cwe_id = ",".join(cwe_list) if cwe_list else None

#         # References
#         references = [r.get("href") for r in cve_details.get("References", []) if r.get("href")]
#         references_str = ",".join(references) if references else None

#         # Recommendations
#         recommendations = cve_details.get("Patched") or cve_details.get("Workarounds")

#         # Description fallback to Impact
#         description = cve_details.get("Description") or cve_details.get("Impact")

#         # CVSS
#         sidebar = cve_details.get("Sidebar_Data") or {}
#         cvss_score = float(sidebar.get("CVSS Score")) if sidebar.get("CVSS Score") else None
#         cvss_vector = sidebar.get("CVSS Vector")

#         cve_id = cve_details.get("CVE_ID")
#         if cve_id:
#             # Insert CVE
#             cur.execute(f"""
#                 INSERT INTO {TABLE_CVES}
#                 (cve_id, cwe_id, description, severity, cvss_score, cvss_vector, reference_url)
#                 VALUES (%s,%s,%s,%s,%s,%s,%s)
#                 ON CONFLICT (cve_id) DO NOTHING
#             """, (cve_id, cwe_id, description, cve_details.get("Severity") or sidebar.get("Severity"), cvss_score, cvss_vector, references_str))

#             # Map advisory <-> CVE
#             cur.execute(f"""
#                 INSERT INTO {TABLE_ADV_CVE_MAP} (advisory_id, cve_id)
#                 VALUES (%s, %s)
#                 ON CONFLICT DO NOTHING
#             """, (advisory_id, cve_id))

#             # Product map
#             cur.execute(f"""
#                 INSERT INTO {TABLE_CVE_PRODUCT_MAP} (cve_id, affected_products_cpe, recommendations)
#                 VALUES (%s,%s,%s)
#                 ON CONFLICT (cve_id) DO UPDATE
#                 SET affected_products_cpe=NULL,
#                     recommendations=EXCLUDED.recommendations
#             """, (cve_id, None, recommendations))

#         # Mark staging as processed
#         cur.execute(f"UPDATE {STAGING_TABLE} SET processed=true WHERE staging_id=%s", (staging_id,))

#         print(f"✔ Normalized staging_id={staging_id} -> advisory_id={advisory_id}")
#         return True

#     except Exception as e:
#         print(f"✘ Failed staging_id={staging_id}: {e}")
#         return False

# # ------------------------- Main Normalization -------------------------
# def normalize_gradle():
#     ensure_tables()
#     with get_connection() as conn, conn.cursor() as cur:
#         cur.execute(f"""
#             SELECT staging_id, raw_data 
#             FROM {STAGING_TABLE} 
#             WHERE vendor_name='Gradle' AND processed=false
#             ORDER BY staging_id
#         """)
#         rows = cur.fetchall()
#         if not rows:
#             print("No data to normalize.")
#             return

#         total = len(rows)
#         print(f"Found {total} unprocessed Gradle rows.")

#         normalized_count = 0
#         for idx, (staging_id, raw_json) in enumerate(rows, start=1):
#             success = process_staging_row(cur, staging_id, raw_json)
#             if success:
#                 normalized_count += 1
#             conn.commit()

#         print(f"Done. Normalized {normalized_count}/{total} rows.")

# # ------------------------- Entrypoint -------------------------
# if __name__ == "__main__":
#     normalize_gradle()




#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Secure Gradle advisory normalizer.
- Minimal logging
- Only unprocessed rows are normalized
- CWEs, References, Recommendations handled as per requirement
- Description fallback to Impact if absent
"""

import os
import json
import psycopg2
from datetime import datetime
from dotenv import load_dotenv
import traceback

# ------------------------- DB Config -------------------------
load_dotenv()
DB_CONFIG = {
    "host": os.getenv("DB_HOST", "localhost"),
    "dbname": os.getenv("DB_NAME", "Gradle"),
    "user": os.getenv("DB_USER", "postgres"),
    "password": os.getenv("DB_PASS", ""),
    "port": int(os.getenv("DB_PORT", 5432)),
}

STAGING_TABLE = "staging_table"
TABLE_VENDORS = "vendors"
TABLE_ADVISORIES = "advisories"
TABLE_CVES = "cves"
TABLE_ADV_CVE_MAP = "advisory_cve_map"
TABLE_CVE_PRODUCT_MAP = "cve_product_map"

# ------------------------- DB Helpers -------------------------
def get_connection():
    return psycopg2.connect(**DB_CONFIG)

def ensure_tables():
    cmds = [
        f"""CREATE TABLE IF NOT EXISTS {TABLE_VENDORS} (
                vendor_id SERIAL PRIMARY KEY,
                vendor_name TEXT NOT NULL UNIQUE
            );""",
        f"""CREATE TABLE IF NOT EXISTS {TABLE_ADVISORIES} (
                advisory_id TEXT PRIMARY KEY,
                vendor_id INTEGER REFERENCES {TABLE_VENDORS}(vendor_id),
                title TEXT,
                severity TEXT,
                initial_release_date DATE,
                latest_update_date DATE,
                advisory_url TEXT
            );""",
        f"""CREATE TABLE IF NOT EXISTS {TABLE_CVES} (
                cve_id TEXT PRIMARY KEY,
                cwe_id TEXT,
                description TEXT,
                severity TEXT,
                cvss_score NUMERIC(3,1),
                cvss_vector TEXT,
                initial_release_date DATE,
                latest_update_date DATE,
                reference_url TEXT
            );""",
        f"""CREATE TABLE IF NOT EXISTS {TABLE_ADV_CVE_MAP} (
                advisory_id TEXT REFERENCES {TABLE_ADVISORIES}(advisory_id) ON DELETE CASCADE,
                cve_id TEXT REFERENCES {TABLE_CVES}(cve_id) ON DELETE CASCADE,
                PRIMARY KEY (advisory_id, cve_id)
            );""",
        f"""CREATE TABLE IF NOT EXISTS {TABLE_CVE_PRODUCT_MAP} (
                qs_id SERIAL NOT NULL UNIQUE,
                cve_id TEXT PRIMARY KEY REFERENCES {TABLE_CVES}(cve_id) ON DELETE CASCADE,
                affected_products_cpe JSONB,
                recommendations TEXT
            );""",
        f"CREATE INDEX IF NOT EXISTS idx_cpe_gin ON {TABLE_CVE_PRODUCT_MAP} USING GIN (affected_products_cpe);"
    ]
    with get_connection() as conn, conn.cursor() as cur:
        for c in cmds:
            cur.execute(c)
        conn.commit()

# ------------------------- Utilities -------------------------
def clean_text(txt):
    if txt is None:
        return None
    return str(txt).strip()

def parse_date(d):
    if not d:
        return None
    try:
        return datetime.strptime(d[:10], "%Y-%m-%d").date()
    except:
        return None

def next_advisory_id(created_at, last_id_num):
    return f"GRD-{created_at.strftime('%Y%m%d')}-{last_id_num+1:03d}"

def get_last_advisory_number_for_date(cur, created_at):
    cur.execute(f"""
        SELECT advisory_id FROM {TABLE_ADVISORIES}
        WHERE initial_release_date=%s
        ORDER BY advisory_id DESC LIMIT 1
    """, (created_at,))
    row = cur.fetchone()
    if not row:
        return 0
    try:
        return int(row[0].split("-")[-1])
    except:
        return 0

def get_or_create_vendor_id(cur, vendor_name):
    cur.execute("SELECT vendor_id FROM vendors WHERE vendor_name=%s", (vendor_name,))
    r = cur.fetchone()
    if r:
        return r[0]
    cur.execute("INSERT INTO vendors (vendor_name) VALUES (%s) ON CONFLICT (vendor_name) DO NOTHING RETURNING vendor_id", (vendor_name,))
    r = cur.fetchone()
    if r:
        return r[0]
    cur.execute("SELECT vendor_id FROM vendors WHERE vendor_name=%s", (vendor_name,))
    return cur.fetchone()[0]

# ------------------------- Row Processing -------------------------
def process_staging_row(cur, staging_id, raw_json):
    try:
        data = json.loads(raw_json) if isinstance(raw_json, str) else raw_json
        cve_details = data.get("CVE_Details") or {}

        created_at = parse_date(data.get("Published_Date")) or datetime.today().date()
        title = clean_text(data.get("Title"))
        advisory_url = data.get("Link")
        last_id_num = get_last_advisory_number_for_date(cur, created_at)
        advisory_id = next_advisory_id(created_at, last_id_num)
        vendor_id = get_or_create_vendor_id(cur, "Gradle")

        # ------------------------- Insert Advisory with severity NULL -------------------------
        cur.execute(f"""
            INSERT INTO {TABLE_ADVISORIES} 
            (advisory_id, vendor_id, title, severity, initial_release_date, advisory_url)
            VALUES (%s, %s, %s, NULL, %s, %s)
            ON CONFLICT (advisory_id) DO NOTHING
        """, (advisory_id, vendor_id, title, created_at, advisory_url))

        # CWE list
        cwe_list = cve_details.get("CWEs") or []
        cwe_id = ",".join(cwe_list) if cwe_list else None

        # References
        references = [r.get("href") for r in cve_details.get("References", []) if r.get("href")]
        references_str = ",".join(references) if references else None

        # Recommendations
        recommendations = cve_details.get("Patched") or cve_details.get("Workarounds")

        # Description fallback to Impact
        description = cve_details.get("Description") or cve_details.get("Impact")

        # CVSS
        sidebar = cve_details.get("Sidebar_Data") or {}
        cvss_score = float(sidebar.get("CVSS Score")) if sidebar.get("CVSS Score") else None
        cvss_vector = sidebar.get("CVSS Vector")

        cve_id = cve_details.get("CVE_ID")
        if cve_id:
            # Insert CVE
            cur.execute(f"""
                INSERT INTO {TABLE_CVES}
                (cve_id, cwe_id, description, severity, cvss_score, cvss_vector, reference_url)
                VALUES (%s,%s,%s,%s,%s,%s,%s)
                ON CONFLICT (cve_id) DO NOTHING
            """, (cve_id, cwe_id, description, cve_details.get("Severity") or sidebar.get("Severity"), cvss_score, cvss_vector, references_str))

            # Map advisory <-> CVE
            cur.execute(f"""
                INSERT INTO {TABLE_ADV_CVE_MAP} (advisory_id, cve_id)
                VALUES (%s, %s)
                ON CONFLICT DO NOTHING
            """, (advisory_id, cve_id))

            # Product map
            cur.execute(f"""
                INSERT INTO {TABLE_CVE_PRODUCT_MAP} (cve_id, affected_products_cpe, recommendations)
                VALUES (%s,%s,%s)
                ON CONFLICT (cve_id) DO UPDATE
                SET affected_products_cpe=NULL,
                    recommendations=EXCLUDED.recommendations
            """, (cve_id, None, recommendations))

        # Mark staging as processed
        cur.execute(f"UPDATE {STAGING_TABLE} SET processed=true WHERE staging_id=%s", (staging_id,))

        print(f"✔ Normalized staging_id={staging_id} -> advisory_id={advisory_id}")
        return True

    except Exception as e:
        print(f"✘ Failed staging_id={staging_id}: {e}")
        traceback.print_exc()
        return False

# ------------------------- Main Normalization -------------------------
def normalize_gradle():
    ensure_tables()
    with get_connection() as conn, conn.cursor() as cur:
        cur.execute(f"""
            SELECT staging_id, raw_data 
            FROM {STAGING_TABLE} 
            WHERE vendor_name='Gradle' AND processed=false
            ORDER BY staging_id
        """)
        rows = cur.fetchall()
        if not rows:
            print("No data to normalize.")
            return

        total = len(rows)
        print(f"Found {total} unprocessed Gradle rows.")

        normalized_count = 0
        for idx, (staging_id, raw_json) in enumerate(rows, start=1):
            success = process_staging_row(cur, staging_id, raw_json)
            if success:
                normalized_count += 1
            conn.commit()

        print(f"Done. Normalized {normalized_count}/{total} rows.")

# ------------------------- Entrypoint -------------------------
if __name__ == "__main__":
    normalize_gradle()
