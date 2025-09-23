#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import json
import psycopg2
from datetime import datetime
from dotenv import load_dotenv

# -------------------------
# Load DB config
# -------------------------
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

# -------------------------
# DB helpers
# -------------------------
def get_connection():
    return psycopg2.connect(**DB_CONFIG)

def ensure_tables():
    commands = [
        f"""
        CREATE TABLE IF NOT EXISTS {TABLE_VENDORS} (
            vendor_id SERIAL PRIMARY KEY,
            vendor_name TEXT NOT NULL UNIQUE
        );
        """,
        f"""
        CREATE TABLE IF NOT EXISTS {TABLE_ADVISORIES} (
            advisory_id TEXT PRIMARY KEY,
            vendor_id INTEGER REFERENCES {TABLE_VENDORS}(vendor_id),
            title TEXT,
            severity TEXT,
            initial_release_date DATE,
            latest_update_date DATE,
            advisory_url TEXT
        );
        """,
        f"""
        CREATE TABLE IF NOT EXISTS {TABLE_CVES} (
            cve_id TEXT PRIMARY KEY,
            cwe_id TEXT,
            description TEXT,
            severity TEXT,
            cvss_score NUMERIC(3,1),
            cvss_vector TEXT,
            initial_release_date DATE,
            latest_update_date DATE,
            reference_url TEXT
        );
        """,
        f"""
        CREATE TABLE IF NOT EXISTS {TABLE_ADV_CVE_MAP} (
            advisory_id TEXT REFERENCES {TABLE_ADVISORIES}(advisory_id) ON DELETE CASCADE,
            cve_id TEXT REFERENCES {TABLE_CVES}(cve_id) ON DELETE CASCADE,
            PRIMARY KEY (advisory_id, cve_id)
        );
        """,
        f"""
        CREATE TABLE IF NOT EXISTS {TABLE_CVE_PRODUCT_MAP} (
            qs_id SERIAL NOT NULL UNIQUE,
            cve_id TEXT PRIMARY KEY REFERENCES {TABLE_CVES}(cve_id) ON DELETE CASCADE,
            affected_products_cpe JSONB,
            recommendations TEXT
        );
        """,
        f"CREATE INDEX IF NOT EXISTS idx_cpe_gin ON {TABLE_CVE_PRODUCT_MAP} USING GIN (affected_products_cpe);"
    ]
    with get_connection() as conn, conn.cursor() as cur:
        for cmd in commands:
            cur.execute(cmd)
        conn.commit()
    print("📦 All tables ensured to exist.")

# -------------------------
# Utility functions
# -------------------------
def clean_text(txt):
    if not txt:
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
    last_id = row[0].split("-")[-1]
    return int(last_id)

# -------------------------
# Main normalization
# -------------------------
def normalize_gradle():
    with get_connection() as conn, conn.cursor() as cur:
        # Ensure vendor exists
        cur.execute(
            f"INSERT INTO {TABLE_VENDORS} (vendor_name) VALUES (%s) "
            f"ON CONFLICT (vendor_name) DO NOTHING RETURNING vendor_id",
            ("Gradle",)
        )
        vendor_id = cur.fetchone()
        if not vendor_id:
            cur.execute(f"SELECT vendor_id FROM {TABLE_VENDORS} WHERE vendor_name=%s", ("Gradle",))
            vendor_id = cur.fetchone()
        vendor_id = vendor_id[0]

        # Fetch unprocessed staging rows
        cur.execute(f"""
            SELECT staging_id, raw_data 
            FROM {STAGING_TABLE} 
            WHERE vendor_name='Gradle' AND processed=false 
            ORDER BY staging_id
        """)
        rows = cur.fetchall()
        normalized_count = 0
        for staging_id, raw_json in rows:
            try:
                data = json.loads(raw_json) if isinstance(raw_json, str) else raw_json
                cve_details = data.get("CVE_Details") or {}

                created_at = parse_date(data.get("Published_Date")) or datetime.today().date()
                title = clean_text(data.get("Title"))
                advisory_url = data.get("Link")

                last_id_num = get_last_advisory_number_for_date(cur, created_at)
                advisory_id = next_advisory_id(created_at, last_id_num)

                # Insert advisory
                cur.execute(f"""
                    INSERT INTO {TABLE_ADVISORIES} 
                    (advisory_id, vendor_id, title, severity, initial_release_date, advisory_url)
                    VALUES (%s, %s, %s, %s, %s, %s)
                    ON CONFLICT (advisory_id) DO NOTHING
                """, (
                    advisory_id, vendor_id, title,
                    data.get("Severity") or cve_details.get("Severity"),
                    created_at, advisory_url
                ))

                # --- Prepare CWE IDs ---
                cwe_list = cve_details.get("CWEs") or []
                cwe_id = ",".join(cwe_list) if cwe_list else None

                # --- References (links only) ---
                references = [r.get("href") for r in cve_details.get("References", []) if r.get("href")]
                references_str = ",".join(references) if references else None

                # --- Recommendations (Patched > Workarounds) ---
                recommendations = None
                if cve_details.get("Patched"):
                    recommendations = cve_details.get("Patched")
                elif cve_details.get("Workarounds"):
                    recommendations = cve_details.get("Workarounds")

                # Insert CVE
                cve_id = cve_details.get("CVE_ID")
                cur.execute(f"""
                    INSERT INTO {TABLE_CVES} 
                    (cve_id, cwe_id, description, severity, cvss_score, cvss_vector, reference_url)
                    VALUES (%s,%s,%s,%s,%s,%s,%s)
                    ON CONFLICT (cve_id) DO NOTHING
                """, (
                    cve_id,
                    cwe_id,
                    cve_details.get("Description"),   # ✅ only description
                    cve_details.get("Severity") or cve_details.get("Sidebar_Data", {}).get("Severity"),
                    float(cve_details.get("Sidebar_Data", {}).get("CVSS Score")) if cve_details.get("Sidebar_Data", {}).get("CVSS Score") else None,
                    cve_details.get("Sidebar_Data", {}).get("CVSS Vector"),
                    references_str
                ))

                # Map advisory <-> CVE
                if cve_id:
                    cur.execute(f"""
                        INSERT INTO {TABLE_ADV_CVE_MAP} (advisory_id, cve_id)
                        VALUES (%s, %s)
                        ON CONFLICT DO NOTHING
                    """, (advisory_id, cve_id))

                # Products always NULL, recommendations handled
                cur.execute(f"""
                    INSERT INTO {TABLE_CVE_PRODUCT_MAP} (cve_id, affected_products_cpe, recommendations)
                    VALUES (%s,%s,%s)
                    ON CONFLICT (cve_id) DO UPDATE
                    SET affected_products_cpe=NULL,
                        recommendations=EXCLUDED.recommendations
                """, (
                    cve_id,
                    None,
                    recommendations
                ))

                # Mark staging processed
                cur.execute(f"""
                    UPDATE {STAGING_TABLE} SET processed=true WHERE staging_id=%s
                """, (staging_id,))

                normalized_count += 1
            except Exception as e:
                print(f"[ERROR] staging_id={staging_id}: {e}")

        conn.commit()
        print(f"✅ Normalized {normalized_count} Gradle advisories.")

# -------------------------
# Main
# -------------------------
if __name__ == "__main__":
    ensure_tables()
    normalize_gradle()
