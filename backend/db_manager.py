# ==============================================================================
# Author: Created with love by Chiranjib and Team
# Description: Database Manager & SQLite Connection Handler
# ==============================================================================
import sqlite3
import os

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
DB_DIR = os.path.join(ROOT_DIR, "data")
DB_PATH = os.path.join(DB_DIR, "cve_database.db")

def get_db_connection():
    if not os.path.exists(DB_DIR):
        os.makedirs(DB_DIR, exist_ok=True)
    conn = sqlite3.connect(DB_PATH, timeout=60.0)
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA busy_timeout=60000;")
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS cve_main (
            cve_id TEXT PRIMARY KEY,
            published_date DATETIME,
            updated_date DATETIME,
            cvss_v3_score REAL,
            cvss_vector TEXT,
            epss_score REAL DEFAULT NULL,
            severity TEXT,
            cwe TEXT,
            affected_vendor TEXT,
            affected_product TEXT,
            is_cisa_kev BOOLEAN DEFAULT 0,
            has_public_poc BOOLEAN DEFAULT 0,
            has_nuclei BOOLEAN DEFAULT 0,
            has_metasploit BOOLEAN DEFAULT 0,
            has_exploitdb BOOLEAN DEFAULT 0,
            osint_mention_count INTEGER DEFAULT 0,
            is_exploited_in_wild BOOLEAN DEFAULT 0,
            is_iot_ot BOOLEAN DEFAULT 0,
            device_type TEXT,
            ics_cert_id TEXT
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS cve_sources (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            cve_id TEXT,
            source_name TEXT,
            url TEXT,
            is_poc_link BOOLEAN DEFAULT 0,
            details TEXT,
            exploit_status TEXT,
            FOREIGN KEY (cve_id) REFERENCES cve_main(cve_id)
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS cve_analysis (
            cve_id TEXT PRIMARY KEY,
            ai_summary TEXT,
            recommended_action TEXT,
            poc_recreation_steps TEXT,
            keywords TEXT,
            is_analyzed BOOLEAN DEFAULT 0,
            FOREIGN KEY (cve_id) REFERENCES cve_main(cve_id)
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS cve_iocs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            cve_id TEXT,
            ioc_type TEXT,
            ioc_value TEXT,
            threat_actor TEXT,
            malware_family TEXT,
            source_feed TEXT,
            confidence INTEGER DEFAULT 80,
            first_seen DATETIME,
            details TEXT,
            FOREIGN KEY (cve_id) REFERENCES cve_main(cve_id)
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS system_state (
            task_name TEXT PRIMARY KEY,
            timestamp DATETIME
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS owned_assets (
            asset_id INTEGER PRIMARY KEY AUTOINCREMENT,
            asset_name TEXT NOT NULL,
            asset_type TEXT NOT NULL,
            vendor TEXT NOT NULL,
            product TEXT NOT NULL,
            version TEXT,
            cpe TEXT,
            ip_address TEXT,
            domain_name TEXT,
            criticality TEXT DEFAULT 'High',
            owner_department TEXT,
            notes TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS asset_cve_matches (
            match_id INTEGER PRIMARY KEY AUTOINCREMENT,
            asset_id INTEGER NOT NULL,
            cve_id TEXT NOT NULL,
            match_type TEXT NOT NULL,
            is_mitigated BOOLEAN DEFAULT 0,
            mitigation_notes TEXT,
            matched_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (asset_id) REFERENCES owned_assets(asset_id),
            FOREIGN KEY (cve_id) REFERENCES cve_main(cve_id)
        )
    ''')

    # Migration for cve_main additional columns if upgrading
    cursor.execute("PRAGMA table_info(cve_main);")
    existing_cols = [row["name"] for row in cursor.fetchall()]
    new_cols = [
        ("ransomware_campaign", "TEXT"),
        ("cisa_date_added", "TEXT"),
        ("cisa_due_date", "TEXT"),
        ("cisa_required_action", "TEXT"),
        ("mitre_attack_id", "TEXT"),
        ("osint_sources", "TEXT")
    ]
    for col_name, col_type in new_cols:
        if col_name not in existing_cols:
            try:
                cursor.execute(f"ALTER TABLE cve_main ADD COLUMN {col_name} {col_type};")
            except Exception:
                pass

    # Migration for cve_sources depth tracking
    cursor.execute("PRAGMA table_info(cve_sources);")
    existing_src_cols = [row["name"] for row in cursor.fetchall()]
    src_new_cols = [
        ("depth_level", "INTEGER DEFAULT 0"),
        ("parent_source_id", "INTEGER")
    ]
    for col_name, col_type in src_new_cols:
        if col_name not in existing_src_cols:
            try:
                cursor.execute(f"ALTER TABLE cve_sources ADD COLUMN {col_name} {col_type};")
            except Exception:
                pass

    # Create High-Performance Indexes
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_sources_cve ON cve_sources(cve_id);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_sources_url ON cve_sources(url);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_iocs_cve ON cve_iocs(cve_id);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_main_pubdate ON cve_main(published_date);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_main_cisa ON cve_main(is_cisa_kev);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_main_severity ON cve_main(severity);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_analysis_analyzed ON cve_analysis(is_analyzed);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_assets_vendor_prod ON owned_assets(vendor, product);")

    conn.commit()
    conn.close()

if __name__ == "__main__":
    init_db()
