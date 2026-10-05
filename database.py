import sqlite3


DATABASE_NAME = "fraudshield.db"


# =========================================================
# CREATE / UPGRADE DATABASE
# =========================================================

def create_database():

    conn = sqlite3.connect(DATABASE_NAME)
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scan_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT NOT NULL,
            score INTEGER NOT NULL,
            risk TEXT NOT NULL,
            scan_type TEXT DEFAULT 'URL',
            scan_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # -----------------------------------------------------
    # CHECK EXISTING COLUMNS
    # -----------------------------------------------------

    cursor.execute("""
        PRAGMA table_info(scan_history)
    """)

    columns = [
        column[1]
        for column in cursor.fetchall()
    ]

    # -----------------------------------------------------
    # ADD scan_type TO OLD DATABASE
    # -----------------------------------------------------

    if "scan_type" not in columns:

        cursor.execute("""
            ALTER TABLE scan_history
            ADD COLUMN scan_type TEXT DEFAULT 'URL'
        """)

    conn.commit()
    conn.close()


# =========================================================
# SAVE SCAN
# =========================================================

def save_scan(
    value,
    score,
    risk,
    scan_type="URL"
):

    conn = sqlite3.connect(DATABASE_NAME)
    cursor = conn.cursor()

    cursor.execute("""
        INSERT INTO scan_history
        (
            url,
            score,
            risk,
            scan_type
        )
        VALUES (?, ?, ?, ?)
    """, (
        value,
        score,
        risk,
        scan_type
    ))

    conn.commit()
    conn.close()


# =========================================================
# GET HISTORY
# =========================================================

def get_history():

    conn = sqlite3.connect(DATABASE_NAME)
    cursor = conn.cursor()

    cursor.execute("""
        SELECT
            url,
            score,
            risk,
            scan_type,
            scan_date
        FROM scan_history
        ORDER BY id DESC
    """)

    history = cursor.fetchall()

    conn.close()

    return history


# =========================================================
# CLEAR HISTORY
# =========================================================

def clear_history():

    conn = sqlite3.connect(DATABASE_NAME)
    cursor = conn.cursor()

    cursor.execute("""
        DELETE FROM scan_history
    """)

    conn.commit()
    conn.close()