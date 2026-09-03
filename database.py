import sqlite3


def save_vulnerability(data):
    conn = sqlite3.connect("vulnerabilities.db")
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS vulnerabilities (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT,
            version TEXT,
            oem TEXT,
            severity TEXT,
            description TEXT,
            mitigation TEXT,
            patch_url TEXT,
            published_date TEXT,
            unique_id TEXT,
            source_url TEXT
        )
    """)

    cursor.execute("""
        INSERT INTO vulnerabilities
        (name, version, oem, severity, description, mitigation,
         patch_url, published_date, unique_id, source_url)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        data["name"],
        data["version"],
        data["oem"],
        data["severity"],
        data["description"],
        data["mitigation"],
        data["patch_url"],
        data["published_date"],
        data["unique_id"],
        data["source_url"]
    ))

    conn.commit()
    conn.close()

    print("[SAVED] Vulnerability stored in database.")


def get_vulnerabilities():
    conn = sqlite3.connect("vulnerabilities.db")
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM vulnerabilities")
    records = cursor.fetchall()

    conn.close()

    return records


if __name__ == "__main__":
    records = get_vulnerabilities()

    print("Saved records:")
    for record in records:
        print(record)
