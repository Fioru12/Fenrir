import sqlite3
import os
from typing import Dict, Any, List

class FenrirDatabase:
    """
    SQLite storage for aggregated Threat Intelligence IOCs.
    """

    def __init__(self, db_path: str = "fenrir.db"):
        self.db_path = db_path
        self._init_db()

    def _init_db(self):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS iocs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                indicator_type TEXT,
                indicator TEXT UNIQUE,
                name TEXT,
                source TEXT,
                severity TEXT,
                date_added TEXT
            )
        """)
        conn.commit()
        conn.close()

    def save_iocs(self, iocs: List[Dict[str, Any]]) -> int:
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        count = 0
        for ioc in iocs:
            try:
                cursor.execute("""
                    INSERT OR IGNORE INTO iocs (indicator_type, indicator, name, source, severity, date_added)
                    VALUES (?, ?, ?, ?, ?, ?)
                """, (
                    ioc.get("indicator_type"),
                    ioc.get("indicator"),
                    ioc.get("name"),
                    ioc.get("source"),
                    ioc.get("severity"),
                    ioc.get("date_added")
                ))
                if cursor.rowcount > 0:
                    count += 1
            except Exception:
                pass
        conn.commit()
        conn.close()
        return count

    def search_ioc(self, query: str) -> List[Dict[str, Any]]:
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("""
            SELECT indicator_type, indicator, name, source, severity, date_added
            FROM iocs WHERE indicator LIKE ? OR name LIKE ?
        """, (f"%{query}%", f"%{query}%"))
        rows = cursor.fetchall()
        conn.close()

        results = []
        for r in rows:
            results.append({
                "indicator_type": r[0],
                "indicator": r[1],
                "name": r[2],
                "source": r[3],
                "severity": r[4],
                "date_added": r[5]
            })
        return results

    def get_stats(self) -> Dict[str, Any]:
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM iocs")
        total = cursor.fetchone()[0]
        conn.close()
        return {"total_iocs": total}
