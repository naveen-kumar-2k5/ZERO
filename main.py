import hashlib
import time
from datetime import datetime

import psycopg2
import requests

DB_CONFIG = {
    "dbname":   "zerorespong_db",
    "user":     "zero",
    "password": "Zero@post1122",
    "host":     "localhost",
    "port":     "5432",
}

API_URL       = "http://192.168.244.131:5000/api/v1/alerts"
POLL_INTERVAL = 60


def _dedup_hash(alert):
    parts = [
        str(alert.get("agent")       or ""),
        str(alert.get("description") or ""),
        str(alert.get("level")       or ""),
        str(alert.get("rule_id")     or ""),
        str(alert.get("source_ip")   or ""),
        str(alert.get("time")        or ""),
    ]
    return hashlib.md5("|".join(parts).encode("utf-8")).hexdigest()


def _parse_time(time_str):
    if not time_str:
        return None
    try:
        return datetime.fromisoformat(time_str.replace("Z", "+00:00"))
    except ValueError:
        return None


def fetch_and_store_alerts():
    try:
        resp = requests.get(API_URL, timeout=10)
        resp.raise_for_status()
        alerts = resp.json().get("data", [])
        if not alerts:
            return

        conn = psycopg2.connect(**DB_CONFIG)
        cur  = conn.cursor()

        insert_sql = """
            INSERT INTO alerts
                (agent, agent_ip, description, level, mitre_id, rule_id,
                 source_ip, target_user, threat_type, time, dedup_hash)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT (dedup_hash) DO NOTHING
        """

        inserted = 0
        skipped  = 0
        for a in alerts:
            cur.execute(insert_sql, (
                a.get("agent"),
                a.get("agent_ip"),
                a.get("description"),
                a.get("level"),
                a.get("mitre_id"),
                a.get("rule_id"),
                a.get("source_ip"),
                a.get("target_user"),
                a.get("threat_type"),
                _parse_time(a.get("time")),
                _dedup_hash(a),
            ))
            if cur.rowcount == 1:
                inserted += 1
            else:
                skipped += 1

        conn.commit()
        cur.close()
        conn.close()

        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print(f"[{ts}] poll: fetched={len(alerts)} inserted={inserted} skipped={skipped}")

    except requests.exceptions.RequestException as e:
        print(f"[{datetime.now():%Y-%m-%d %H:%M:%S}] fetch error: {e}")
    except Exception as e:
        print(f"[{datetime.now():%Y-%m-%d %H:%M:%S}] db error: {e}")


if __name__ == "__main__":
    print(f"Polling {API_URL} every {POLL_INTERVAL}s ...")
    try:
        while True:
            fetch_and_store_alerts()
            time.sleep(POLL_INTERVAL)
    except KeyboardInterrupt:
        print("\nstopped")