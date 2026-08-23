from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import sqlite3
import datetime
import random
import os
import asyncio

from data_fetcher import VENDORS, VULNERABILITIES

# ── Scan engine configuration ────────────────────────────────────────────────
SCAN_INTERVAL_SECONDS = 30
RESOLVE_FRACTION = 0.30
NEW_VULN_FRACTION = 0.20

# ── Per-device probe question probabilities ──────────────────────────────────
STATUS_CHANGE_CHANCE = 0.05
FIRMWARE_PATCH_CHANCE = 0.30
CONFIG_CHANGE_CHANCE = 0.12
SUSPICIOUS_BEHAVIOR_CHANCE = 0.10

app = FastAPI(
    title="Municipal IoT Scanner API",
    description="Authorized backend API for Municipal IoT Asset Inventory & Vulnerability Auditing.",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

DB_NAME = "municipal_iot.db"


def ensure_tables(conn):
    conn.execute("""
    CREATE TABLE IF NOT EXISTS scan_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        scan_time TEXT NOT NULL,
        devices_scanned INTEGER NOT NULL,
        telemetry_updates INTEGER NOT NULL,
        vulnerabilities_resolved INTEGER NOT NULL,
        new_vulnerabilities_found INTEGER NOT NULL
    )
    """)
    conn.execute("""
    CREATE TABLE IF NOT EXISTS device_probe_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        scan_id INTEGER NOT NULL,
        asset_id TEXT NOT NULL,
        still_online_response TEXT NOT NULL,
        reported_firmware TEXT NOT NULL,
        config_changed INTEGER NOT NULL,
        suspicious_behavior INTEGER NOT NULL,
        outcome TEXT NOT NULL,
        FOREIGN KEY (scan_id) REFERENCES scan_log(id) ON DELETE CASCADE,
        FOREIGN KEY (asset_id) REFERENCES assets(id) ON DELETE CASCADE
    )
    """)
    conn.commit()


def bump_firmware(fw: str) -> str:
    try:
        core = fw.lstrip("v")
        major, minor, patch = (int(x) for x in core.split("."))
        patch += 1
        if patch > 9:
            patch = 0
            minor += 1
        return f"v{major}.{minor}.{patch}"
    except Exception:
        return fw


def get_eligible_vulns(asset_type: str, vendor: str):
    for profile in VENDORS.get(asset_type, []):
        if profile["vendor"] == vendor:
            return profile["vulns"]
    return []


def send_probe_requests(current_status: str, current_firmware: str, is_vulnerable: bool) -> dict:
    if random.random() < STATUS_CHANGE_CHANCE:
        still_online_response = random.choice(["Online", "Offline", "Maintenance"])
    else:
        still_online_response = current_status

    firmware_patched = False
    reported_firmware = current_firmware
    if is_vulnerable and random.random() < FIRMWARE_PATCH_CHANCE:
        reported_firmware = bump_firmware(current_firmware)
        firmware_patched = True

    config_changed = (not is_vulnerable) and random.random() < CONFIG_CHANGE_CHANCE
    suspicious_behavior = (not is_vulnerable) and random.random() < SUSPICIOUS_BEHAVIOR_CHANCE

    return {
        "still_online_response": still_online_response,
        "reported_firmware": reported_firmware,
        "firmware_patched": firmware_patched,
        "config_changed": config_changed,
        "suspicious_behavior": suspicious_behavior,
    }


def run_scan_sweep(conn) -> dict:
    cursor = conn.cursor()
    now_str = datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")

    cursor.execute("""
        INSERT INTO scan_log (scan_time, devices_scanned, telemetry_updates, vulnerabilities_resolved, new_vulnerabilities_found)
        VALUES (?, 0, 0, 0, 0)
    """, (now_str,))
    scan_id = cursor.lastrowid

    cursor.execute("""
        SELECT a.id as asset_id, a.type, d.vendor, d.status, d.firmware_version,
               EXISTS(
                   SELECT 1 FROM device_vulnerabilities dv
                   WHERE dv.asset_id = a.id AND dv.status = 'Active'
               ) as is_vulnerable
        FROM assets a
        JOIN device_details d ON a.id = d.asset_id
        WHERE d.is_isolated = 0
    """)
    devices = cursor.fetchall()

    telemetry_updates = 0
    vulnerabilities_resolved = 0
    new_vulnerabilities_found = 0

    for device in devices:
        asset_id = device["asset_id"]
        is_vulnerable = bool(device["is_vulnerable"])

        probe = send_probe_requests(device["status"], device["firmware_version"], is_vulnerable)
        outcome = "no_change"

        if probe["still_online_response"] != device["status"]:
            cursor.execute(
                "UPDATE device_details SET status = ? WHERE asset_id = ?",
                (probe["still_online_response"], asset_id)
            )
            telemetry_updates += 1

        if is_vulnerable and probe["firmware_patched"]:
            cursor.execute(
                "UPDATE device_vulnerabilities SET status = 'Resolved' WHERE asset_id = ? AND status = 'Active'",
                (asset_id,)
            )
            baseline_risk = round(random.uniform(1.0, 2.5), 1)
            cursor.execute(
                "UPDATE device_details SET risk_score = ?, firmware_version = ?, last_scanned = ? WHERE asset_id = ?",
                (baseline_risk, probe["reported_firmware"], now_str, asset_id)
            )
            vulnerabilities_resolved += 1
            outcome = "vulnerability_resolved"

        elif (not is_vulnerable) and (probe["config_changed"] or probe["suspicious_behavior"]):
            eligible = get_eligible_vulns(device["type"], device["vendor"])
            if eligible:
                chosen_id = random.choice(eligible)
                cursor.execute(
                    "INSERT OR REPLACE INTO device_vulnerabilities (asset_id, vulnerability_id, status) VALUES (?, ?, 'Active')",
                    (asset_id, chosen_id)
                )
                cursor.execute("SELECT cvss_score FROM vulnerabilities WHERE id = ?", (chosen_id,))
                cvss_row = cursor.fetchone()
                new_risk = cvss_row["cvss_score"] if cvss_row else 5.0
                cursor.execute(
                    "UPDATE device_details SET risk_score = ?, last_scanned = ? WHERE asset_id = ?",
                    (new_risk, now_str, asset_id)
                )
                new_vulnerabilities_found += 1
                outcome = "new_vulnerability_found"
            else:
                outcome = "flagged_no_matching_cve"
                cursor.execute(
                    "UPDATE device_details SET last_scanned = ? WHERE asset_id = ?",
                    (now_str, asset_id)
                )
        else:
            cursor.execute(
                "UPDATE device_details SET last_scanned = ? WHERE asset_id = ?",
                (now_str, asset_id)
            )

        cursor.execute("""
            INSERT INTO device_probe_log
                (scan_id, asset_id, still_online_response, reported_firmware, config_changed, suspicious_behavior, outcome)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            scan_id, asset_id, probe["still_online_response"], probe["reported_firmware"],
            int(probe["config_changed"]), int(probe["suspicious_behavior"]), outcome
        ))

    cursor.execute("""
        UPDATE scan_log
        SET devices_scanned = ?, telemetry_updates = ?, vulnerabilities_resolved = ?, new_vulnerabilities_found = ?
        WHERE id = ?
    """, (len(devices), telemetry_updates, vulnerabilities_resolved, new_vulnerabilities_found, scan_id))

    conn.commit()

    return {
        "scan_id": scan_id,
        "scan_time": now_str,
        "scanned_devices": len(devices),
        "telemetry_updates": telemetry_updates,
        "vulnerabilities_resolved": vulnerabilities_resolved,
        "new_vulnerabilities_found": new_vulnerabilities_found
    }


async def background_scan_loop():
    while True:
        await asyncio.sleep(SCAN_INTERVAL_SECONDS)
        try:
            conn = sqlite3.connect(DB_NAME)
            conn.row_factory = sqlite3.Row
            run_scan_sweep(conn)
            conn.close()
        except Exception as e:
            print(f"[background scanner] sweep failed: {e}")


@app.on_event("startup")
async def on_startup():
    conn = sqlite3.connect(DB_NAME)
    ensure_tables(conn)
    conn.close()
    asyncio.create_task(background_scan_loop())

def get_db():
    if not os.path.exists(DB_NAME):
        raise HTTPException(status_code=500, detail="Database not initialized. Run data_fetcher.py first.")
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    return conn

class IsolationRequest(BaseModel):
    isolate: bool

@app.get("/")
def read_root():
    return {
        "message": "Welcome to the Municipal IoT Scanner API Portal",
        "endpoints": {
            "swagger_docs": "/docs",
            "assets": "/api/assets",
            "stats": "/api/stats",
            "vulnerabilities": "/api/vulnerabilities"
        }
    }

@app.get("/api/assets")
def get_assets(
    type: str = Query(None, description="Filter by asset type: traffic_signal, street_lamp, surveillance_camera"),
    status: str = Query(None, description="Filter by status: Online, Offline, Maintenance"),
    is_isolated: int = Query(None, description="Filter by isolation status: 0 or 1"),
    min_risk: float = Query(None, description="Filter by minimum risk score (0.0 to 10.0)")
):
    conn = get_db()
    cursor = conn.cursor()

    query = """
        SELECT a.*, d.vendor, d.model, d.firmware_version, d.mac_address, d.ip_address, d.status, d.risk_score, d.is_isolated, d.last_scanned,
               (SELECT COUNT(*) FROM device_vulnerabilities dv WHERE dv.asset_id = a.id AND dv.status = 'Active') as active_vulnerabilities_count
        FROM assets a
        JOIN device_details d ON a.id = d.asset_id
        WHERE 1=1
    """
    params = []

    if type:
        query += " AND a.type = ?"
        params.append(type)
    if status:
        query += " AND d.status = ?"
        params.append(status)
    if is_isolated is not None:
        query += " AND d.is_isolated = ?"
        params.append(is_isolated)
    if min_risk is not None:
        query += " AND d.risk_score >= ?"
        params.append(min_risk)

    cursor.execute(query, params)
    rows = cursor.fetchall()
    conn.close()

    assets = []
    for row in rows:
        asset = dict(row)
        asset["current_risk_score"] = 0.5 if asset["is_isolated"] == 1 else asset["risk_score"]
        assets.append(asset)

    return assets

@app.get("/api/assets/{asset_id}")
def get_asset_details(asset_id: str):
    conn = get_db()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT a.*, d.vendor, d.model, d.firmware_version, d.mac_address, d.ip_address, d.status, d.risk_score, d.is_isolated, d.last_scanned
        FROM assets a
        JOIN device_details d ON a.id = d.asset_id
        WHERE a.id = ?
    """, (asset_id,))

    asset_row = cursor.fetchone()
    if not asset_row:
        conn.close()
        raise HTTPException(status_code=404, detail=f"Asset with ID {asset_id} not found.")

    device = dict(asset_row)
    device["current_risk_score"] = 0.5 if device["is_isolated"] == 1 else device["risk_score"]

    cursor.execute("""
        SELECT v.*, dv.status as vulnerability_status
        FROM vulnerabilities v
        JOIN device_vulnerabilities dv ON v.id = dv.vulnerability_id
        WHERE dv.asset_id = ?
    """, (asset_id,))

    vulnerabilities = [dict(v) for v in cursor.fetchall()]
    device["vulnerabilities"] = vulnerabilities

    conn.close()
    return device

@app.post("/api/assets/{asset_id}/isolate")
def toggle_isolation(asset_id: str, request: IsolationRequest):
    conn = get_db()
    cursor = conn.cursor()

    cursor.execute("SELECT asset_id FROM device_details WHERE asset_id = ?", (asset_id,))
    if not cursor.fetchone():
        conn.close()
        raise HTTPException(status_code=404, detail=f"Asset with ID {asset_id} not found.")

    isolation_val = 1 if request.isolate else 0
    cursor.execute("""
        UPDATE device_details
        SET is_isolated = ?, last_scanned = ?
        WHERE asset_id = ?
    """, (isolation_val, datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"), asset_id))

    conn.commit()
    conn.close()

    action = "isolated" if request.isolate else "reconnected"
    return {
        "success": True,
        "asset_id": asset_id,
        "is_isolated": request.isolate,
        "message": f"Device {asset_id} has been successfully {action}."
    }

@app.get("/api/vulnerabilities")
def get_vulnerabilities():
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM vulnerabilities")
    vulns = [dict(v) for v in cursor.fetchall()]
    conn.close()
    return vulns

@app.get("/api/stats")
def get_stats():
    conn = get_db()
    cursor = conn.cursor()

    cursor.execute("SELECT COUNT(*), SUM(is_isolated) FROM device_details")
    total, isolated = cursor.fetchone()

    cursor.execute("SELECT status, COUNT(*) FROM device_details GROUP BY status")
    status_counts = {row["status"]: row[1] for row in cursor.fetchall()}

    cursor.execute("SELECT type, COUNT(*) FROM assets GROUP BY type")
    type_counts = {row["type"]: row[1] for row in cursor.fetchall()}

    cursor.execute("SELECT COUNT(DISTINCT asset_id) FROM device_vulnerabilities WHERE status = 'Active'")
    vulnerable_count = cursor.fetchone()[0]

    cursor.execute("""
        SELECT v.severity, COUNT(*)
        FROM device_vulnerabilities dv
        JOIN vulnerabilities v ON dv.vulnerability_id = v.id
        WHERE dv.status = 'Active'
        GROUP BY v.severity
    """)
    severity_counts = {row["severity"]: row[1] for row in cursor.fetchall()}

    cursor.execute("SELECT AVG(risk_score) FROM device_details")
    avg_risk = cursor.fetchone()[0] or 0.0

    cursor.execute("""
        SELECT AVG(CASE WHEN is_isolated = 1 THEN 0.5 ELSE risk_score END)
        FROM device_details
    """)
    avg_active_risk = cursor.fetchone()[0] or 0.0

    conn.close()

    return {
        "summary": {
            "total_assets": total,
            "online_assets": status_counts.get("Online", 0),
            "offline_assets": status_counts.get("Offline", 0),
            "maintenance_assets": status_counts.get("Maintenance", 0),
            "isolated_assets": isolated or 0,
            "vulnerable_assets": vulnerable_count,
            "average_base_risk": round(avg_risk, 2),
            "average_network_risk": round(avg_active_risk, 2)
        },
        "assets_by_type": {
            "traffic_signal": type_counts.get("traffic_signal", 0),
            "surveillance_camera": type_counts.get("surveillance_camera", 0),
            "street_lamp": type_counts.get("street_lamp", 0)
        },
        "vulnerabilities_by_severity": {
            "Critical": severity_counts.get("Critical", 0),
            "High": severity_counts.get("High", 0),
            "Medium": severity_counts.get("Medium", 0),
            "Low": severity_counts.get("Low", 0)
        }
    }

@app.post("/api/scan")
def trigger_scan():
    conn = get_db()
    result = run_scan_sweep(conn)
    conn.close()

    return {
        "success": True,
        "message": f"Vulnerability audit scan sweep completed at {result['scan_time']}.",
        **result
    }


@app.get("/api/scan/status")
def get_scan_status():
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM scan_log ORDER BY id DESC LIMIT 1")
    last = cursor.fetchone()
    conn.close()

    if not last:
        return {"last_scan": None, "scan_interval_seconds": SCAN_INTERVAL_SECONDS}

    last_scan_time = datetime.datetime.strptime(last["scan_time"], "%Y-%m-%dT%H:%M:%SZ")
    seconds_since = (datetime.datetime.utcnow() - last_scan_time).total_seconds()
    seconds_until_next = max(0, round(SCAN_INTERVAL_SECONDS - seconds_since))

    return {
        "last_scan": dict(last),
        "scan_interval_seconds": SCAN_INTERVAL_SECONDS,
        "seconds_until_next_scan": seconds_until_next
    }


@app.get("/api/scan/history")
def get_scan_history(limit: int = Query(20, description="Number of recent scan sweeps to return")):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM scan_log ORDER BY id DESC LIMIT ?", (limit,))
    rows = [dict(r) for r in cursor.fetchall()]
    conn.close()
    return rows


@app.get("/api/scan/{scan_id}/probes")
def get_scan_probes(scan_id: int):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM scan_log WHERE id = ?", (scan_id,))
    if not cursor.fetchone():
        conn.close()
        raise HTTPException(status_code=404, detail=f"Scan {scan_id} not found.")
    cursor.execute("SELECT * FROM device_probe_log WHERE scan_id = ? ORDER BY id", (scan_id,))
    rows = [dict(r) for r in cursor.fetchall()]
    conn.close()
    return rows


@app.get("/api/assets/{asset_id}/probe-history")
def get_asset_probe_history(asset_id: str, limit: int = Query(10, description="Number of recent probes to return")):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT pl.*, sl.scan_time
        FROM device_probe_log pl
        JOIN scan_log sl ON pl.scan_id = sl.id
        WHERE pl.asset_id = ?
        ORDER BY pl.id DESC
        LIMIT ?
    """, (asset_id, limit))
    rows = [dict(r) for r in cursor.fetchall()]
    conn.close()
    return rows