from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import sqlite3
import datetime
import random
import os

app = FastAPI(
    title="Municipal IoT Scanner API",
    description="Authorized backend API for Municipal IoT Asset Inventory & Vulnerability Auditing.",
    version="1.0.0"
)

# Enable CORS for frontend connectivity
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

DB_NAME = "municipal_iot.db"

def get_db():
    if not os.path.exists(DB_NAME):
        raise HTTPException(status_code=500, detail="Database not initialized. Run data_fetcher.py first.")
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    return conn

# Response Models
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
    """Retrieve all municipal IoT assets with their location and security status."""
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
        # Calculate current dynamic risk score (e.g. if isolated, risk is mitigated to 0.5)
        asset["current_risk_score"] = 0.5 if asset["is_isolated"] == 1 else asset["risk_score"]
        assets.append(asset)
        
    return assets

@app.get("/api/assets/{asset_id}")
def get_asset_details(asset_id: str):
    """Retrieve detailed specification, firmware, and active vulnerabilities for a specific device."""
    conn = get_db()
    cursor = conn.cursor()
    
    # Fetch asset and device details
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
    
    # Fetch active vulnerabilities for this device
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
    """Isolate a compromised device from the municipal network or reconnect it."""
    conn = get_db()
    cursor = conn.cursor()
    
    # Check if asset exists
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
    """Get the listing of known IoT CVE vulnerabilities in the auditor database."""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM vulnerabilities")
    vulns = [dict(v) for v in cursor.fetchall()]
    conn.close()
    return vulns

@app.get("/api/stats")
def get_stats():
    """Retrieve summarized statistics for dashboard widgets and chart rendering."""
    conn = get_db()
    cursor = conn.cursor()
    
    # 1. Total count, online, offline, maintenance, isolated
    cursor.execute("SELECT COUNT(*), SUM(is_isolated) FROM device_details")
    total, isolated = cursor.fetchone()
    
    cursor.execute("SELECT status, COUNT(*) FROM device_details GROUP BY status")
    status_counts = {row["status"]: row[1] for row in cursor.fetchall()}
    
    # 2. Counts by asset type
    cursor.execute("SELECT type, COUNT(*) FROM assets GROUP BY type")
    type_counts = {row["type"]: row[1] for row in cursor.fetchall()}
    
    # 3. Vulnerable asset counts (assets with at least one active vulnerability)
    cursor.execute("SELECT COUNT(DISTINCT asset_id) FROM device_vulnerabilities WHERE status = 'Active'")
    vulnerable_count = cursor.fetchone()[0]
    
    # 4. Count of vulnerabilities by severity
    cursor.execute("""
        SELECT v.severity, COUNT(*) 
        FROM device_vulnerabilities dv
        JOIN vulnerabilities v ON dv.vulnerability_id = v.id
        WHERE dv.status = 'Active'
        GROUP BY v.severity
    """)
    severity_counts = {row["severity"]: row[1] for row in cursor.fetchall()}
    
    # 5. Average risk score
    cursor.execute("SELECT AVG(risk_score) FROM device_details")
    avg_risk = cursor.fetchone()[0] or 0.0
    
    # Calculate an active risk score average (taking isolation into account)
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
    """Simulate a network vulnerability scan sweep. Updates scanning times and statuses."""
    conn = get_db()
    cursor = conn.cursor()
    
    now_str = datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
    
    # 1. Update last scanned timestamp for all non-isolated devices
    cursor.execute("UPDATE device_details SET last_scanned = ? WHERE is_isolated = 0", (now_str,))
    
    # 2. Randomly toggle status for 3-5% of devices to simulate live telemetry updates
    cursor.execute("SELECT asset_id, status FROM device_details")
    devices = cursor.fetchall()
    
    toggled_count = 0
    for device in devices:
        if random.random() < 0.05: # 5% chance of telemetry changes
            current_status = device["status"]
            new_status = random.choice(["Online", "Offline", "Maintenance"])
            if current_status != new_status:
                cursor.execute(
                    "UPDATE device_details SET status = ?, last_scanned = ? WHERE asset_id = ?",
                    (new_status, now_str, device["asset_id"])
                )
                toggled_count += 1
                
    conn.commit()
    conn.close()
    
    return {
        "success": True,
        "message": f"Vulnerability audit scan sweep completed at {now_str}.",
        "telemetry_updates": toggled_count,
        "scanned_devices": len(devices)
    }
