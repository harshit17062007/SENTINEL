import sqlite3
import random
import requests
import json
import os
import sys

DB_NAME = "municipal_iot.db"
JAIPUR_LAT = 26.9124
JAIPUR_LON = 75.7873

# Defined IoT Vulnerabilities (CVE database)
VULNERABILITIES = [
    {
        "id": "CVE-2023-51764",
        "title": "Siemens Traffic Controller Hardcoded Credentials",
        "severity": "Critical",
        "cvss_score": 9.8,
        "description": "Hardcoded credentials in the SSH interface of Siemens M50/M60 Traffic Controllers allow remote attackers to gain root access.",
        "remediation": "Disable SSH password authentication, rotate root passwords, and upgrade firmware to v1.5.0."
    },
    {
        "id": "CVE-2022-26134",
        "title": "Hikvision CCTV Remote Code Execution",
        "severity": "High",
        "cvss_score": 8.8,
        "description": "An unauthenticated remote code execution vulnerability exists in the web server of Hikvision cameras via crafted HTTP requests.",
        "remediation": "Upgrade camera firmware to version v1.2.0 or higher immediately and restrict web interface access."
    },
    {
        "id": "CVE-2024-32113",
        "title": "Philips Lighting Bridge Command Injection",
        "severity": "Medium",
        "cvss_score": 6.5,
        "description": "Insecure parameter validation on the Philips Hue Bridge API interface allows authenticated local users to execute arbitrary system commands.",
        "remediation": "Apply vendor firmware update v3.5.2 and place the bridge on a separate VLAN."
    },
    {
        "id": "CVE-2021-36423",
        "title": "Cisco Industrial Switch Buffer Overflow",
        "severity": "High",
        "cvss_score": 7.5,
        "description": "A buffer overflow in the web management UI of Cisco IE3400 switches allows attackers to cause a denial of service or execute arbitrary code with privilege.",
        "remediation": "Install Cisco IOS XE Software update version 17.6 or apply ACL filters on port 443."
    },
    {
        "id": "CVE-2023-45678",
        "title": "Smart-Lighting Central Gateway Command Injection",
        "severity": "Critical",
        "cvss_score": 9.1,
        "description": "Flaw in command parsing interface of Schneider Smart-Lighting Controller permits remote code execution without authentication.",
        "remediation": "Disable administrative web portal from external access and patch firmware to v2.1."
    },
    {
        "id": "CVE-2022-11223",
        "title": "Surveillance Camera Information Disclosure",
        "severity": "Low",
        "cvss_score": 3.2,
        "description": "Axis cameras leak system state info and network configurations to unauthenticated users via the raw status API endpoints.",
        "remediation": "Restrict API read access permissions by enforcing API keys or basic auth."
    }
]

# Asset profiles for realistic data generation
VENDORS = {
    "traffic_signal": [
        {"vendor": "Siemens", "models": ["M50 Controller", "M60 Controller"], "vulns": ["CVE-2023-51764"]},
        {"vendor": "Swarco", "models": ["ITC-3 Traffic Controller", "ACTROS Controller"], "vulns": ["CVE-2021-36423"]},
        {"vendor": "Schneider Electric", "models": ["EcoStruxure Traffic Control"], "vulns": []}
    ],
    "surveillance_camera": [
        {"vendor": "Hikvision", "models": ["DS-2CD2143G0-I Camera", "DS-2CD2087G2-L Camera"], "vulns": ["CVE-2022-26134"]},
        {"vendor": "Axis Communications", "models": ["Q6075-E PTZ Camera", "M3065-V Dome"], "vulns": ["CVE-2022-11223"]},
        {"vendor": "Dahua Technology", "models": ["DH-IPC-HFW2431S Camera"], "vulns": ["CVE-2022-26134"]}
    ],
    "street_lamp": [
        {"vendor": "Philips Lighting", "models": ["CityTouch Connector Node", "Hue Bridge SL-100"], "vulns": ["CVE-2024-32113"]},
        {"vendor": "Schneider Electric", "models": ["Smart Lamp Node SLN-200"], "vulns": ["CVE-2023-45678"]},
        {"vendor": "GE Current", "models": ["LightGrid Gen 3 Nodes"], "vulns": []}
    ]
}

def setup_database():
    """Create SQLite tables for the Municipal IoT inventory."""
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    
    # 1. Assets table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS assets (
        id TEXT PRIMARY KEY,
        osm_id INTEGER,
        name TEXT NOT NULL,
        type TEXT NOT NULL,
        latitude REAL NOT NULL,
        longitude REAL NOT NULL,
        street TEXT,
        city TEXT NOT NULL,
        zone TEXT,
        ward TEXT,
        responsible_officer TEXT,
        contractor_name TEXT,
        contract_reference TEXT,
        officer_email TEXT
    )
    """)
    
    # 2. Device details table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS device_details (
        asset_id TEXT PRIMARY KEY,
        vendor TEXT NOT NULL,
        model TEXT NOT NULL,
        firmware_version TEXT NOT NULL,
        mac_address TEXT UNIQUE NOT NULL,
        ip_address TEXT UNIQUE NOT NULL,
        status TEXT NOT NULL,
        risk_score REAL NOT NULL,
        is_isolated INTEGER DEFAULT 0,
        last_scanned TEXT NOT NULL,
        FOREIGN KEY (asset_id) REFERENCES assets(id) ON DELETE CASCADE
    )
    """)
    
    # 3. Vulnerabilities table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS vulnerabilities (
        id TEXT PRIMARY KEY,
        title TEXT NOT NULL,
        severity TEXT NOT NULL,
        cvss_score REAL NOT NULL,
        description TEXT NOT NULL,
        remediation TEXT NOT NULL
    )
    """)
    
    # 4. Device vulnerabilities mapping table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS device_vulnerabilities (
        asset_id TEXT,
        vulnerability_id TEXT,
        status TEXT DEFAULT 'Active',
        PRIMARY KEY (asset_id, vulnerability_id),
        FOREIGN KEY (asset_id) REFERENCES assets(id) ON DELETE CASCADE,
        FOREIGN KEY (vulnerability_id) REFERENCES vulnerabilities(id) ON DELETE CASCADE
    )
    """)
    
    # Populate standard vulnerabilities
    for v in VULNERABILITIES:
        cursor.execute("""
        INSERT OR REPLACE INTO vulnerabilities (id, title, severity, cvss_score, description, remediation)
        VALUES (?, ?, ?, ?, ?, ?)
        """, (v["id"], v["title"], v["severity"], v["cvss_score"], v["description"], v["remediation"]))
        
    conn.commit()
    conn.close()
    print("Database tables initialized successfully.")

def fetch_osm_data():
    """Fetch real-world municipal infrastructure nodes from OpenStreetMap Overpass API."""
    query = """
    [out:json][timeout:30];
    area[name="Jaipur"]->.searchArea;
    (
      node["highway"="traffic_signals"](area.searchArea);
      node["man_made"="surveillance"](area.searchArea);
      node["highway"="street_lamp"](area.searchArea);
      node["man_made"="street_lamp"](area.searchArea);
    );
    out body;
    """
    
    # Overpass mirrors for reliability
    mirrors = [
        "https://overpass-api.de/api/interpreter",
        "https://overpass.kumi.systems/api/interpreter",
        "https://overpass.openstreetmap.ru/api/interpreter"
    ]
    
    # Unique, compliant User-Agent identification string
    headers = {
        "User-Agent": "JaipurMunicipalIoTScannerAudit/1.0 (contact.yahar.hackathon@example.com)",
        "Accept": "application/json"
    }
    
    import urllib.parse
    
    for url in mirrors:
        try:
            print(f"Fetching real municipal asset data from OSM mirror (GET): {url}...")
            # Try GET first as WAFs are less aggressive against URL GET requests
            encoded_query = urllib.parse.quote(query.strip())
            get_url = f"{url}?data={encoded_query}"
            
            response = requests.get(get_url, headers=headers, timeout=20)
            if response.status_code == 200:
                data = response.json()
                nodes = data.get("elements", [])
                print(f"Successfully fetched {len(nodes)} nodes from OSM via GET.")
                return nodes
            else:
                print(f"GET to mirror {url} returned status {response.status_code}. Trying POST...")
                
                response = requests.post(url, data={"data": query}, headers=headers, timeout=20)
                if response.status_code == 200:
                    data = response.json()
                    nodes = data.get("elements", [])
                    print(f"Successfully fetched {len(nodes)} nodes from OSM via POST.")
                    return nodes
                else:
                    print(f"POST to mirror {url} returned status {response.status_code}. Trying next mirror...")
        except Exception as e:
            print(f"Mirror {url} failed: {e}. Trying next...")
            
    print("All OSM mirrors failed. Falling back to local generation.")
    return []

def generate_synthetic_nodes(count=200):
    """Generate highly realistic municipal IoT nodes around Jaipur landmarks to augment data."""
    print(f"Generating {count} synthetic municipal IoT nodes for Jaipur...")
    nodes = []
    types = ["traffic_signals", "surveillance", "street_lamp"]
    
    # Famous Jaipur locations to anchor device clusters
    anchors = [
        {"name": "Hawa Mahal", "lat": 26.9239, "lon": 75.8267},
        {"name": "City Palace", "lat": 26.9258, "lon": 75.8237},
        {"name": "Albert Hall Museum", "lat": 26.9116, "lon": 75.8195},
        {"name": "Jal Mahal", "lat": 26.9535, "lon": 75.8462},
        {"name": "C-Scheme", "lat": 26.9096, "lon": 75.8016},
        {"name": "Malviya Nagar", "lat": 26.8532, "lon": 75.8048},
        {"name": "Mansarovar", "lat": 26.8688, "lon": 75.7645},
        {"name": "Raja Park", "lat": 26.8996, "lon": 75.8291},
        {"name": "Jaipur Railway Station", "lat": 26.9197, "lon": 75.7878},
        {"name": "Tonk Road", "lat": 26.8776, "lon": 75.7950}
    ]
    
    for i in range(count):
        anchor = random.choice(anchors)
        # Jitter coordinates slightly around the anchor point
        lat = anchor["lat"] + random.uniform(-0.015, 0.015)
        lon = anchor["lon"] + random.uniform(-0.015, 0.015)
        
        node_type = random.choices(types, weights=[0.3, 0.2, 0.5], k=1)[0]
        node_id = 9000000000 + i
        
        tags = {}
        if node_type == "traffic_signals":
            tags["highway"] = "traffic_signals"
            tags["name"] = f"Traffic Signal near {anchor['name']}"
        elif node_type == "surveillance":
            tags["man_made"] = "surveillance"
            tags["name"] = f"CCTV Surveillance near {anchor['name']}"
        else:
            tags["highway"] = "street_lamp"
            tags["name"] = f"Street Light near {anchor['name']}"
            
        nodes.append({
            "id": node_id,
            "lat": lat,
            "lon": lon,
            "tags": tags
        })
    return nodes

def generate_mac():
    return ":".join(f"{random.randint(0, 255):02X}" for _ in range(6))

def generate_ip(index):
    # Generates IP in municipal subnet 10.150.X.Y
    subnet_x = (index // 250) + 1
    subnet_y = (index % 250) + 1
    return f"10.150.{subnet_x}.{subnet_y}"

def map_osm_type(tags):
    if "highway" in tags and tags["highway"] == "traffic_signals":
        return "traffic_signal"
    elif "man_made" in tags and tags["man_made"] == "surveillance":
        return "surveillance_camera"
    elif "surveillance" in tags:
        return "surveillance_camera"
    elif "highway" in tags and tags["highway"] == "street_lamp":
        return "street_lamp"
    elif "man_made" in tags and tags["man_made"] == "street_lamp":
        return "street_lamp"
    else:
        return "street_lamp" # Default fallback

def populate_devices(nodes):
    """Processes nodes, generates simulated metadata, and populates the database."""
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    
    # Clean old entries
    cursor.execute("DELETE FROM assets")
    cursor.execute("DELETE FROM device_details")
    cursor.execute("DELETE FROM device_vulnerabilities")
    
    print(f"Populating database with {len(nodes)} devices...")
    
    for i, node in enumerate(nodes):
        osm_id = node["id"]
        lat = node["lat"]
        lon = node["lon"]
        tags = node.get("tags", {})
        
        # 1. Resolve asset type & human-friendly name
        asset_type = map_osm_type(tags)
        
        # Determine name
        raw_name = tags.get("name")
        if not raw_name:
            if asset_type == "traffic_signal":
                raw_name = f"Traffic Signal (Node #{osm_id % 100000})"
            elif asset_type == "surveillance_camera":
                raw_name = f"CCTV Dome Camera (Node #{osm_id % 100000})"
            else:
                raw_name = f"Smart Streetlight (Node #{osm_id % 100000})"
                
        # Generate custom unique asset ID
        asset_prefix = {
            "traffic_signal": "TL-JPR",
            "surveillance_camera": "CAM-JPR",
            "street_lamp": "LT-JPR"
        }.get(asset_type, "IOT-JPR")
        
        asset_id = f"{asset_prefix}-{osm_id % 1000000:06d}"
        
        street = tags.get("addr:street", tags.get("road", None))
        city = "Jaipur"
        
        # Accountability Routing Info
        zones = ["Jaipur Greater", "Jaipur Heritage"]
        zone = random.choice(zones)
        ward = f"Ward {random.randint(1, 150)}"
        
        # Real-world contractors active in Rajasthan/Jaipur smart projects
        contractor_map = {
            "traffic_signal": [
                {"name": "Data Core Infotech Pvt Ltd", "ref": "Tender Ref: JSCL/ITMS/2024/NIB-42"},
                {"name": "Larsen & Toubro (L&T) Smart World & Communication", "ref": "Tender Ref: JDA/EE-IT/2025/NIB-88"}
            ],
            "surveillance_camera": [
                {"name": "Data Core Infotech Pvt Ltd", "ref": "Tender Ref: JSCL/CCTV/2024/NIB-42"},
                {"name": "HFCL Limited", "ref": "Tender Ref: Police-HQ/CCTV-Surveillance/2023/11"},
                {"name": "Larsen & Toubro (L&T) Smart World & Communication", "ref": "Tender Ref: JDA/CCTV-Safety/2024/NIB-102"}
            ],
            "street_lamp": [
                {"name": "Energy Efficiency Services Limited (EESL)", "ref": "Tender Ref: Nagar-Nigam/Smart-Light/2024-25/08"},
                {"name": "Techno Electric & Engineering Co. Ltd", "ref": "Tender Ref: JSCL/Lighting/2023-24/NIB-17"}
            ]
        }
        
        contractor_profile = random.choice(contractor_map[asset_type])
        contractor_name = contractor_profile["name"]
        contract_reference = contractor_profile["ref"]
        
        if zone == "Jaipur Greater":
            responsible_officer = "Shri Rajesh Kumar Gupta, Executive Engineer (Electrical), Nagar Nigam Jaipur Greater"
            officer_email = "ee.electrical.greater@jaipurmc.org"
        else:
            responsible_officer = "Smt. Priyanka Sharma, Deputy Commissioner (IT & Smart City), Nagar Nigam Jaipur Heritage"
            officer_email = "dc.it.heritage@jaipurmc.org"
            
        # Insert into assets table
        cursor.execute("""
        INSERT INTO assets (id, osm_id, name, type, latitude, longitude, street, city, zone, ward, responsible_officer, contractor_name, contract_reference, officer_email)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (asset_id, osm_id, raw_name, asset_type, lat, lon, street, city, zone, ward, responsible_officer, contractor_name, contract_reference, officer_email))
        
        # 2. Generate simulated details
        profiles = VENDORS[asset_type]
        profile = random.choice(profiles)
        
        vendor = profile["vendor"]
        model = random.choice(profile["models"])
        
        # Generate firmware version
        # Some are outdated, some are patched
        major = random.randint(1, 4)
        minor = random.randint(0, 9)
        patch = random.randint(0, 9)
        firmware = f"v{major}.{minor}.{patch}"
        
        # Determine if vulnerable based on random chance
        # Let's say 40% of devices have active vulnerabilities
        is_vulnerable = random.random() < 0.4
        
        assigned_vulns = []
        if is_vulnerable and profile["vulns"]:
            # Pick from model's designated vulnerabilities
            assigned_vulns = random.sample(profile["vulns"], k=random.randint(1, len(profile["vulns"])))
            # Add general network vulnerability occasionally
            if random.random() < 0.3:
                assigned_vulns.append("CVE-2021-36423")
                
        # Deduplicate vulnerabilities
        assigned_vulns = list(set(assigned_vulns))
        
        # Calculate initial risk score based on vulnerability CVSS scores
        if assigned_vulns:
            # Find maximum CVSS score of active vulnerabilities
            max_cvss = 0.0
            for v_id in assigned_vulns:
                for v in VULNERABILITIES:
                    if v["id"] == v_id:
                        max_cvss = max(max_cvss, v["cvss_score"])
            risk_score = round(max_cvss, 1)
        else:
            # Baseline risk for internet/network-connected IoT device
            risk_score = round(random.uniform(1.0, 2.5), 1)
            
        mac = generate_mac()
        ip = generate_ip(i)
        
        status = random.choices(["Online", "Offline", "Maintenance"], weights=[0.85, 0.10, 0.05], k=1)[0]
        
        # Last scanned timestamp in ISO format (simulated recent scans)
        hours_ago = random.randint(0, 48)
        mins_ago = random.randint(0, 59)
        last_scanned = f"2026-08-23T{23 - (hours_ago % 24):02d}:{mins_ago:02d}:00Z"
        
        # Insert into device_details
        cursor.execute("""
        INSERT INTO device_details (asset_id, vendor, model, firmware_version, mac_address, ip_address, status, risk_score, is_isolated, last_scanned)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0, ?)
        """, (asset_id, vendor, model, firmware, mac, ip, status, risk_score, last_scanned))
        
        # Associate vulnerabilities
        for v_id in assigned_vulns:
            cursor.execute("""
            INSERT OR IGNORE INTO device_vulnerabilities (asset_id, vulnerability_id, status)
            VALUES (?, ?, 'Active')
            """, (asset_id, v_id))
            
    conn.commit()
    conn.close()
    print("Database population complete!")

def main():
    setup_database()
    
    # Try fetching real OSM data
    osm_nodes = fetch_osm_data()
    
    # If OSM data is sparse (e.g. fewer than 50 entries) or empty, we augment it
    target_count = 200
    if len(osm_nodes) < 50:
        print(f"OSM results ({len(osm_nodes)}) are sparse. Augmenting with synthetic Jaipur municipal nodes.")
        synth_nodes = generate_synthetic_nodes(target_count - len(osm_nodes))
        all_nodes = osm_nodes + synth_nodes
    else:
        # If we got enough, we can use them directly or crop if there are too many for a snappy demo
        all_nodes = osm_nodes[:300]
        print(f"Using {len(all_nodes)} nodes from OSM.")
        
    populate_devices(all_nodes)
    
    # Save a cached version as mock_data.json for backup/direct reference
    # Let's read from sqlite and dump to JSON for a quick inspection/backup
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("""
        SELECT a.*, d.vendor, d.model, d.firmware_version, d.mac_address, d.ip_address, d.status, d.risk_score, d.is_isolated, d.last_scanned
        FROM assets a JOIN device_details d ON a.id = d.asset_id
    """)
    rows = cursor.fetchall()
    data_list = [dict(row) for row in rows]
    
    with open("mock_data.json", "w") as f:
        json.dump(data_list, f, indent=2)
    print("Exported local cache to 'mock_data.json' for reference.")
    conn.close()

if __name__ == "__main__":
    main()
