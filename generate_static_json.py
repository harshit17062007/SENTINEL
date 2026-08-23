import json
import random

# Target City Details
CITY = "Jaipur"
JAIPUR_LAT = 26.9124
JAIPUR_LON = 75.7873

# Standard CVE database
VULNERABILITIES_DB = {
    "CVE-2023-51764": {
        "id": "CVE-2023-51764",
        "title": "Siemens Traffic Controller Hardcoded Credentials",
        "severity": "Critical",
        "cvss_score": 9.8,
        "description": "Hardcoded credentials in the SSH interface of Siemens M50/M60 Traffic Controllers allow remote attackers to gain root access.",
        "remediation": "Disable SSH password authentication, rotate root passwords, and upgrade firmware to v1.5.0."
    },
    "CVE-2022-26134": {
        "id": "CVE-2022-26134",
        "title": "Hikvision CCTV Remote Code Execution",
        "severity": "High",
        "cvss_score": 8.8,
        "description": "An unauthenticated remote code execution vulnerability exists in the web server of Hikvision cameras via crafted HTTP requests.",
        "remediation": "Upgrade camera firmware to version v1.2.0 or higher immediately and restrict web interface access."
    },
    "CVE-2024-32113": {
        "id": "CVE-2024-32113",
        "title": "Philips Lighting Bridge Command Injection",
        "severity": "Medium",
        "cvss_score": 6.5,
        "description": "Insecure parameter validation on the Philips Hue Bridge API interface allows authenticated local users to execute arbitrary system commands.",
        "remediation": "Apply vendor firmware update v3.5.2 and place the bridge on a separate VLAN."
    },
    "CVE-2021-36423": {
        "id": "CVE-2021-36423",
        "title": "Cisco Industrial Switch Buffer Overflow",
        "severity": "High",
        "cvss_score": 7.5,
        "description": "A buffer overflow in the web management UI of Cisco IE3400 switches allows attackers to cause a denial of service or execute arbitrary code with privilege.",
        "remediation": "Install Cisco IOS XE Software update version 17.6 or apply ACL filters on port 443."
    },
    "CVE-2023-45678": {
        "id": "CVE-2023-45678",
        "title": "Smart-Lighting Central Gateway Command Injection",
        "severity": "Critical",
        "cvss_score": 9.1,
        "description": "Flaw in command parsing interface of Schneider Smart-Lighting Controller permits remote code execution without authentication.",
        "remediation": "Disable administrative web portal from external access and patch firmware to v2.1."
    },
    "CVE-2022-11223": {
        "id": "CVE-2022-11223",
        "title": "Surveillance Camera Information Disclosure",
        "severity": "Low",
        "cvss_score": 3.2,
        "description": "Axis cameras leak system state info and network configurations to unauthenticated users via the raw status API endpoints.",
        "remediation": "Restrict API read access permissions by enforcing API keys or basic auth."
    }
}

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

def generate_mac():
    return ":".join(f"{random.randint(0, 255):02X}" for _ in range(6))

def generate_ip(index):
    subnet_x = (index // 250) + 1
    subnet_y = (index % 250) + 1
    return f"10.150.{subnet_x}.{subnet_y}"

def generate_dataset():
    assets = []
    types = ["traffic_signal", "surveillance_camera", "street_lamp"]
    
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
    
    # Real-world contractors active in Jaipur Smart City
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
    
    for i in range(200):
        anchor = random.choice(anchors)
        lat = anchor["lat"] + random.uniform(-0.015, 0.015)
        lon = anchor["lon"] + random.uniform(-0.015, 0.015)
        
        asset_type = random.choices(types, weights=[0.3, 0.2, 0.5], k=1)[0]
        osm_id = 9000000000 + i
        
        # Name and Prefix
        if asset_type == "traffic_signal":
            raw_name = f"Traffic Signal near {anchor['name']}"
            prefix = "TL-JPR"
        elif asset_type == "surveillance_camera":
            raw_name = f"CCTV Surveillance near {anchor['name']}"
            prefix = "CAM-JPR"
        else:
            raw_name = f"Street Light near {anchor['name']}"
            prefix = "LT-JPR"
            
        asset_id = f"{prefix}-{osm_id % 1000000:06d}"
        
        # Device details
        profile = random.choice(VENDORS[asset_type])
        vendor = profile["vendor"]
        model = random.choice(profile["models"])
        
        major = random.randint(1, 4)
        minor = random.randint(0, 9)
        patch = random.randint(0, 9)
        firmware = f"v{major}.{minor}.{patch}"
        
        # Accountability Details
        zones = ["Jaipur Greater", "Jaipur Heritage"]
        zone = random.choice(zones)
        ward = f"Ward {random.randint(1, 150)}"
        
        contractor_profile = random.choice(contractor_map[asset_type])
        contractor_name = contractor_profile["name"]
        contract_reference = contractor_profile["ref"]
        
        if zone == "Jaipur Greater":
            responsible_officer = "Shri Rajesh Kumar Gupta, Executive Engineer (Electrical), Nagar Nigam Jaipur Greater"
            officer_email = "ee.electrical.greater@jaipurmc.org"
        else:
            responsible_officer = "Smt. Priyanka Sharma, Deputy Commissioner (IT & Smart City), Nagar Nigam Jaipur Heritage"
            officer_email = "dc.it.heritage@jaipurmc.org"
            
        # Vulnerability Association
        is_vulnerable = random.random() < 0.4
        assigned_vulns = []
        if is_vulnerable and profile["vulns"]:
            assigned_vulns = random.sample(profile["vulns"], k=random.randint(1, len(profile["vulns"])))
            if random.random() < 0.3:
                assigned_vulns.append("CVE-2021-36423")
        
        assigned_vulns = list(set(assigned_vulns))
        
        # CVE detailed dict list
        vulnerabilities = []
        max_cvss = 0.0
        for v_id in assigned_vulns:
            v_details = VULNERABILITIES_DB[v_id]
            vulnerabilities.append(v_details)
            max_cvss = max(max_cvss, v_details["cvss_score"])
            
        risk_score = round(max_cvss, 1) if assigned_vulns else round(random.uniform(1.0, 2.5), 1)
        mac = generate_mac()
        ip = generate_ip(i)
        status = random.choices(["Online", "Offline", "Maintenance"], weights=[0.85, 0.10, 0.05], k=1)[0]
        
        hours_ago = random.randint(0, 48)
        mins_ago = random.randint(0, 59)
        last_scanned = f"2026-08-23T{23 - (hours_ago % 24):02d}:{mins_ago:02d}:00Z"
        
        # Liability-safe Disclaimer Email Template Draft
        remediation_notice = None
        if assigned_vulns:
            vuln_list_str = "\n".join([f"- {v['id']}: {v['title']} (CVSS: {v['cvss_score']})" for v in vulnerabilities])
            action_list_str = "\n".join([f"{idx+1}. {v['remediation']}" for idx, v in enumerate(vulnerabilities)])
            
            remediation_notice = {
                "to_officer_email": officer_email,
                "cc_contractor_email": "support@eesl.co.in" if asset_type == "street_lamp" else "support@datacoreinfotech.co.in",
                "subject": f"URGENT: Remediation Request - Probable Security Exposure on Asset {asset_id}",
                "body": (
                    f"Dear {responsible_officer.split(',')[0]},\n\n"
                    f"We are writing to report a probable security exposure identified on municipal asset {asset_id} "
                    f"({raw_name}), currently deployed under {ward} ({zone}).\n\n"
                    f"According to Rajasthan State Public Procurement Portal (SPPP) Award of Contract records ({contract_reference}), "
                    f"this infrastructure is maintained by {contractor_name}.\n\n"
                    f"DETAILED SCAN TELEMETRY:\n"
                    f"- Device IP: {ip}\n"
                    f"- Vendor/Model: {vendor} {model}\n"
                    f"- Firmware Version: {firmware}\n"
                    f"- Identified Vulnerability(ies):\n{vuln_list_str}\n"
                    f"- Composite Risk Score: {risk_score} (CVSS-based)\n\n"
                    f"RECOMMENDED REMEDIATION ACTIONS:\n"
                    f"{action_list_str}\n"
                    f"*. Consider isolating the device from the network until remediation is verified.\n\n"
                    f"IMPORTANT LIABILITY DISCLAIMER:\n"
                    f"This notice is generated based on automated vulnerability scanner telemetry and SPPP award records. "
                    f"This is a PROBABLE MATCH only. Kindly verify the device configuration and firmware record directly "
                    f"against the physical tender documents and asset registry prior to committing changes.\n\n"
                    f"Sincerely,\nMunicipal IoT Scanner - Vulnerability Audit Engine\nCity of Jaipur"
                )
            }
            
        assets.append({
            "id": asset_id,
            "osm_id": osm_id,
            "name": raw_name,
            "type": asset_type,
            "latitude": lat,
            "longitude": lon,
            "city": CITY,
            "zone": zone,
            "ward": ward,
            "vendor": vendor,
            "model": model,
            "firmware_version": firmware,
            "mac_address": mac,
            "ip_address": ip,
            "status": status,
            "risk_score": risk_score,
            "is_isolated": 0,
            "last_scanned": last_scanned,
            "responsible_officer": responsible_officer,
            "officer_email": officer_email,
            "contractor_name": contractor_name,
            "contract_reference": contract_reference,
            "active_vulnerabilities": vulnerabilities,
            "remediation_notice_draft": remediation_notice
        })
        
    with open("jaipur_iot_assets.json", "w") as f:
        json.dump(assets, f, indent=2)
        
    print("Static dataset successfully created at 'jaipur_iot_assets.json'!")

if __name__ == "__main__":
    generate_dataset()
