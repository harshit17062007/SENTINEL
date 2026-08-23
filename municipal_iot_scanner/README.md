# Municipal IoT Scanner - Vulnerability Audit Data & API Server

This project provides a realistic, structured municipal IoT inventory database and mock API server for a vulnerability auditor dashboard. It covers the city of **Jaipur, India**, combining real coordinates and locations with simulated IoT firmware and vulnerabilities (CVEs) to facilitate high-fidelity demos.

## Tech Stack
- **Database**: SQLite (`municipal_iot.db`)
- **Backend API**: Python 3, FastAPI, Uvicorn
- **Data Source**: OpenStreetMap (OSM) Overpass API (with high-fidelity fallback generator)

---

## Directory Structure
- `requirements.txt` - Python dependencies (fastapi, uvicorn, requests)
- `data_fetcher.py` - Database creation & data population script
- `server.py` - FastAPI REST API server
- `mock_data.json` - Exported JSON file containing the complete initial generated database for quick inspection/backup
- `municipal_iot.db` - SQLite database containing all device metadata

---

## Installation & Setup

1. **Install Python Dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

2. **Re-populate the Database (Optional)**:
   The database is already populated with 200 devices located near famous Jaipur landmarks (Hawa Mahal, City Palace, Jal Mahal, Malviya Nagar, Mansarovar, etc.). If you wish to refresh or rebuild the database, run:
   ```bash
   python data_fetcher.py
   ```

3. **Start the API Server**:
   Run the FastAPI server locally:
   ```bash
   python -m uvicorn server:app --reload --host 127.0.0.1 --port 8000
   ```
   *The server is currently running in the background on your system.*

---

## API Documentation & Endpoints

FastAPI includes a built-in **interactive Swagger UI** where you can test all endpoints:
👉 **[http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)**

### Summary of REST Endpoints:

#### 1. Global Statistics (`GET /api/stats`)
Returns total asset counts, status summaries (online/offline/isolated), device type distribution, CVE severity counts, and overall average risk scores. Excellent for populating dashboard widgets.
- **URL**: `http://127.0.0.1:8000/api/stats`

#### 2. Get Asset Inventory (`GET /api/assets`)
Returns a list of all devices in the city with coordinates, type, model, IP/MAC address, current risk score, status, and isolation state. Supports query filtering by:
- `type` (e.g. `traffic_signal`, `street_lamp`, `surveillance_camera`)
- `status` (e.g. `Online`, `Offline`, `Maintenance`)
- `is_isolated` (e.g. `0` or `1`)
- `min_risk` (e.g. `5.0`)
- **URL**: `http://127.0.0.1:8000/api/assets`

#### 3. Get Device Details (`GET /api/assets/{asset_id}`)
Returns detailed device configuration and a list of active CVE vulnerabilities associated with that device (with descriptions, CVSS scores, and remediation steps).
- **URL**: `http://127.0.0.1:8000/api/assets/TL-JPR-000000`

#### 4. Toggle Network Isolation (`POST /api/assets/{asset_id}/isolate`)
Isolates a device from the municipal network (or reconnects it), mitigating risk.
- **Request Body**: `{"isolate": true}` (or `false` to reconnect)
- **Effect**: Setting `isolate: true` updates `is_isolated` to `1` and dynamically reduces its active network risk score to `0.5`.
- **URL**: `http://127.0.0.1:8000/api/assets/TL-JPR-000000/isolate`

#### 5. Trigger Vulnerability Sweep (`POST /api/scan`)
Simulates a live vulnerability scan. It updates the scanning time of online devices and randomly alters the status of some nodes (e.g., simulates a device going offline or returning online).
- **URL**: `http://127.0.0.1:8000/api/scan`

#### 6. Vulnerabilities Dictionary (`GET /api/vulnerabilities`)
Returns the complete list of known CVE templates mapped in the audit engine.
- **URL**: `http://127.0.0.1:8000/api/vulnerabilities`

---

## Example Frontend Map/Telemetry Mapping

- **Latitude/Longitude**: Use to plot markers on a Map (Leaflet, Mapbox, Google Maps, OpenLayers).
- **Marker Color**: Set marker colors dynamically based on the device's `current_risk_score`:
  - `current_risk_score >= 9.0` 🔴 **Critical** (Red)
  - `7.0 <= current_risk_score < 9.0` 🟠 **High** (Orange)
  - `4.0 <= current_risk_score < 7.0` 🟡 **Medium** (Yellow)
  - `current_risk_score < 4.0` 🟢 **Low/Safe** (Green)
- **Telemetry Indicators**: Display the `status` flag (`Online`, `Offline`, `Maintenance`) alongside standard stats.
- **Isolation Response Action**: Bind a button on your frontend detail modal to call `POST /api/assets/{id}/isolate` to instantly isolate a device, and watch the risk indicators recalculate dynamically!
