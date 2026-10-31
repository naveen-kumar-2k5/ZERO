<div align="center">

<img src="https://capsule-render.vercel.app/api?type=waving&color=0:0f2027,50:203a43,100:2c5364&height=220&section=header&text=ZERO&fontSize=90&fontColor=ffffff&animation=fadeIn&fontAlignY=38&desc=Detect%20%E2%80%A2%20Triage%20%E2%80%A2%20Respond&descSize=22&descAlignY=60" alt="ZERO banner" width="100%"/>

### 🛡️ A lightweight SOC dashboard & incident-response platform for Wazuh

<p>
  <img src="https://img.shields.io/badge/Python-3.10+-3776AB?style=for-the-badge&logo=python&logoColor=white" alt="Python"/>
  <img src="https://img.shields.io/badge/Flask-Backend-000000?style=for-the-badge&logo=flask&logoColor=white" alt="Flask"/>
  <img src="https://img.shields.io/badge/PostgreSQL-16-4169E1?style=for-the-badge&logo=postgresql&logoColor=white" alt="PostgreSQL"/>
  <img src="https://img.shields.io/badge/Wazuh-SIEM-005571?style=for-the-badge&logo=wazuh&logoColor=white" alt="Wazuh"/>
  <img src="https://img.shields.io/badge/Docker-Ready-2496ED?style=for-the-badge&logo=docker&logoColor=white" alt="Docker"/>
</p>

<p>
  <img src="https://img.shields.io/github/stars/naveen-kumar-2k5/ZERO?style=flat-square&color=yellow" alt="Stars"/>
  <img src="https://img.shields.io/github/forks/naveen-kumar-2k5/ZERO?style=flat-square&color=blue" alt="Forks"/>
  <img src="https://img.shields.io/github/last-commit/naveen-kumar-2k5/ZERO?style=flat-square&color=green" alt="Last commit"/>
  <img src="https://img.shields.io/badge/PRs-welcome-brightgreen?style=flat-square" alt="PRs welcome"/>
</p>

[✨ Features](#-features) •
[🏗️ Architecture](#️-architecture) •
[🚀 Quick Start](#-quick-start) •
[⚙️ Configuration](#️-configuration) •
[📡 API](#-api-overview) •
[🤝 Contributing](#-contributing)

</div>

---

## 📖 About

**ZERO** ingests security alerts from [Wazuh](https://wazuh.com/) through a webhook, stores them in PostgreSQL, and serves them in a clean web UI with live alert feeds, platform health, monitored endpoints, and an incident case manager driven by response playbooks.

> 💡 From raw alert to resolved case, all in one place.

---

## ✨ Features

| | Feature | Description |
|---|---|---|
| 📥 | **Webhook Receiver** | Accepts Wazuh alerts and normalises source IP, target user, MITRE technique/tactic and threat type |
| 🔄 | **Alert Poller** | Continuously syncs parsed alerts from the webhook into PostgreSQL |
| 📊 | **SOC Dashboard** | Severity breakdown, daily trend, top agents, top source IPs, category split, recent alerts |
| 🔎 | **Alert Feed** | Filter by severity, category, free-text search and time range |
| 🧠 | **Threat Classification** | Maps alerts into Brute Force, Privilege Escalation, File Integrity and Ransomware using threat type, rule IDs and MITRE ATT&CK families |
| 🖥️ | **Monitored Systems** | Live Wazuh agent inventory: status, OS, department, alerts today, last keep-alive |
| 💓 | **Platform Health** | Checks for Webhook API, UI, PostgreSQL and alert-sync freshness |
| 🗂️ | **Incident Cases** | Case lifecycle tracking with step-by-step response playbooks |
| 🔐 | **Auth & RBAC** | Session login, admin-only routes, password reset and audit log |
| 🐳 | **Dockerised** | Entire stack up with one command |

---

## 🏗️ Architecture

```mermaid
flowchart LR
    W[🛡️ Wazuh Manager]
    H[📥 webhook.py<br/>:5000]
    P[🔄 main.py<br/>Poller]
    D[(🐘 PostgreSQL 16)]
    A[🖥️ app.py<br/>Flask UI :5001]

    W -- "POST /webhook" --> H
    P -- "GET /api/v1/alerts" --> H
    P -- "INSERT" --> D
    A <-- "SQL" --> D
    W -- "REST API: agents & alerts" --> A
```

| Service | Entry point | Port | Purpose |
|:---|:---|:---:|:---|
| 🐘 `db` | PostgreSQL 16 | `5432` | Stores alerts, users, cases and audit data (`init.sql`) |
| 📥 `webhook` | `webhook.py` | `5000` | Receives and parses Wazuh alerts |
| 🔄 `poller` | `main.py` | n/a | Syncs alerts from the webhook into PostgreSQL |
| 🖥️ `app` | `app.py` | `5001` | Web UI, REST API, auth, cases and health checks |

---

## 📁 Project Structure

```text
ZERO/
├── 🐍 app.py              # Main Flask app: UI, REST API, auth, Wazuh integration
├── 📥 webhook.py          # Wazuh webhook receiver and alert parser
├── 🔄 main.py             # Poller: webhook → PostgreSQL
├── 🧩 models.py           # Data models
├── 🗄️ init.sql            # Database schema / seed data
├── 🎨 templates/          # Jinja2 templates (dashboard, alerts, systems, health, incidents, login)
├── 💅 static/css/         # Stylesheets
├── 🐳 Dockerfile
├── 🐙 docker-compose.yml
└── 📦 requirements.txt
```

---

## 🚀 Quick Start

### 📋 Prerequisites

- 🐳 [Docker](https://docs.docker.com/get-docker/) & Docker Compose **or** 🐍 Python 3.10+ with PostgreSQL 14+
- 🛡️ A running Wazuh manager with API access (default port `55000`)

### 🐳 Run with Docker

```bash
git clone https://github.com/naveen-kumar-2k5/ZERO.git
cd ZERO

# Review credentials and the Wazuh host first (see Configuration)
docker compose up -d --build
```

| 🌐 Service | URL |
|:---|:---|
| Dashboard / UI | http://localhost:5001 |
| Webhook receiver | http://localhost:5000 |

### 🔌 Connect Wazuh to ZERO

Add this to your Wazuh manager's `ossec.conf`:

```xml
<integration>
  <name>custom-zero</name>
  <hook_url>http://<ZERO_HOST>:5000/webhook</hook_url>
  <alert_format>json</alert_format>
</integration>
```

Then restart the manager: `systemctl restart wazuh-manager`

<details>
<summary><b>🛠️ Manual setup (without Docker)</b></summary>

<br/>

```bash
git clone https://github.com/naveen-kumar-2k5/ZERO.git
cd ZERO

python -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements.txt

# Create the database and load the schema
psql -U postgres -c "CREATE USER zero WITH PASSWORD 'your-password';"
psql -U postgres -c "CREATE DATABASE zerorespong_db OWNER zero;"
psql -U zero -d zerorespong_db -f init.sql

# Run each component in its own terminal
python webhook.py   # :5000
python main.py      # poller
python app.py       # :5001
```

</details>

---

## ⚙️ Configuration

All settings are read from environment variables.

<details>
<summary><b>🔧 Show all environment variables</b></summary>

<br/>

| Variable | Default | Description |
|:---|:---|:---|
| `SECRET_KEY` | `dev-only-secret-key-change-me` | Flask session secret ⚠️ change in production |
| `PG_HOST` | `localhost` | PostgreSQL host |
| `PG_PORT` | `5432` | PostgreSQL port |
| `PG_DB` | `zerorespong_db` | Database name |
| `PG_USER` | `zero` | Database user |
| `PG_PASSWORD` | n/a | Database password |
| `WAZUH_HOST` | `https://192.168.244.131:55000` | Wazuh API base URL |
| `WAZUH_USER` | `wazuh-wui` | Wazuh API user |
| `WAZUH_PASS` | n/a | Wazuh API password |
| `WEBHOOK_URL` | `http://127.0.0.1:5000` | Webhook service URL (health checks) |
| `UI_URL` | `http://127.0.0.1:5001` | UI service URL (health checks) |
| `POLLER_STALE_SEC` | `300` | Seconds before alert sync is marked stale |
| `API_URL` | n/a | Webhook alerts endpoint used by the poller |

</details>

> [!WARNING]
> Move credentials out of source code and `docker-compose.yml` into a `.env` file or a secrets manager, and rotate any credentials that have already been committed.

---

## 📡 API Overview

> [!NOTE]
> All `/api/v1/*` endpoints (except login and `/healthz`) require an authenticated session.

| Method | Endpoint | Description |
|:---:|:---|:---|
| ![POST](https://img.shields.io/badge/POST-49cc90?style=flat-square) | `/api/v1/auth/login` | Sign in with username and password |
| ![POST](https://img.shields.io/badge/POST-49cc90?style=flat-square) | `/api/v1/auth/logout` | Sign out |
| ![POST](https://img.shields.io/badge/POST-49cc90?style=flat-square) | `/api/v1/me/reset-password` | Change your own password |
| ![GET](https://img.shields.io/badge/GET-61affe?style=flat-square) | `/api/v1/alerts/feed` | Alert feed (`sev`, `category`, `q`, `from`, `to`, `limit`) |
| ![GET](https://img.shields.io/badge/GET-61affe?style=flat-square) | `/api/v1/dashboard` | Dashboard aggregates (`days` 1 to 30) |
| ![GET](https://img.shields.io/badge/GET-61affe?style=flat-square) | `/api/v1/systems` | Monitored systems from Wazuh agents |
| ![GET](https://img.shields.io/badge/GET-61affe?style=flat-square) | `/api/v1/health` | Component health checks |
| ![GET](https://img.shields.io/badge/GET-61affe?style=flat-square) | `/healthz` | Liveness probe (DB connectivity) |
| ![POST](https://img.shields.io/badge/POST-49cc90?style=flat-square) | `/webhook` *(port 5000)* | Wazuh alert ingestion |
| ![GET](https://img.shields.io/badge/GET-61affe?style=flat-square) | `/api/v1/alerts` *(port 5000)* | Parsed alerts held by the webhook |

### 🚦 Severity Mapping

| Wazuh Level | Severity |
|:---:|:---|
| `16+` | 🔴 Critical |
| `14 – 15` | 🟠 High |
| `12 – 13` | 🟡 Medium |
| `0 – 11` | 🟢 Low |

### 🎯 Threat Categories

| Key | Category | Icon |
|:---:|:---|:---:|
| `bf` | Brute Force | 🔨 |
| `pe` | Privilege Escalation | 🪜 |
| `fim` | File Integrity | 📄 |
| `ra` | Ransomware | 🔒 |

### 🧭 Incident Case Lifecycle

```mermaid
stateDiagram-v2
    [*] --> open
    open --> investigating
    investigating --> containing
    containing --> contained
    contained --> resolved
    investigating --> false_positive
    resolved --> [*]
    false_positive --> [*]
```

---

## 🗺️ Pages

| Route | Description |
|:---|:---|
| 🔑 `/login` | Sign in |
| 📊 `/` · `/dashboard` | SOC overview |
| 🚨 `/alerts` | Searchable alert feed |
| 🖥️ `/systems` | Monitored endpoints and servers |
| 💓 `/health` | Platform health |
| 🗂️ `/incidents` | Incident case list |
| 🔍 `/incidents/<id>` | Case detail and playbook |

---

## 🧰 Tech Stack

<div align="center">

<img src="https://skillicons.dev/icons?i=python,flask,postgres,docker,html,css,linux&theme=dark" alt="Tech stack"/>

</div>

---

## 🤝 Contributing

Contributions are welcome! 🎉

1. 🍴 Fork the repository
2. 🌿 Create a feature branch: `git checkout -b feature/my-feature`
3. 💾 Commit your changes: `git commit -m "Add my feature"`
4. 📤 Push the branch: `git push origin feature/my-feature`
5. 🔃 Open a Pull Request

---

## 📜 License

No license has been specified yet. Add a `LICENSE` file (for example MIT) to define how others may use this project.

---

<div align="center">

### 👨‍💻 Author

**Naveen Kumar** · [@naveen-kumar-2k5](https://github.com/naveen-kumar-2k5)

⭐ If you find ZERO useful, consider giving it a star!

<img src="https://capsule-render.vercel.app/api?type=waving&color=0:2c5364,50:203a43,100:0f2027&height=120&section=footer" alt="footer" width="100%"/>

</div>
