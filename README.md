<img width="942" height="393" alt="dashbord1" src="https://github.com/user-attachments/assets/4802e6b1-4a74-4aa2-8c7f-b7277748dae3" />
<img width="956" height="382" alt="dashborad2" src="https://github.com/user-attachments/assets/a9fc5291-177a-41b6-b8d9-642d3fbcbcc3" />
# 🚀 NetScope: Real-Time Network Traffic Monitoring & SIEM System

![CI](https://github.com/YOUR_USERNAME/YOUR_REPO/actions/workflows/main.yml/badge.svg)

---

## 🧠 Project Overview

**NetScope** is a real-time **Network Traffic Monitoring and SIEM (Security Information and Event Management) system** designed to capture, analyze, and visualize network packets.

It simulates real-world cybersecurity tools used in enterprises for:

* 📡 Monitoring network traffic
* 🔍 Protocol analysis
* ⚠️ Suspicious activity detection
* 📊 Real-time dashboards and analytics

---

## 🔥 Key Features

* 📡 Real-time packet capture using Tshark
* 🧠 Protocol analysis with OSI layer mapping
* ⚠️ Suspicious traffic detection
* 🔐 JWT-based authentication system
* ☁️ Cloud database integration (Supabase)
* 🚀 Backend deployed on Render
* 🌐 Frontend dashboard (React + Vercel)
* 📊 Live charts and traffic statistics
* 🔄 CI/CD pipeline using GitHub Actions

---

## 🏗️ System Architecture

```text
Tshark (Local Machine)
        ↓
capture.js (Node.js)
        ↓
Backend API (Render)
        ↓
Supabase PostgreSQL Database
        ↓
Frontend Dashboard (Vercel)
```

---

## 📡 Packet Capture Engine

NetScope uses **Tshark (Wireshark CLI)** to capture live network packets.

### ⚙️ Command

```bash
tshark -i <interface> -l -T fields \
-e ip.src -e ip.dst -e _ws.col.Protocol \
-e dns.qry.name -e http.host
```

### 🔄 Data Flow

```text
Tshark → capture.js → Backend → Supabase → Frontend
```

### ⚠️ Limitations

* Requires admin/root access
* Runs locally (not supported in cloud CI/CD)
* Needs correct network interface

---

## 🛠️ Tech Stack

### 🔹 Backend

* Node.js
* Express.js
* PostgreSQL (Supabase)
* JWT Authentication

### 🔹 Frontend

* React.js
* Recharts

### 🔹 Deployment & Tools

* Tshark
* Render
* Vercel
* Supabase
* GitHub Actions (CI/CD)

---

## ⚙️ How It Works

1. 📡 Capture packets using Tshark
2. 🧠 Process and normalize protocols
3. ⚠️ Detect suspicious traffic
4. 🗄️ Store data in Supabase
5. 📊 Display insights on dashboard
6. 🔄 Auto-update every 5 seconds

---

## 🔐 Security Features

* 🔑 JWT Authentication
* 🔒 Password hashing (bcrypt)
* 🔐 Environment variables for secrets
* ☁️ Secure database connection

---

## 🔄 CI/CD Pipeline

This project uses **GitHub Actions** to automate testing, build, and security checks.

### 🚀 Pipeline Steps

* Checkout code
* Setup Node.js
* Install dependencies
* Run backend health check
* Build frontend
* Perform security audit

### ⚙️ Workflow File

```yaml
name: NetScope CI/CD

on:
  push:
    branches: ["main"]

jobs:
  build:
    runs-on: ubuntu-latest

    steps:
    - name: Checkout Code
      uses: actions/checkout@v3

    - name: Setup Node.js
      uses: actions/setup-node@v3
      with:
        node-version: '18'

    - name: Install Backend Dependencies
      run: npm install

    - name: Run Backend Server Check
      run: node server.js & sleep 5

    - name: Build Frontend
      run: |
        cd netscope-frontend
        npm install
        npm run build

    - name: Security Audit
      run: npm audit
```

---

## 🧪 Local Setup

### 🔹 Backend

```bash
npm install
node server.js
```

### 🔹 Frontend

```bash
cd netscope-frontend
npm install
npm start
```

---

## 🔐 Environment Variables

```env
DATABASE_URL=your_database_url
SUPABASE_URL=your_supabase_url
SUPABASE_KEY=your_supabase_key
```

---

## 📊 Screenshots

### 📊 Dashboard

<img src="./images/dashboard.png" width="800"/>

### 🔐 Login Page

<img src="./images/login.png" width="500"/>

---

## 🚀 Deployment

* Backend → Render
* Frontend → Vercel
* Database → Supabase

---

## 📡 API Endpoints

| Method | Endpoint        | Description    |
| ------ | --------------- | -------------- |
| POST   | /login          | Login          |
| POST   | /register       | Register       |
| POST   | /packets        | Insert packet  |
| GET    | /packets        | Get packets    |
| GET    | /packets/filter | Filter traffic |
| GET    | /packets/stats  | Statistics     |

---

## 💼 Use Case

This system simulates:

* SIEM platforms
* Intrusion Detection Systems (IDS)
* Enterprise network monitoring tools

---

## 🧠 What I Learned

* Full-stack development
* Secure backend design
* CI/CD pipeline implementation
* Cloud deployment
* Network traffic analysis
* Debugging real-world issues

---

## 🚀 Future Improvements

* 🔔 Real-time alerts (Email/Telegram)
* 🤖 AI-based anomaly detection
* 📈 Advanced analytics
* 🌍 Multi-device monitoring

---

## 👨‍💻 Author

**Rajesh**

---

## ⭐ Support

If you like this project, give it a ⭐ on GitHub!

---


