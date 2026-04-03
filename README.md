<img width="942" height="393" alt="dashbord1" src="https://github.com/user-attachments/assets/4802e6b1-4a74-4aa2-8c7f-b7277748dae3" />
<img width="956" height="382" alt="dashborad2" src="https://github.com/user-attachments/assets/a9fc5291-177a-41b6-b8d9-642d3fbcbcc3" />
![CI](https://github.com/YOUR_USERNAME/YOUR_REPO/actions/workflows/main.yml/badge.svg)
# 🚀 NetScope: Real-Time Network Traffic Monitoring & SIEM System

---

## 🧠 Project Overview

**NetScope** is a **real-time network traffic monitoring and SIEM (Security Information and Event Management) system** that captures, analyzes, and visualizes network packets.

It simulates how real-world cybersecurity tools:

* 📡 Monitor network traffic
* 🔍 Analyze protocols
* ⚠️ Detect suspicious activity
* 📊 Provide actionable insights via dashboards

---

## 🔥 Key Features

* 📡 **Real-Time Packet Capture using Tshark (Wireshark CLI)**
* 🧠 **Protocol Analysis & OSI Layer Mapping**
* ⚠️ **Suspicious Traffic Detection**
* 🔐 **JWT-Based Authentication System**
* ☁️ **Cloud Database Integration (Supabase)**
* 🚀 **Backend Deployment on Render**
* 🌐 **Frontend Dashboard (React + Vercel)**
* 📊 **Live Charts & Traffic Statistics**

---

## 📡 Packet Capture Engine (Tshark)

NetScope uses **Tshark (Wireshark CLI)** to capture live network packets.

### 🔧 How It Works

* Captures packets from network interface
* Extracts:

  * 🌐 Source IP
  * 🌐 Destination IP
  * 🔁 Protocol
  * 🌍 Website (DNS/HTTP)

---

### ⚙️ Tshark Command

```bash
tshark -i <interface> -l -T fields \
-e ip.src -e ip.dst -e _ws.col.Protocol \
-e dns.qry.name -e http.host
```

---

### 🔄 Data Flow

```text
Tshark → capture.js → Backend API → Supabase → Frontend Dashboard
```

---

### ⚠️ Limitations

* Requires admin/root access
* Runs locally (not supported on cloud platforms)
* Needs correct network interface configuration

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

## 🛠️ Tech Stack

### 🔹 Backend

* Node.js
* Express.js
* PostgreSQL (Supabase)
* JWT Authentication

### 🔹 Frontend

* React.js
* Recharts (Charts)

### 🔹 Tools & Deployment

* Tshark (Packet Capture)
* Render (Backend)
* Vercel (Frontend)
* Supabase (Database)

---

## ⚙️ How It Works (Step-by-Step)

### 1️⃣ Packet Capture

* Tshark captures live traffic
* Extracts IPs, protocol, domain

---

### 2️⃣ Data Processing

* Protocol normalization (HTTP, TCP, TLS)
* OSI Layer Mapping:

  * HTTP → Layer 7
  * TLS → Layer 6
  * TCP → Layer 4

---

### 3️⃣ Threat Detection ⚠️

* HTTP traffic flagged
* Unknown protocols flagged
* Suspicious packets stored

---

### 4️⃣ Backend API

* Built with Express.js
* Handles:

  * Data storage
  * Filtering
  * Analytics

---

### 5️⃣ Database (Supabase)

* PostgreSQL cloud DB
* Stores:

  * Packet logs
  * Protocol data
  * Threat flags

---

### 6️⃣ Frontend Dashboard

* Displays:

  * 📊 Statistics
  * 📡 Packet logs
  * ⚠️ Alerts
* Auto-refresh every 5 seconds

---

### 7️⃣ Deployment 🚀

* Backend → Render
* Frontend → Vercel
* Database → Supabase

---

## 📊 Screenshots

### 📊 Dashboard

<img src="./images/dashboard.png" width="800"/>

### 🔐 Login Page

<img src="./images/login.png" width="500"/>

---

## 🔐 Security Features

* 🔑 JWT Authentication
* 🔒 Password hashing (bcrypt)
* 🔐 Environment variables for secrets
* ☁️ SSL-secured DB connection

---

## 🚀 API Endpoints

| Method | Endpoint        | Description    |
| ------ | --------------- | -------------- |
| POST   | /login          | Login          |
| POST   | /register       | Register       |
| POST   | /packets        | Insert packet  |
| GET    | /packets        | Get packets    |
| GET    | /packets/filter | Filter traffic |
| GET    | /packets/stats  | Statistics     |

---

## 🧪 How to Run Locally

### 🔹 Backend

```bash
npm install
node server.js
```

---

### 🔹 Frontend

```bash
cd netscope-frontend
npm install
npm start
```

---

### 🔹 Environment Variables

```env
DATABASE_URL=your_database_url
SUPABASE_URL=your_supabase_url
SUPABASE_KEY=your_supabase_key
```

---

## 🧠 What I Learned

* ⚙️ Full-stack development
* 🔐 Secure backend design
* ☁️ Cloud deployment
* 🧠 Network traffic analysis
* 📡 Packet inspection using Tshark
* 🔍 Debugging real-world issues

---

## 💼 Use Case

This system simulates:

* SIEM platforms
* Intrusion Detection Systems (IDS)
* Network monitoring tools used in enterprises

---

## 🚀 Future Improvements

* 🔔 Real-time alert system
* 📈 Advanced analytics dashboard
* 🤖 AI-based anomaly detection
* 🌍 Multi-device monitoring

---

## 👨‍💻 Author

**Rajesh**

---

## ⭐ Support

If you like this project, give it a ⭐ on GitHub!

---

