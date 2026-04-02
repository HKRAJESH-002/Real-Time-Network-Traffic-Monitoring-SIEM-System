<img width="942" height="393" alt="dashbord1" src="https://github.com/user-attachments/assets/4802e6b1-4a74-4aa2-8c7f-b7277748dae3" />
<img width="956" height="382" alt="dashborad2" src="https://github.com/user-attachments/assets/a9fc5291-177a-41b6-b8d9-642d3fbcbcc3" />
# 🚀 NetScope: Real-Time Network Traffic Monitoring & SIEM System

---

## 🧠 Project Overview

NetScope is a **real-time network traffic monitoring and SIEM (Security Information and Event Management) system** designed to capture, analyze, and visualize network packets.

It helps in:

* 📡 Monitoring live network traffic
* 🧠 Mapping protocols to OSI layers
* ⚠️ Detecting suspicious activities
* 📊 Visualizing data in a dashboard

---

## 🔥 Key Features

* 📡 **Real-Time Packet Capture** using Tshark
* 🧠 **Protocol Analysis & OSI Layer Mapping**
* ⚠️ **Suspicious Traffic Detection**
* 🔐 **JWT Authentication System**
* ☁️ **Cloud Database Integration (Supabase)**
* 🚀 **Live Backend Deployment (Render)**
* 🌐 **Frontend Dashboard (React + Vercel)**
* 📊 **Live Charts & Traffic Statistics**

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
* Recharts (Data Visualization)

### 🔹 Tools & Deployment

* Tshark (Packet Capture)
* Render (Backend Hosting)
* Vercel (Frontend Hosting)
* Supabase (Cloud Database)

---

## ⚙️ How It Works (Step-by-Step)

### 1️⃣ Packet Capture

* Tshark captures real-time packets from network interface
* Extracts:

  * Source IP 🌐
  * Destination IP 🌐
  * Protocol 🔁
  * Website (DNS/HTTP)

---

### 2️⃣ Data Processing

* Protocols normalized (HTTP, TCP, TLS)
* OSI Layer mapping:

  * HTTP → Layer 7
  * TLS → Layer 6
  * TCP → Layer 4

---

### 3️⃣ Threat Detection ⚠️

* HTTP traffic marked as suspicious
* Unknown protocols flagged
* Suspicious flag stored in DB

---

### 4️⃣ Backend API

* REST API built using Express.js
* Routes:

  * `/packets` → store & fetch data
  * `/packets/filter` → filter suspicious traffic
  * `/packets/stats` → analytics
  * `/login` → authentication

---

### 5️⃣ Database (Supabase)

* PostgreSQL cloud database
* Stores:

  * packet data
  * protocol info
  * threat flags

---

### 6️⃣ Frontend Dashboard

* Displays:

  * 📊 Traffic statistics
  * 📡 Packet logs
  * ⚠️ Suspicious alerts
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
* 🔒 Secure password hashing (bcrypt)
* 🔐 Environment variables for secrets
* ☁️ SSL-secured database connection

---

## 🚀 API Endpoints

| Method | Endpoint        | Description     |
| ------ | --------------- | --------------- |
| POST   | /login          | User login      |
| POST   | /register       | Register user   |
| POST   | /packets        | Insert packet   |
| GET    | /packets        | Get all packets |
| GET    | /packets/filter | Filter packets  |
| GET    | /packets/stats  | Get statistics  |

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
* ☁️ Cloud deployment (Render + Vercel)
* 🧠 Network traffic analysis
* 📡 Packet inspection using Tshark
* 🔍 Debugging real-world issues

---

## 💼 Use Case

This system simulates:

* SIEM tools
* Intrusion Detection Systems (IDS)
* Network monitoring tools used in real companies

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

## ⭐ If you like this project

Give it a ⭐ on GitHub and support!

---
