import React, { useEffect, useState } from "react";
import { PieChart, Pie, Cell, Tooltip, Legend } from "recharts";

function App() {
  const [packets, setPackets] = useState([]);
  const [stats, setStats] = useState({
    total_packets: 0,
    suspicious_packets: 0,
    http_packets: 0
  });

  const [token, setToken] = useState(localStorage.getItem("token"));
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");

  // 🔐 LOGIN
  const handleLogin = () => {
    fetch("http://localhost:3000/login", {
      method: "POST",
      headers: {
        "Content-Type": "application/json"
      },
      body: JSON.stringify({ username, password })
    })
      .then(res => res.json())
      .then(data => {
        if (data.token) {
          localStorage.setItem("token", data.token);
          setToken(data.token);
        } else {
          alert("Login failed ❌");
        }
      })
      .catch(err => console.error(err));
  };

  // 🔓 LOGOUT
  const handleLogout = () => {
    localStorage.removeItem("token");
    setToken(null);
  };

  // 🔹 Fetch packets
  const fetchPackets = () => {
    fetch("http://localhost:3000/packets", {
      headers: {
        Authorization: "Bearer " + token
      }
    })
      .then(res => res.json())
      .then(data => setPackets(data || []))
      .catch(err => console.error(err));
  };

  // 🔹 Fetch suspicious
  const fetchSuspicious = () => {
    fetch("http://localhost:3000/packets/filter?suspicious=true", {
      headers: {
        Authorization: "Bearer " + token
      }
    })
      .then(res => res.json())
      .then(data => setPackets(data || []));
  };

  // 🔹 Fetch stats
  const fetchStats = () => {
    fetch("http://localhost:3000/packets/stats", {
      headers: {
        Authorization: "Bearer " + token
      }
    })
      .then(res => res.json())
      .then(data => setStats(data || {}));
  };

  // 🔄 Auto refresh (only if logged in)
  useEffect(() => {
    if (!token) return;

    fetchPackets();
    fetchStats();

    const interval = setInterval(() => {
      fetchPackets();
      fetchStats();
    }, 5000);

    return () => clearInterval(interval);
  }, [token]);

  // 📊 Chart data
  const chartData = [
    {
      name: "Safe",
      value: (stats.total_packets || 0) - (stats.suspicious_packets || 0)
    },
    {
      name: "Suspicious",
      value: stats.suspicious_packets || 0
    }
  ];

  // 🔐 LOGIN SCREEN
  if (!token) {
    return (
      <div style={{ padding: "40px", textAlign: "center" }}>
        <h2>🔐 NetScope Login</h2>

        <input
          placeholder="Username"
          onChange={e => setUsername(e.target.value)}
          style={inputStyle}
        />
        <br />

        <input
          type="password"
          placeholder="Password"
          onChange={e => setPassword(e.target.value)}
          style={inputStyle}
        />
        <br />

        <button onClick={handleLogin} style={btnStyle}>
          Login
        </button>
      </div>
    );
  }

  // 🚀 DASHBOARD
  return (
    <div style={{ padding: "20px", fontFamily: "Arial" }}>
      
      <h1>🚀 NetScope Dashboard</h1>

      <button onClick={handleLogout} style={{ ...btnStyle, backgroundColor: "red" }}>
        Logout
      </button>

      {/* 🔥 STATS */}
      <div style={{ display: "flex", gap: "20px", marginBottom: "20px" }}>
        <div style={cardStyle}>
          <h3>Total Packets</h3>
          <p>{stats.total_packets}</p>
        </div>

        <div style={cardStyle}>
          <h3>Suspicious</h3>
          <p style={{ color: "red" }}>{stats.suspicious_packets}</p>
        </div>

        <div style={cardStyle}>
          <h3>HTTP Traffic</h3>
          <p>{stats.http_packets}</p>
        </div>
      </div>

      {/* 📊 CHART */}
      <PieChart width={400} height={300}>
        <Pie
          data={chartData}
          dataKey="value"
          cx="50%"
          cy="50%"
          outerRadius={100}
          label
        >
          <Cell fill="green" />
          <Cell fill="red" />
        </Pie>
        <Tooltip />
        <Legend />
      </PieChart>

      {/* 🔘 BUTTONS */}
      <div style={{ marginBottom: "20px" }}>
        <button onClick={fetchPackets} style={btnStyle}>All Traffic</button>
        <button onClick={fetchSuspicious} style={btnStyle}>
          Suspicious Only ⚠️
        </button>
      </div>

      {/* 📋 TABLE */}
      <table border="1" cellPadding="10" style={{ width: "100%" }}>
        <thead>
          <tr>
            <th>ID</th>
            <th>Source IP</th>
            <th>Destination IP</th>
            <th>Protocol</th>
            <th>OSI Layer</th>
            <th>Website 🌐</th>
            <th>Status</th>
          </tr>
        </thead>

        <tbody>
          {packets.map(packet => (
            <tr key={packet.id}>
              <td>{packet.id}</td>
              <td>{packet.source_ip}</td>
              <td>{packet.destination_ip}</td>
              <td>{packet.protocol}</td>
              <td>{packet.osi_layer}</td>
              <td>{packet.website || "—"}</td>
              <td>
                {packet.is_suspicious ? "⚠️ Suspicious" : "✅ Safe"}
              </td>
            </tr>
          ))}
        </tbody>
      </table>

    </div>
  );
}

// 🎨 Styles
const cardStyle = {
  padding: "15px",
  border: "1px solid #ccc",
  borderRadius: "10px",
  width: "150px",
  textAlign: "center"
};

const btnStyle = {
  padding: "10px 15px",
  margin: "10px",
  cursor: "pointer",
  borderRadius: "5px",
  border: "none",
  backgroundColor: "#007bff",
  color: "white"
};

const inputStyle = {
  padding: "10px",
  margin: "10px",
  width: "200px"
};

export default App;