const express = require('express');
const { Pool } = require('pg');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();

// 🔐 ENV
const SECRET_KEY = process.env.SECRET_KEY || "netscope_secret_key";

// ✅ Middleware
app.use(cors());
app.use(express.json());

// 🔗 DB CONNECTION (Supabase + Render FIX)
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: {
        rejectUnauthorized: false
    }
});

// ✅ DB TEST
pool.connect()
    .then(() => console.log("✅ DB Connected"))
    .catch(err => console.error("❌ DB Error:", err.message));

// ==============================
// 🔐 AUTH ROUTES
// ==============================

// REGISTER
app.post('/register', async (req, res) => {
    try {
        const { username, password } = req.body;

        if (!username || !password) {
            return res.status(400).json({ error: "Missing fields" });
        }

        const hashedPassword = await bcrypt.hash(password, 10);

        await pool.query(
            'INSERT INTO users (username, password) VALUES ($1, $2)',
            [username, hashedPassword]
        );

        res.json({ message: "User registered ✅" });

    } catch (err) {
        console.error(err.message);
        res.status(500).json({ error: "User exists or DB error" });
    }
});

// LOGIN
app.post('/login', async (req, res) => {
    try {
        const { username, password } = req.body;

        const result = await pool.query(
            'SELECT * FROM users WHERE username = $1',
            [username]
        );

        if (result.rows.length === 0) {
            return res.status(401).json({ error: "User not found" });
        }

        const user = result.rows[0];

        const isMatch = await bcrypt.compare(password, user.password);

        if (!isMatch) {
            return res.status(401).json({ error: "Invalid password" });
        }

        const token = jwt.sign(
            { id: user.id, username: user.username },
            SECRET_KEY,
            { expiresIn: '1h' }
        );

        res.json({ token });

    } catch (err) {
        console.error(err.message);
        res.status(500).json({ error: "Login error" });
    }
});

// ==============================
// 🔐 AUTH MIDDLEWARE
// ==============================

const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) return res.status(401).json({ error: "No token" });

    jwt.verify(token, SECRET_KEY, (err, user) => {
        if (err) return res.status(403).json({ error: "Invalid token" });

        req.user = user;
        next();
    });
};

// ==============================
// 🚀 ROUTES
// ==============================

// Health check (IMPORTANT for Render)
app.get('/', (req, res) => {
    res.send('🚀 NetScope Backend Running');
});

// INSERT PACKET
app.post('/packets', async (req, res) => {
    try {
        const { source_ip, destination_ip, protocol, website } = req.body;

        if (!source_ip || !destination_ip || !protocol) {
            return res.status(400).json({ error: "Invalid packet data" });
        }

        const cleanProtocol = protocol.trim().toUpperCase();

        let osi_layer = '';
        let is_suspicious = false;

        if (['HTTP', 'HTTPS', 'DNS'].includes(cleanProtocol)) {
            osi_layer = 'Layer 7 (Application)';
        } 
        else if (cleanProtocol.includes('TLS') || cleanProtocol === 'SSL') {
            osi_layer = 'Layer 6 (Presentation)';
        } 
        else if (['TCP', 'UDP'].includes(cleanProtocol)) {
            osi_layer = 'Layer 4 (Transport)';
        } 
        else {
            osi_layer = 'Unknown';
        }

        if (cleanProtocol === 'HTTP' || osi_layer === 'Unknown') {
            is_suspicious = true;
        }

        const result = await pool.query(
            `INSERT INTO packets 
            (source_ip, destination_ip, protocol, osi_layer, is_suspicious, website) 
            VALUES ($1, $2, $3, $4, $5, $6) RETURNING *`,
            [source_ip, destination_ip, cleanProtocol, osi_layer, is_suspicious, website || null]
        );

        res.json(result.rows[0]);

    } catch (err) {
        console.error(err.message);
        res.status(500).json({ error: "Insert error" });
    }
});

// GET ALL (⚠️ removed auth for frontend ease)
app.get('/packets', async (req, res) => {
    try {
        const result = await pool.query('SELECT * FROM packets ORDER BY id DESC');
        res.json(result.rows);
    } catch (err) {
        res.status(500).json({ error: "Fetch error" });
    }
});

// FILTER
app.get('/packets/filter', async (req, res) => {
    try {
        const { protocol, suspicious } = req.query;

        let query = 'SELECT * FROM packets WHERE 1=1';
        let values = [];

        if (protocol) {
            values.push(protocol.toUpperCase());
            query += ` AND protocol = $${values.length}`;
        }

        if (suspicious !== undefined) {
            values.push(suspicious === 'true');
            query += ` AND is_suspicious = $${values.length}`;
        }

        const result = await pool.query(query, values);
        res.json(result.rows);

    } catch (err) {
        res.status(500).json({ error: "Filter error" });
    }
});

// STATS
app.get('/packets/stats', async (req, res) => {
    try {
        const total = await pool.query('SELECT COUNT(*) FROM packets');
        const suspicious = await pool.query('SELECT COUNT(*) FROM packets WHERE is_suspicious = true');

        res.json({
            total_packets: Number(total.rows[0].count),
            suspicious_packets: Number(suspicious.rows[0].count)
        });

    } catch (err) {
        res.status(500).json({ error: "Stats error" });
    }
});

// ==============================
// 🚀 START SERVER
// ==============================

const PORT = process.env.PORT || 10000;

app.listen(PORT, () => {
    console.log(`🚀 Server running on port ${PORT}`);
});
