const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const cors = require('cors'); // Added CORS
require('dotenv').config();

const app = express();

// --- MIDDLEWARE ---
// This allows your HTML page to talk to this backend
app.use(cors({
    origin: true, // Allows any origin to connect (Good for testing)
    credentials: true // Allows cookies to be sent
}));
app.use(express.json());
app.use(cookieParser());

// Database connection
const pool = new Pool({ 
    connectionString: process.env.DATABASE_URL,
    ssl: { rejectUnauthorized: false } // Required for Railway/Postgres
});

// --- VALIDATION HELPER ---
const validateUser = (username, password) => {
    const userRegex = /^[a-zA-Z0-9_]+$/;
    if (!username || username.length > 16 || !userRegex.test(username)) {
        return "Username must be 1-16 chars, no spaces, only letters, numbers, and _";
    }
    if (!password || password.length > 30 || password.includes(" ")) {
        return "Password must be max 30 chars and contain no spaces";
    }
    return null;
};

// --- ROUTES ---

app.get('/', (req, res) => res.send("Server is Online")); // Health check

// --- UPDATED SIGNUP ---
app.post('/api/signup', async (req, res) => {
    const { username, password } = req.body;
    const error = validateUser(username, password);
    if (error) return res.status(400).json({ error });

    try {
        const userCount = await pool.query('SELECT COUNT(*) FROM users');
        const isFirstUser = userCount.rows[0].count === "0";
        const hashedPassword = await bcrypt.hash(password, 10);
        
        await pool.query(
            'INSERT INTO users (username, password, is_approved, is_owner) VALUES ($1, $2, $3, $4)',
            [username, hashedPassword, isFirstUser, isFirstUser]
        );

        res.json({ 
            message: isFirstUser ? "Owner account created! Please Login." : "Account pending approval.",
            isFirstUser: isFirstUser 
        });
    } catch (err) {
        res.status(400).json({ error: "Username already exists." });
    }
});

// --- UPDATED LOGIN ---
app.post('/api/login', async (req, res) => {
    const { username, password } = req.body;
    try {
        const userResult = await pool.query('SELECT * FROM users WHERE username = $1', [username]);
        const user = userResult.rows[0];

        if (!user || !(await bcrypt.compare(password, user.password))) {
            return res.status(401).json({ error: "Invalid credentials" });
        }

        if (!user.is_approved) {
            return res.status(403).json({ error: "Your account is still pending approval." });
        }

        const token = jwt.sign({ id: user.id, is_owner: user.is_owner }, process.env.JWT_SECRET, { expiresIn: '30d' });
        
        res.cookie('auth_token', token, { 
            maxAge: 30 * 24 * 60 * 60 * 1000, 
            httpOnly: true, 
            secure: true, 
            sameSite: 'none' 
        });

        // Send back info so Frontend knows what to show
        res.json({ 
            message: "Logged in", 
            isOwner: user.is_owner, 
            username: user.username 
        });
    } catch (err) {
        res.status(500).json({ error: "Server Error" });
    }
});

// STARTER CODE VERIFICATION
app.post('/api/verify-code', async (req, res) => {
    const token = req.cookies.auth_token;
    const { code } = req.body;
    if (!token) return res.status(401).json({ error: "Unauthenticated" });

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        const userResult = await pool.query('SELECT starter_code, is_owner FROM users WHERE id = $1', [decoded.id]);
        const user = userResult.rows[0];

        if (user.is_owner || user.starter_code === code) {
            res.json({ success: true });
        } else {
            res.status(403).json({ error: "Invalid Starter Code" });
        }
    } catch (e) {
        res.status(401).json({ error: "Invalid Session" });
    }
});

// LISTEN ON 0.0.0.0 (REQUIRED FOR RAILWAY)
const PORT = process.env.PORT || 3000;
app.listen(PORT, '0.0.0.0', () => {
    console.log(`Server is running on port ${PORT}`);
});
