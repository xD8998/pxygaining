const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
require('dotenv').config();

const app = express();
app.use(express.json());
app.use(cookieParser());

const pool = new Pool({ connectionString: process.env.DATABASE_URL });

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

// --- SIGN UP ---
app.post('/api/signup', async (req, res) => {
    const { username, password } = req.body;
    
    const error = validateUser(username, password);
    if (error) return res.status(400).json({ error });

    try {
        const userCount = await pool.query('SELECT COUNT(*) FROM users');
        const isFirstUser = userCount.rows[0].count === "0";
        
        const hashedPassword = await bcrypt.hash(password, 10);
        
        // If first user, they are Owner and Approved
        const newUser = await pool.query(
            'INSERT INTO users (username, password, is_approved, is_owner) VALUES ($1, $2, $3, $4) RETURNING *',
            [username, hashedPassword, isFirstUser, isFirstUser]
        );

        res.json({ message: isFirstUser ? "Owner account created." : "Account pending approval." });
    } catch (err) {
        res.status(400).json({ error: "Username already exists." });
    }
});

// --- LOGIN ---
app.post('/api/login', async (req, res) => {
    const { username, password } = req.body;
    const userResult = await pool.query('SELECT * FROM users WHERE username = $1', [username]);
    const user = userResult.rows[0];

    if (!user || !(await bcrypt.compare(password, user.password))) {
        return res.status(401).json({ error: "Invalid credentials" });
    }

    if (!user.is_approved) {
        return res.status(403).json({ error: "Waiting for approval from owner." });
    }

    const token = jwt.sign({ id: user.id, is_owner: user.is_owner }, process.env.JWT_SECRET, { expiresIn: '30d' });
    
    // Cookie expires in 30 days
    res.cookie('auth_token', token, { maxAge: 30 * 24 * 60 * 60 * 1000, httpOnly: true });
    res.json({ message: "Logged in", needsStarterCode: !user.is_owner });
});

// --- STARTER CODE VERIFICATION ---
// User must call this after login and every time they reopen the site
app.post('/api/verify-code', async (req, res) => {
    const token = req.cookies.auth_token;
    const { code } = req.body;
    if (!token) return res.status(401).json({ error: "Unauthenticated" });

    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const userResult = await pool.query('SELECT starter_code, is_owner FROM users WHERE id = $1', [decoded.id]);
    const user = userResult.rows[0];

    if (user.is_owner || user.starter_code === code) {
        res.json({ success: true });
    } else {
        res.status(403).json({ error: "Invalid Starter Code" });
    }
});

// --- HIDDEN REDIRECT ---
// The frontend calls this. The browser never sees the destination URL in the HTML.
app.get('/api/go/:id', async (req, res) => {
    const token = req.cookies.auth_token;
    if (!token) return res.redirect('/login');

    const result = await pool.query('SELECT actual_url FROM links WHERE id = $1', [req.params.id]);
    if (result.rows.length > 0) {
        res.redirect(result.rows[0].actual_url);
    } else {
        res.status(404).send("Link not found");
    }
});

// --- OWNER CONTROLS ---
app.post('/api/admin/approve', async (req, res) => {
    const { userId, rankId, starterCode } = req.body;
    // (Add middleware here to check if requester is_owner)
    await pool.query(
        'UPDATE users SET is_approved = true, rank_id = $1, starter_code = $2 WHERE id = $3',
        [rankId, starterCode, userId]
    );
    res.json({ message: "User approved and rank assigned" });
});

app.listen(process.env.PORT || 3000, () => console.log("Server running"));
