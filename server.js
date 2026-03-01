const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const cors = require('cors');
require('dotenv').config();

const app = express();

// Middleware
app.use(cors({ origin: true, credentials: true }));
app.use(express.json());
app.use(cookieParser());

const pool = new Pool({ 
    connectionString: process.env.DATABASE_URL,
    ssl: { rejectUnauthorized: false } 
});

// Validation
const validateUser = (username, password) => {
    const userRegex = /^[a-zA-Z0-9_]+$/;
    if (!username || username.length > 16 || !userRegex.test(username)) 
        return "Username: 1-16 chars, letters/numbers/_ only, no spaces.";
    if (!password || password.length > 30 || password.includes(" ")) 
        return "Password: Max 30 chars, no spaces.";
    return null;
};

// --- AUTH ROUTES ---

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
        res.json({ message: isFirstUser ? "Owner account created!" : "Waiting for owner approval.", isFirstUser });
    } catch (err) {
        res.status(400).json({ error: "Username already exists." });
    }
});

app.post('/api/login', async (req, res) => {
    const { username, password } = req.body;
    try {
        const result = await pool.query('SELECT * FROM users WHERE username = $1', [username]);
        const user = result.rows[0];
        if (!user || !(await bcrypt.compare(password, user.password))) return res.status(401).json({ error: "Invalid credentials" });
        if (!user.is_approved) return res.status(403).json({ error: "Account not approved yet." });

        const token = jwt.sign({ id: user.id, is_owner: user.is_owner }, process.env.JWT_SECRET, { expiresIn: '30d' });
        res.cookie('auth_token', token, { maxAge: 2592000000, httpOnly: true, secure: true, sameSite: 'none' });
        res.json({ username: user.username, isOwner: user.is_owner });
    } catch (err) { res.status(500).json({ error: "Server Error" }); }
});

app.post('/api/verify-code', async (req, res) => {
    const { code } = req.body;
    const token = req.cookies.auth_token;
    if (!token) return res.status(401).send();
    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        const user = (await pool.query('SELECT * FROM users WHERE id = $1', [decoded.id])).rows[0];
        if (user.is_owner || user.starter_code === code) return res.json({ success: true });
        res.status(403).json({ error: "Invalid Code" });
    } catch (e) { res.status(401).send(); }
});

// --- LINK ROUTES ---

app.get('/api/links', async (req, res) => {
    const result = await pool.query('SELECT id, button_name FROM links');
    res.json(result.rows);
});

app.get('/api/go/:id', async (req, res) => {
    const result = await pool.query('SELECT actual_url FROM links WHERE id = $1', [req.params.id]);
    if (result.rows[0]) res.redirect(result.rows[0].actual_url);
    else res.status(404).send("Not found");
});

// --- ADMIN ROUTES ---

app.get('/api/admin/pending', async (req, res) => {
    const token = req.cookies.auth_token;
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    if (!decoded.is_owner) return res.status(403).send();
    const result = await pool.query('SELECT id, username FROM users WHERE is_approved = false');
    res.json(result.rows);
});

app.post('/api/admin/approve', async (req, res) => {
    const { userId, rankName, starterCode } = req.body;
    const rank = await pool.query('INSERT INTO ranks (name) VALUES ($1) ON CONFLICT (name) DO UPDATE SET name=$1 RETURNING id', [rankName]);
    await pool.query('UPDATE users SET is_approved = true, rank_id = $1, starter_code = $2 WHERE id = $3', [rank.rows[0].id, starterCode, userId]);
    res.json({ success: true });
});

app.post('/api/admin/links', async (req, res) => {
    const { name, url } = req.body;
    await pool.query('INSERT INTO links (button_name, actual_url) VALUES ($1, $2)', [name, url]);
    res.json({ success: true });
});

app.listen(process.env.PORT || 3000, '0.0.0.0', () => console.log("Server Live"));
