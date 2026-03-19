// ═══════════════════════════════════════════════════════════════
// TEST FILE: clean_node.js
// EXPECTED: 0 findings (ZERO false positives)
// Every pattern here LOOKS dangerous but is actually safe.
// ═══════════════════════════════════════════════════════════════

const express = require("express");
const { execFile } = require("child_process");
const mysql = require("mysql");
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");

const app = express();
app.use(express.json());


// SAFE: Parameterized query
app.get("/user", (req, res) => {
    const id = req.query.id;
    const db = mysql.createConnection({
        host: "localhost",
        user: "root",
        database: "app"
    });
    db.query("SELECT * FROM users WHERE id = ?", [id], (err, rows) => {
        res.json(rows);
    });
});


// SAFE: execFile with array args — not command injection
app.get("/ping", (req, res) => {
    const host = req.query.host;
    execFile("ping", ["-c", "4", host], (err, stdout) => {
        res.send(stdout);
    });
});


// SAFE: textContent not innerHTML — not XSS
app.get("/search", (req, res) => {
    const query = req.query.q;
    res.send(`
        <html><body>
        <div id="results"></div>
        <script>
            document.getElementById("results").textContent = ${JSON.stringify(query)};
        </script>
        </body></html>
    `);
});


// SAFE: Path validation — not path traversal
app.get("/download", (req, res) => {
    const filename = req.query.file;
    const base = path.resolve("/uploads");
    const full = path.resolve(path.join(base, filename));
    if (!full.startsWith(base + path.sep)) {
        return res.status(403).send("Forbidden");
    }
    res.sendFile(full);
});


// SAFE: Environment variable — not hardcoded secret
const JWT_SECRET = process.env.JWT_SECRET;


// SAFE: crypto.randomBytes — not weak random
app.get("/reset-token", (req, res) => {
    const token = crypto.randomBytes(32).toString("hex");
    res.json({ resetToken: token });
});


// SAFE: Input type validation — not NoSQL injection
app.post("/auth", async (req, res) => {
    const { username, password } = req.body;
    if (typeof username !== "string" || typeof password !== "string") {
        return res.status(400).json({ error: "Invalid input" });
    }
    // ... safe auth logic
    res.json({ authenticated: true });
});


app.listen(3000);
