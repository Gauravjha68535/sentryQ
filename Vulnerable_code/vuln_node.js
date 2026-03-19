// ═══════════════════════════════════════════════════════════════
// TEST FILE: vuln_node.js
// EXPECTED: 8 findings (all True Positives)
// ═══════════════════════════════════════════════════════════════

const express = require("express");
const { exec } = require("child_process");
const mysql = require("mysql");
const fs = require("fs");
const path = require("path");
const jwt = require("jsonwebtoken");

const app = express();
app.use(express.json());


// ── VULN 1: SQL Injection (CWE-89) ──────────────────────────
// EXPECTED: Critical — string concatenation in query()
app.get("/user", (req, res) => {
    const id = req.query.id;
    const db = mysql.createConnection({ host: "localhost", user: "root", database: "app" });
    db.query("SELECT * FROM users WHERE id = " + id, (err, rows) => {
        res.json(rows);
    });
});


// ── VULN 2: Command Injection (CWE-78) ──────────────────────
// EXPECTED: Critical — user input in exec()
app.get("/ping", (req, res) => {
    const host = req.query.host;
    exec("ping -c 4 " + host, (err, stdout) => {
        res.send(stdout);
    });
});


// ── VULN 3: XSS (CWE-79) ───────────────────────────────────
// EXPECTED: High — user input directly in innerHTML
app.get("/search", (req, res) => {
    const query = req.query.q;
    res.send(`
        <html>
        <body>
            <h1>Search results for:</h1>
            <div id="results">${query}</div>
            <script>
                document.getElementById("results").innerHTML = "${query}";
            </script>
        </body>
        </html>
    `);
});


// ── VULN 4: Path Traversal (CWE-22) ────────────────────────
// EXPECTED: High — user input in readFileSync
app.get("/download", (req, res) => {
    const filename = req.query.file;
    const content = fs.readFileSync(path.join("/uploads", filename));
    res.send(content);
});


// ── VULN 5: Hardcoded Secret (CWE-798) ─────────────────────
// EXPECTED: High — JWT secret in source code
const JWT_SECRET = "my-super-secret-jwt-key-do-not-share-2024";

app.post("/login", (req, res) => {
    const { username, password } = req.body;
    // pretend auth check
    const token = jwt.sign({ username }, JWT_SECRET, { expiresIn: "1h" });
    res.json({ token });
});


// ── VULN 6: Prototype Pollution (CWE-1321) ──────────────────
// EXPECTED: High — Object.assign with req.body
app.post("/settings", (req, res) => {
    const defaults = { theme: "light", lang: "en" };
    const settings = Object.assign(defaults, req.body);
    res.json(settings);
});


// ── VULN 7: NoSQL Injection (CWE-943) ──────────────────────
// EXPECTED: High — direct user input in MongoDB find()
const MongoClient = require("mongodb").MongoClient;
app.post("/auth", async (req, res) => {
    const client = await MongoClient.connect("mongodb://localhost:27017");
    const db = client.db("app");
    const user = await db.collection("users").findOne(req.body);
    res.json({ authenticated: !!user });
});


// ── VULN 8: Weak Random (CWE-330) ──────────────────────────
// EXPECTED: Medium — Math.random for token generation
app.get("/reset-token", (req, res) => {
    const token = Math.random().toString(36).substring(2);
    res.json({ resetToken: token });
});


app.listen(3000, () => console.log("Running on :3000"));
