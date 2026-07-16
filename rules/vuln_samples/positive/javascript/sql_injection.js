// POSITIVE: SQL injection in Node.js
const mysql = require('mysql');

function getUser(req, res) {
    const userId = req.query.id;
    // Unsafe: template literal in query
    db.query(`SELECT * FROM users WHERE id = ${userId}`, callback);
    // Unsafe: concatenation
    pool.query("SELECT * FROM users WHERE id = " + userId, callback);
    // Unsafe: template literal with request body
    client.query(`SELECT * FROM products WHERE name = '${req.body.name}'`);
}
