// NEGATIVE: Safe SQL in Node.js
function safeQuery(userId) {
    // Safe: parameterized query with array
    db.query("SELECT * FROM users WHERE id = ?", [userId], callback);
    // Safe: named parameters
    pool.query("SELECT * FROM users WHERE id = $1", [userId]);
}
