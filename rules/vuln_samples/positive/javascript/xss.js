// POSITIVE: XSS vulnerabilities
const express = require('express');

function handleRequest(req, res) {
    const name = req.query.name;
    // Unsafe: innerHTML with user input
    document.getElementById('output').innerHTML = name;
    // Unsafe: document.write
    document.write(location.search);
    // Unsafe: innerHTML with request body
    element.innerHTML = req.body.comment;
}
