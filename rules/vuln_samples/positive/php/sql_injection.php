<?php
// POSITIVE: SQL injection
$id = $_GET['id'];

// Unsafe: direct query with GET param
mysqli_query($conn, "SELECT * FROM users WHERE id = '" . $id . "'");

// Unsafe: mysql_query concatenation
$db->query("SELECT * FROM products WHERE id = " . $_POST['product_id']);
?>
