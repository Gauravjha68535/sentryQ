<?php
// NEGATIVE: Safe SQL
$id = $_GET['id'];

// Safe: PDO prepared statement
$stmt = $pdo->prepare("SELECT * FROM users WHERE id = ?");
$stmt->execute([$id]);

// Safe: bindParam
$stmt = $pdo->prepare("SELECT * FROM users WHERE id = :id");
$stmt->bindParam(':id', $id);
$stmt->execute();
?>
