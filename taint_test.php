<?php
$user = $_GET['user'];
$name = $user;
$query = "SELECT * FROM users WHERE name = '" . $name . "'";
eval($query);
?>
