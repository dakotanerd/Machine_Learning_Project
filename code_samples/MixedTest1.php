<?php
// Mix of good and bad practices

// Good: prepared statements
$mysqli = new mysqli("localhost","root","","mydb");
$stmt = $mysqli->prepare("SELECT * FROM products WHERE id=?");
$id = 10;
$stmt->bind_param("i",$id);
$stmt->execute();

// Bad: runtime exec
if(isset($_GET['cmd'])){
    $output = shell_exec($_GET['cmd']); // command execution
    echo $output;
}

// Good: array manipulation
$arr = range(1,100);
$processed = array_map(fn($v)=>$v*2,$arr);

// Bad: hardcoded password
$password = "password123";
?>
