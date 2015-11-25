<?php
// require key stretching function and session check.
require_once "pbkdf2.php";
require_once "settoken.php";

// connect to login db.
$con = new mysqli("localhost", "placeholder", "placeholder", "placeholder");
if ($con->connect_errno){
	print("Connect failed: ". $con->connect_error);
	exit();
}

// set variables
$name = $_POST['username'];
$pass = $_POST['key'];
$hash_size = 64;

// prepare and execute statement to get the needed variables to check users hash
$stmt = $con->prepare("SELECT `hash`, `salt`, `algorithm`, `iterations` FROM `users` WHERE `name` = ?");
if($stmt->errno){
	print("error: ". $stmt->error);
	exit();
}
$stmt->bind_param("s", $name);
$stmt->execute();
if($stmt->errno){
	print("error: ". $stmt->error);
	exit();
}
// check if user exists (if there is a result the user exists)
$stmt->store_result();
if($stmt->num_rows > 0){
	$stmt->bind_result($hash, $salt, $algorithm, $iterations);
	$stmt->fetch();
	$stmt->close();
	$salt = base64_decode($salt);
	// create hash to check against db
	$hashCheck = pbkdf2($algorithm, $pass, $salt, $iterations, $hash_size, false);
	//check hash
	if($hash == $hashCheck){
		// set current session to user when hash matches
		if($stmt = $con->prepare("UPDATE `users` SET `session` = ? WHERE `name` = ?")){
			$stmt->bind_param("ss", $token, $name);
			$stmt->execute();
			if($stmt->errno){
				print("error: ". $stmt->error);
				exit();
			}
			print("succesfully logged in.");
			$stmt->close();
		}else{
			print("error: ".$con->error);
			exit();
		}
	// if hash does not match	
	}else{
		print("Invalid username/password combination");
	}
// if result is empty (user does not exist)
}else{ 
	print("Invalid username/password combination");
}

$con->close();
?>