<?php
  $fich = fopen('/tmp/myrules.rules', 'a');
  if ($fich == false)
  	exit();
  $url = $_POST['url'];
  if (isset($_POST['like']) && isset($_POST['com'])) {
    if (!empty($_POST['comment'])) {
	$comment = $_POST['comment'];
	$role = "drop tcp any any -> any any (content:\"add=true\"; content:\"comment_text=$comment\"; msg:\"Like et commentaire spécifique     	bloqué\"; nocase; sid=100001;)";
    }
    else {
	// faire la regle sur le like et bloquer les comment
	$role = "drop tcp any any -> any any (content:\"add=true\"; content:\"comment_text=\"; msg:\"Like et commentaire bloqué\"; nocase; 		sid=100001;)";
    }
  }
  else 
  if (isset($_POST['like'])) {
    //faire la règle sur le like uniquement
    $role = "drop tcp any any -> any any (content:\"add=true\"; msg:\"Like bloqué\"; nocase; sid=100001;)";
  }
  else
  if (isset($_POST['com'])) {
     if (!empty($_POST['comment'])) {
	$comment = $_POST['comment'];
	//bloquer le commentaire spécifié
	$role = "drop tcp any any -> any any (content:\"comment_text=$comment\"; msg:\"Commentaire spécifique bloqué\"; nocase; sid=100001;)";
     }
     else {
        //bloquer tous les comment
	$role = "drop tcp any any -> any any (content:\"comment_text=\"; msg:\"Commentaire bloqué\"; nocase; sid=100001;)";
     }
  }

  fwrite($fich,"$role\n");
  fclose($fich);
  //header("./index.php");

?>
