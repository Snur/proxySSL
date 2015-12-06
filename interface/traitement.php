<html>
  <head>
    <meta charset = "utf-8">
    <title> Dark Net </title>
  </head>
  <body>
	<?php
	  $connect = mysql_connect('localhost','darknet_user','Centos@2015') or die("Erreur de connexion au serveur.");
	  mysql_select_db('darknet',$connect) or die ("Erreur lors de la connexion à la base de données");

	  $req = mysql_query("SELECT * FROM Snort_sid",$connect) or die ('Erreur SQL !'.'<br />'.mysql_error());
	  while($data = mysql_fetch_object($req)) {
	    $sid = $data->sid_number;
      }

      echo "Veuillez copier les règles Snort ci-dessous et les coller dans votre fichier de rôle: 
      		<strong> /etc/snort/rules/[nom_fichier].rules </strong> <br/> <br/>";

	  $oldSID = $sid;	  	  
	   
	   foreach ($_POST['tag'] as $tag) {
		if ($tag != "default") {
		   $role = "drop tcp any any -> any any (appid:$tag; msg:\"Tag $tag bloqué\"; sid:$sid;)";
	           echo "$role <br/>";
	           ++$sid;
		}
	   }
	   
	   if (!empty($_POST['ajout'])) {
		$ajout = $_POST['ajout'];
		$app = explode(";", $ajout);
		foreach ($app as &$value) {
		  $tag = explode(":", $value);
		  $sql = "INSERT INTO Tag_perso VALUES ('$tag[1]','$tag[0]')";
		  $req = mysql_query($sql,$connect) or die ('Erreur SQL !'.'<br />'.mysql_error());
		  $role = "drop tcp any any -> any any (content:\"$tag[1]\"; msg:\"Tag $tag[0] bloqué\"; nocase; sid:$sid;)";
		  echo "$role <br/>";
		  ++$sid;
		}
	   }	  

	    if ($sid != $oldSID) {
	    	$sql = "UPDATE Snort_sid SET sid_number = $sid WHERE sid_number = $oldSID";
		$req = mysql_query($sql,$connect) or die ('Erreur SQL !'.'<br />'.mysql_error());
	    }
	?>
  </body>
</html>

