<?php
	$connect = mysql_connect('localhost','darknet_user','Centos@2015') or die("Erreur de connexion au serveur.");
	mysql_select_db('darknet',$connect) or die ("Erreur lors de la connexion à la base de données");

	system('cat /usr/local/lib/openappid/odp/appMapping.data | cut -f2 > /tmp/app.txt',$res);
	$file = fopen ('/tmp/app.txt','r');
	if ($file == null)
	  exit();

	do {
	   $ligne = trim(addslashes(fgets($file))); echo "$ligne\n";
	   $sql = "INSERT INTO Tag_openappid VALUES ('$ligne')";
	   $req = mysql_query($sql,$connect) or die ('Erreur SQL !'.'<br />'.mysql_error());
	} while (!feof($file));
	
	echo "Insertion réussie\n";

	fclose($file);
?>
