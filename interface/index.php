<html>
  <head>
    <meta charset = "utf-8">
    <title> Dark Net </title>
  </head>
  <body>
    <form method="post" action="traitement.php">
     
       <fieldset>
           <legend> APPLICATIONS </legend>
           <p>
             <label for="site"> Quelles applications souhaitez-vous bloquer ? </label> <br />
             <input type="text" id="app" name="app" placeholder="Séparer les par ';'" />
           </p>
       </fieldset>
     
       <fieldset>
           <legend> TAGS à BLOQUER </legend> 
           
    	     <label for="block"> Que souhaitez-vous bloquer ? </label> <br />
           <select name="tag" id="tag">
        	     <option value="default"> Tags </option>";
        	     <?php
            		  $connect = mysql_connect('localhost','root','Centos@2015') or die("Erreur de connexion au serveur.");
            		  mysql_select_db('darknet',$connect) or die ("Erreur lors de la connexion à la base de données");

            		  $req = mysql_query("SELECT * FROM tag",$connect);
            		  while($data = mysql_fetch_object($req)) {
            		    // on affiche les informations de l'enregistrement en cours
            		    echo "<option value=\"$data->nom_tag\"> $data->nom_app </option>";
            	          }
        	     ?>
           </select>
                 
           <p>
        		<label for="texte"> Aucun tag ne vous convient? Rajoutez-en </label> <br />
        		<input type="text" id="ajout" name="ajout" placeholder="Séparer les par ';'" />
        		<br /> <label for="ind"> Veuillez respecter le format: nom_application:tag </label> <br />
           </p>
				   
       </fieldset>
       <input type="submit" value="Générer le script" />
    </form>
  </body>
  <script src="affiche.js"></script> 
</html>
