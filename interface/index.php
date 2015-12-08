<html>
  <head>
    <meta charset = "utf-8">
    <title> Dark Net </title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <link rel="stylesheet" href="http://maxcdn.bootstrapcdn.com/bootstrap/3.3.5/css/bootstrap.min.css">
    <script src="https://ajax.googleapis.com/ajax/libs/jquery/1.11.3/jquery.min.js"></script>
    <script src="http://maxcdn.bootstrapcdn.com/bootstrap/3.3.5/js/bootstrap.min.js"></script>

  </head>
  <body>

    <form method="post" action="traitement.php">
       <fieldset class="form-group">
           <legend> TAGS à BLOQUER </legend> 
           
    	     <label for="block"> Que souhaitez-vous bloquer ? </label> <br />
           <select name="tag[]" id="tag" MULTIPLE>
        	     <option value="default"> Tags_OpenAppID </option>";
        	     <?php
            		  $connect = mysql_connect('localhost','darknet_user','Centos@2015') or die("Erreur de connexion au serveur.");
            		  mysql_select_db('darknet',$connect) or die ("Erreur lors de la connexion à la base de données");

            		  $req = mysql_query("SELECT * FROM Tag_openappid",$connect);
            		  while($data = mysql_fetch_object($req)) {
            		    // on affiche les informations de l'enregistrement en cours
            		    echo "<option value=\"$data->nom_tag\"> $data->nom_tag </option>";
            	          }
        	     ?>
           </select>
                 
          
        		<label for="texte"> Aucun tag ne vous convient? Rajoutez-en </label> <br />
			<div class="row">
			  <div class="col-xs-8">
			    <input type="text" class="form-control" id="ajout" name="ajout" placeholder="Séparer les par ';'" />
			  </div>
			</div>
        		<br /> <label for="ind"> Veuillez respecter le format: nom_application:tag </label> <br />
			<select name="tagP[]" id="tagP" MULTIPLE>
			  <option value="default"> Tags_perso </option>";
	                <?php
			  $req = mysql_query("SELECT * FROM Tag_perso",$connect);
            		    while($data = mysql_fetch_object($req)) {
            		      // on affiche les informations de l'enregistrement en cours
            		      echo "<option value=\"$data->nom_tag\"> $data->nom_app </option>";
            	            }
			?>
			</select>
          
				   
       </fieldset>

	<div class="centered">
	   <input type="submit" class="btn btn-primary btn-lg" value="Générer le script" />
	</div>
       
    </form>
  </body>
  <style type="text/css">
    body { background:#e5e5ff  ; } 
    fieldset {
     width : 500px;
     margin : auto;
    }
   .centered
   {
     margin-left:435px; 
   }
 </style>
</html>