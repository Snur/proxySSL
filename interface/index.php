<html>
  <head>
    <meta charset = "utf-8">
    <title>Dark Net</title>
  </head>
  <body>
    <form method="post" action="traitement.php">
     
       <fieldset>
           <legend>Sites web</legend> <!-- Titre du fieldset --> 
           <p>
             <label for="site">Quels sites souhaitez-vous bloquer ?</label><br />
             <select name="url" id="url">
                 <option value="fb">Facebook</option>
                 <option value="ig">Instagram</option>
                 <option value="a24">Africa24</option>              
             </select>
           </p>
       </fieldset>
     
       <fieldset>
           <legend>Contenu à bloquer</legend> 
           
	   <label for="bloc">Que souhaitez-vous bloquer ? </label><br />
	   <input type="checkbox" name="like" id="like" /><label for="like">Like</label><br>
           <input type="checkbox" id="com" name="com" onclick="afficher(this)" /><label for="com">Commentaires</label><br>
           <label for="comment">Contenu specifique:</label><input type="text" id="comment" name="comment" disabled="disabled"/>
				   
       </fieldset>
       <input type="submit" value="Générer le script" />
    </form>
  </body>
  <script src="affiche.js"></script> 
</html>
