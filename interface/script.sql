/***** Script à fournir pour création BD, puis tables, puis insertion des tags *****/
-- On crée la base de données pour contenir les applications et leurs tags associés
CREATE DATABASE darknet;
-- On sélectionne la BD qu'on vient de créer
USE darknet;

-- On crée la table destinée à accueillir les tags des applicatons
CREATE TABLE tag (nom_tag VARCHAR(100), nom_app VARCHAR(100), CONSTRAINT pk_tag PRIMARY KEY(nom_tag) );
-- On insère nos tags prédéfinis
INSERT INTO tag VALUES ("comment_text=","Facebook_comment");
INSERT INTO tag VALUES ("add=true","Facebook_like");
INSERT INTO tag VALUES ("fb_dtsg=","Facebook_post");
INSERT INTO tag VALUES ("comment=","Linkedin_comment");
INSERT INTO tag VALUES ("shareId=","Linkedin_share");
INSERT INTO tag VALUES ("iwReconnectSubmit=","Linkedin_invite");

-- On crée la table destinée à contenir les SID des règles de Snort
CREATE TABLE Snort_sid (sid_number INTEGER, CONSTRAINT pk_snortSID PRIMARY KEY(sid_number) );
-- On insère notre valeur par défaut
INSERT INTO Snort_sid VALUES (1000);
