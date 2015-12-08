/***** Script à fournir pour création BD, puis tables, puis insertion des tags *****/
-- On crée la base de données pour contenir les applications et leurs tags associés
CREATE DATABASE darknet;
-- On crée un utilisateur
CREATE USER 'darknet_user'@'localhost' IDENTIFIED BY 'Centos@2015';
-- On lui donne les permissions sur la BD qu'on vient de créer
GRANT ALL ON darknet.* TO 'darknet_user'@'localhost';
FLUSH PRIVILEGES;
-- On sélectionne la BD qu'on vient de créer
USE darknet;

-- On crée la table destinée à accueillir les tags des applicatons
CREATE TABLE Tag_openappid (nom_tag VARCHAR(100), CONSTRAINT pk_openappid PRIMARY KEY(nom_tag) );
CREATE TABLE Tag_perso (nom_tag VARCHAR(100), nom_app VARCHAR(100), CONSTRAINT pk_perso PRIMARY KEY(nom_tag) );

-- On crée la table destinée à contenir les SID des règles de Snort
CREATE TABLE Snort_sid (sid_number INTEGER, CONSTRAINT pk_snortSID PRIMARY KEY(sid_number) );
-- On insère notre valeur par défaut
INSERT INTO Snort_sid VALUES (1000);
