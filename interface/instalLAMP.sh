# Install MySQL YUM repository
sudo yum localinstall https://dev.mysql.com/get/mysql57-community-release-el7-7.noarch.rpm
# Install MySQL 5.7.9
sudo yum install mysql-community-server
# Start MySQL server and autostart MySQL on boot
systemctl start mysqld.service
systemctl enable mysqld.service
# Get Your Generated Random root Password
grep 'A temporary password is generated for root@localhost' /var/log/mysqld.log  |tail -1 > /tmp/passwd.txt

# Connect to MySQL database (localhost) with password
# Remi Dependency
rpm -Uvh http://dl.fedoraproject.org/pub/epel/7/x86_64/e/epel-release-7-5.noarch.rpm
rpm -Uvh http://rpms.famillecollet.com/enterprise/remi-release-7.rpm
# Install Apache (httpd) Web server and PHP 5.6.15
sudo yum --enablerepo=remi,remi-php56 install httpd php php-common
# Install PHP 5.6.15 modules
sudo yum --enablerepo=remi,remi-php56 install php-mysqlnd
#Start Apache HTTP server (httpd) and autostart Apache HTTP server on boot
systemctl start httpd.service
systemctl enable httpd.service

# Restart MySQL server
systemctl restart mysqld.service

# Start MySQL Secure Installation (Answer Yes 'y' to all questions)
/usr/bin/mysql_secure_installation
# Connect to MySQL database (localhost) with password and create the database
mysql -u root -p < ./script.sql
php ./bd.php