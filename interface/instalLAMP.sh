# Install MySQL YUM repository
yum localinstall https://dev.mysql.com/get/mysql57-community-release-el7-7.noarch.rpm
# Install MySQL 5.7.9
yum install mysql-community-server
# Start MySQL server and autostart MySQL on boot
systemctl start mysqld.service
systemctl enable mysqld.service
# Get Your Generated Random root Password
grep 'A temporary password is generated for root@localhost' /var/log/mysqld.log |tail -1
# Puis appeler le script pour création BD, puis tables, puis insertion des tags
# Start firewalld.service
systemctl start firewalld.service
# Add New Rule to Firewalld
firewall-cmd --permanent --zone=public --add-service=mysql
# Restart firewalld.service
systemctl restart firewalld.service

# Remi Dependency
rpm -Uvh http://dl.fedoraproject.org/pub/epel/7/x86_64/e/epel-release-7-5.noarch.rpm
rpm -Uvh http://rpms.famillecollet.com/enterprise/remi-release-7.rpm
# Install Apache (httpd) Web server and PHP 5.6.15
yum --enablerepo=remi,remi-php56 install httpd php php-common
# Install PHP 5.6.15 modules
yum --enablerepo=remi,remi-php56 install php-mysqlnd
#Start Apache HTTP server (httpd) and autostart Apache HTTP server on boot
systemctl start httpd.service
systemctl enable httpd.service

# Start MySQL Secure Installation (Answer Yes 'y' to all questions)
/usr/bin/mysql_secure_installation

# Connect to MySQL database (localhost) with password
#mysql -u root -p
mysql -u root -p < /home/admin/Desktop/script.sql

# Restart MySQL server
systemctl restart mysqld.service

