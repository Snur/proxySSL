sudo yum install https://www.snort.org/downloads/snort/snort-openappid-2.9.8.0-1.centos7.x86_64.rpm
sudo rm /etc/snort/snort.conf
sudo cp ./snort.conf /etc/snort/snort.conf
mkdir /usr/local/lib/openappid
wget https://snort.org/downloads/openappid/2738 -O snort-openappid.tar.gz
tar -xzvf ./snort-openappid.tar.gz
mv odp /usr/local/lib/openappid
