#!/bin/bash
sudo yum remove snort
mkdir /home/admin/installs
cd /home/admin/installs
wget http://luajit.org/download/LuaJIT-2.0.2.tar.gz
tar xzvf LuaJIT-2.0.2.tar.gz
cd LuaJIT-2.0.2
sudo make
sudo make install
cd ..
wget https://snort.org/downloads/snort/snort-2.9.7.6.tar.gz
tar -xvf snort-2.9.7.6.tar.gz
cd  snort-2.9.7.6
./configure --enable-sourcefire --enable-open-appid
sudo make
make install
cd /etc
cp attribute_table.dtd file_magic.conf unicode.map classification.config gen-msg.map reference.config threshold.conf /etc/snort/
mkdir /usr/local/lib/openappid
wget https://snort.org/downloads/openappid/2738 -O snort-openappid.tar.gz
tar -xzvf ./snort-openappid.tar.gz
mv odp /usr/local/lib/openappid

