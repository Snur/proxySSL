sudo yum install flex libpcap-devel bison libmnl-devel libnfnetlink-devel libnetfilter_queue-devel libdnet-devel automake
cd ../daq-2.0.6/
sudo ln -s /usr/bin/aclocal /usr/bin/aclocal-1.15
sudo ln -s /usr/bin/automake /usr/bin/automake-1.15
./configure --disable-afpacket-module --disable-dump-module --disable-ipfw-module --disable-ipq-module --disable-pcap-module --disable-netmap-module --enable-nfq-module
make
sudo make install
