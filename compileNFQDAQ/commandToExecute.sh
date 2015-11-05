sudo yum install flex libpcap-devel bison libmnl-devel libnfnetlink-devel libnetfilter_queue-devel libdnet-devel automake
cd ../daq-2.0.6/
./configure --disable-afpacket-module --disable-dump-module --disable-ipfw-module --disable-ipq-module --disable-pcap-module --disable-netmap-module --enable-nfq-module
sudo ln -s /usr/bin/automake /usr/bin/automake-1.15
make
sudo make install
