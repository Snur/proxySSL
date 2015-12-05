--[[
# Copyright 2001-2014 Cisco Systems, Inc. and/or its affiliates. All rights
# reserved.
#
# This file contains proprietary Detector Content created by Cisco Systems,
# Inc. or its affiliates ("Cisco") and is distributed under the GNU General
# Public License, v2 (the "GPL").  This file may also include Detector Content
# contributed by third parties. Third party contributors are identified in the
# "authors" file.  The Detector Content created by Cisco is owned by, and
# remains the property of, Cisco.  Detector Content from third party
# contributors is owned by, and remains the property of, such third parties and
# is distributed under the GPL.  The term "Detector Content" means specifically
# formulated patterns and logic to identify applications based on network
# traffic characteristics, comprised of instructions in source code or object
# code form (including the structure, sequence, organization, and syntax
# thereof), and all documentation related thereto that have been officially
# approved by Cisco.  Modifications are considered part of the Detector
# Content.
--]]
--[[
detection_name: Content Group "Port Services"
version: 16
description: Group of Port Service detectors.
bundle_description: $VAR1 = {
          'idfp' => 'Registered with IANA on port 549 TCP/UDP.',
          'Groove' => 'Microsoft desktop application designed for document collaboration.',
          'Philips Video-Conferencing' => 'Used by Philips Electronics in their video conferencing products.',
          'REAL SQL Server' => 'A relational database management system.',
          'Hyperwave-ISP' => 'Hyperwave-ISP focuses on document and knowledge management in intranet environments.',
          'AccessBuilder' => 'A family of dial-in remote access servers for mobile computer users and remote office workers.',
          'MSOC File Transfer' => 'Microsoft Office Communications Server and File Transfer.',
          'Videotex' => 'Videotex was one of the earliest implementations of an end-user information system.',
          'Softros LAN Messenger' => 'Instant messaging program for user-to-user or user-to-group message and file exchange.',
          'GKrellM' => 'GNU Krell Monitors is a single process stack of system monitors.',
          'eDonkey Static' => 'eDonkey related traffic.',
          'Sun IPC server' => 'Client-server communication program that listens for connections from local-domain clients.',
          'Ariel3' => 'Ariel allows users to send high-detail electronic images.',
          'CSTA' => 'Registered with IANA on port 450 TCP/UDP.',
          'RDA' => 'Remote Database Access, a protocol standard for database access.',
          'npmp-local' => 'Registered with IANA on port 610 TCP/UDP.',
          'Meter' => 'Registered with IANA on port 570 TCP/UDP.',
          'SNTP-HEARTBEAT' => 'Simple Network Time Protocol Heartbeat is used to provide a multicast heartbeat in a network.',
          'Airsoft Powerburst' => 'A remote access accelerator that caches client sessions on the remote server. IANA tcp/udp 485.',
          'Borland DSJ' => 'Deployment Server for Java (DSJ) is a deployment service.',
          'Courier Mail Server' => 'A mail server.',
          'CU-SeeMe' => 'Internet video conferencing client.',
          'Citrix Static' => 'Citrix related service.',
          'kshell' => 'Registered with IANA on port 544 TCP/UDP.',
          'Mobility XE protocol' => 'A mobile VPN.',
          'rxe' => 'Registered with IANA on port 761 TCP/UDP.',
          'CVSup' => 'A protocol for synchronizing files. Originally a tool for CVS but has been extended to other file types.',
          'SynOptics SNMP Relay' => 'Registered with IANA on port 391 TCP/UDP.',
          'Customer Ixchange' => 'Registered with IANA on port 528 TCP/UDP.',
          'Hassle' => 'A networking application that allows to execute remote jobs that have a transfer component built in.',
          'ESCP' => 'Registered with IANA on port 621 TCP/UDP.',
          'SEND' => 'SEcure Neighbor Discovery, a security extension of the Neighbor Discovery Protocol in IPv6.',
          'Photuris' => 'A session-key management protocol.',
          'DirectPlay8' => 'Part of Microsoft\'s DirectX API.',
          'eSignal' => 'Used by eSignal in their online trading line of products.',
          'DTK' => 'The Deception ToolKit is honeypot software that allows faking of vulnerabilities.',
          'Network Innovations Multiplex' => 'Registered with IANA on port 171 TCP/UDP.',
          'ha-cluster' => 'Protocol for High Availability systems.',
          'Direct TV Tickers' => 'Registered with IANA on port 3336 TCP/UDP.',
          'AMANDA' => 'Advanced Maryland Automatic Network Disk Archiver. IANA tcp/udp port 10080.',
          'Skronk' => 'Registered with IANA on port 460 TCP/UDP.',
          'scohelp' => 'Registered with IANA on port 457 TCP/UDP.',
          'Graphics' => 'Registered with IANA on port 41 TCP/UDP.',
          'DEOS' => 'Distributed External Object Store. Registered with IANA on port 76 tcp/udp.',
          'Smart Session Description Protocol' => 'Registered with IANA on port 426 tcp/udp.',
          'repcmd' => 'Repcmd is a protocol used by the SupportSoft.',
          'cpq-wbem' => 'Compaq Insight Manager Service.',
          'DHCPv6 Client' => 'DHCPv6 is a network protocol that is used for configuring IPv6 hosts with IP addresses.',
          'Call of Duty' => 'Shooter video game series franchise.',
          'PAPI' => 'Process Application Programming Interface, used by Aruba Networks in their network management tools to control and manage access points.',
          'Heroix Longitude' => 'A performance monitoring solution.',
          'WAP vCal' => 'Registered with IANA on port 9205 TCP/UDP.',
          'Novadigm EDM' => 'Novadigm Enterprise Desktop Manager, a management platform for deploying enterprise applications.',
          'Oracle Net8 Cman' => 'Oracle Connection Manager, an Net8 component that acts much like a router.',
          'Monitor' => 'Registered with IANA on port 561 TCP/UDP.',
          'NSW User System FE' => 'Registered with IANA on port 27 TCP/UDP.',
          'SCO System Administration Server' => 'Registered with IANA on port 616 TCP/UDP.',
          'SNET' => 'Sirius Systems.',
          'BACnet' => 'Building Automation and Control Networks is a communications protocol for building automation.',
          'SPMP' => 'Registered with IANA on port 656 TCP/UDP.',
          'PRM Node Man' => 'Prospero Resource Manager is a scalable resource allocation systemi.',
          'GNU Generation Foundation NCP 128' => 'Registered with IANA on port 128 TCP/UDP.',
          'Technical Analysis Software' => 'A professional electronic trading platform for financial market traders.',
          'NetWall' => 'Protocol for emergency broadcasts.',
          'bgs-nsi' => 'Registered with IANA on port 482 TCP/UDP.',
          '3Com AMP3' => 'Registered with IANA on port 629 TCP/UDP.',
          'HMMP Operation' => 'Registered with IANA on port 613 TCP/UDP.',
          'DirecTV Webcasting' => 'Consumer satellite internet broadcasts.',
          'sFlow' => 'sFlow is a technology for monitoring network, wireless, and host devices.',
          'Mondex' => 'Mondex is a smart card electronic cash system. The main protocol of Mondex implements electronic cash transfer, using either a device (wallet) with two slots, or an Internet connection.',
          'Networked Media Streaming Protocol' => 'Registered with IANA on port 537 TCP/UDP.',
          'OBEX' => 'OBject Exchange, a communications protocol for binary objects.',
          'WAP Push OTA-HTTP port' => 'Used for asynchronous communication between a PPG (Push Proxy Gateway) and a WAP client, utilizing HTTP services.',
          'Access Network' => 'Registered with IANA on port 699 TCP/UDP.',
          'Entrust Administration Service Handler' => 'Registered with IANA on port 710 TCP/UDP.',
          'qrh' => 'Registered with IANA on port 752 TCP/UDP.',
          'Tapeware' => 'An automated backup system.',
          'rmiregistry' => 'rmiregistry is a command that creates and starts a remote object registry on the current host.',
          'WAP Session Service Secure' => 'A component of Wireless Transaction Protocol (WTP).',
          'DDM' => 'IBM Lotus Domino domain monitoring, a management system for Domino networks.',
          'itm-mcell-s' => 'Registered with IANA on port 828 TCP/UDP.',
          'ListProc' => 'ListProcessor, mailing list management software.',
          'Survey Measurement' => 'Registered with IANA on port 243 TCP/UDP.',
          'Ohimsrv' => 'Registered with IANA on port 506 TCP/UDP.',
          'WAP vCard Secure' => 'Registered with IANA on port 9206 TCP/UDP.',
          'banyan-rpc' => 'Registered with IANA on port 567 TCP/UDP.',
          'QMTP' => 'Quick Mail Transfer Protocol, an e-mail transmission protocol.',
          'TeamSound' => 'Voice conferencing software for online game players.',
          'Russell Info Sci Calendar Manager' => 'Registered with IANA on port 748 TCP/UDP.',
          'iafdbase' => 'Registered with IANA on port 480 TCP/UDP.',
          'SURF' => 'Speeded Up Robust Feature (SURF) is a local feature detector.',
          'IMSP' => 'The Internet Message Support Protocol, for mail provisioning.',
          'PAWSERV' => 'Allows you to analyze transaction performance and behavioral problems by providing a platform for investigating logs and other historical data.',
          'UTMPCD' => 'Registered with IANA on port 431 TCP/UDP.',
          'Transport Independent Convergence' => 'Registered with IANA on port 493 TCP/UDP.',
          'ISO-TP0' => 'A protocol that is used to bridge ISO TP0 packets between X.25 and TCP networks.',
          'Britton Lee IDM' => 'Britton Lee Integrated Database Manager.',
          'HTTP RPC Ep Map' => 'The http-rpc-epmap endpoint mapper provides CIS parameters for Remote Procedure Call.',
          'DHCP Failover' => 'DHCP Failover Protocol supports automatic DHCP failover.',
          'Desknet\'s' => 'Desknet\'s (by NEO) is a Japanese groupware application for resource sharing.',
          'Ariel2' => 'Ariel allows users to send high-detail electronic images.',
          'Plus Fives MUMPS' => 'Registered with IANA on port 188 TCP/UDP.',
          'CSNET Mailbox Name Nameserver' => 'A relic of the Computer Science Network, which was "ARPANET-lite".',
          'whoami' => 'Registered with IANA on port 565 TCP/UDP.',
          'ipdd' => 'Registered with IANA on port 578 TCP/UDP.',
          'webster' => 'Protocol for accessing dictionaries and thesauruses.',
          'PassGo Technologies Service' => 'Software for web access management.',
          'Bundle Discovery Protocol' => 'A Multi-link PPP (MP) Link Control Protocol.',
          'Orbix 2000 Locator' => 'Used by Progree Software Corporation in their Orbix software for enterprise COBRA solutions.',
          'Netix MPP' => 'Message Posting Protocol is a network protocol that is used for posting messages.',
          'AgentX' => 'AgentX is an SNMP-related protocol.',
          'SVN' => 'Managing Subversion servers.',
          'OLSR' => 'Optimized Link State Routing protocol, a routing protocol for mobile ad-hoc networks.',
          'MFTP' => 'Multisource File Transfer Protocol, a file sharing protocol.',
          'ISO Transport Class 2 Non-Control over TCP' => 'Implementation of ISO Transport Class 2 Non-use of Explicit Flow Control on top of TCP.',
          'HAP' => 'Host Access Protocol is a network layer protocol that defines different types of host-to-network control messages.',
          'Oracle Business Intelligence' => 'Used by Oracle systems.',
          'MF Cobol' => 'Micro Focus Cobol Directory Service.',
          'ginad' => 'Registered with IANA on port 634 TCP/UDP.',
          'GraphOn Login' => 'A secure cloud application delivery solution.',
          'Entrust SPS' => 'Registered with IANA on port 640 TCP/UDP.',
          'ETOS' => 'Registered with IANA on ports 377-378 tcp/udp.',
          'GoBoogy' => 'Korean P2P file sharing software.',
          'PIP' => 'Presence Information Protocol. Registered with IANA on port 321 tcp/udp.',
          'SET' => 'Secure Electronic Transaction was a standard protocol for securing credit card transactions over insecure networks.',
          'STMF' => 'Registered with IANA on port 501 TCP/UDP.',
          'AS Server Mapper' => 'Provides a method for client applications to determine the port number associated with a particular server.',
          'Multiling HTTP' => 'Registered with IANA on port 777 TCP/UDP.',
          'BB' => 'Big Brother is a tool for systems and network monitoring.',
          'Chat' => 'Registered with IANA on port 531 TCP/UDP.',
          'GotoDevice' => 'Cross-platform control and administration software.',
          'SCC Security' => 'Registered with IANA on port 582 TCP/UDP.',
          'SFS config server' => 'Cray Shared File System config server.',
          'CDDB' => 'Compact Disc Database Protocol, for searching CD contents.',
          'FCP' => 'FirstClass Protocol, a transport layer networking protocol.',
          'TIA/EIA/IS-99 modem client' => 'A data services option standard for wideband spread spectrum digital cellular systems.',
          'netGW' => 'Registered with IANA on port 741 TCP/UDP.',
          'Decbsrv' => 'Registered with IANA on port 579 TCP/UDP.',
          'CFDP' => 'Coherent File Distribution Protocol, for one-to-many file transfer operations.',
          'ARNS' => 'Adaptive Receive Node Scheduling, port 384 tcp/udp.',
          'SMID' => 'Secure management and installation discovery, registered on ports 3211,3502,3871 TCP/UDP.',
          'ACAP' => 'Application Configuration Access Protocol.',
          'Chshell' => 'Registered with IANA on port 562 TCP/UDP.',
          'tell' => 'Registered with IANA on port 754 TCP/UDP.',
          'cvc_hostd' => 'Registered with IANA on port 442 TCP/UDP.',
          'SCO Desktop Administration Server' => 'Registered with IANA on port 617 TCP/UDP.',
          'Oracle coauthor' => 'Registered with IANA on port 1529 TCP/UDP.',
          'HMMP Indication' => 'Registered with IANA on port 612 TCP/UDP.',
          'Stock IXChange' => 'Registered with IANA on port 527 TCP/UDP.',
          'MRM' => 'Multicast Routing Monitor, a management diagnostic tool in Cisco products.',
          'SCO WebServer Manager' => 'Registered with IANA on port 620 TCP/UDP.',
          'Rational Method Composer' => 'A platform for process engineers and managers.',
          'SCO Web Server Manager 3' => 'Registered with IANA on port 598 TCP/UDP.',
          'gdomap' => 'Used by GNUstep programs to look up distributed objects and processes.',
          'HEMS' => 'High-Level Entity Management System.',
          'Nmap' => 'Network Mapper, a security scanner.',
          'entrust-aaas' => 'Registered with IANA on port 680 TCP/UDP.',
          'WAP Push OTA-HTTP secure' => 'Allows WAP content to be pushed to the mobile handset with minimum user intervention.',
          'RSVP Tunnel' => 'A transport layer protocol designed to reserve resources across a network.',
          'Memcomm' => 'Registered with IANA on port 668 TCP/UDP.',
          'NFS Lock Daemon Manager' => 'NFS file locking system.',
          'DOOM' => 'A first person shooter game with multiplayer support developed by Id Software.',
          'GNU Generation Foundation NCP 678' => 'Registered with IANA on port 678 TCP/UDP.',
          'QFT' => 'Queued File Transport. Registered with IANA on port 189 TCP/UDP.',
          'Unix time' => 'Unix system call that changes the access and modification times of an inode.',
          'SIFT' => 'Sender-Initiated File Transfer (SIFT) protocol',
          'AppleTalk Unused 205' => 'Registered with IANA on port 205 TCP/UDP.',
          'Avian' => 'Registered with IANA on port 486 TCP/UDP.',
          'decap' => 'Registered with IANA on port 403 TCP/UDP.',
          'Remote-KIS' => 'Registered with IANA on port 185 TCP/UDP.',
          'Kerberos Administration' => 'Kerberos is a network authentication protocol.',
          'wpgs' => 'Registered with IANA on port 780 TCP/UDP.',
          'GSS HTTP' => 'Authentication mechanism for GSS HTTP.',
          'vemmi' => 'VEMMI is an international standard defining user interface and client/server protocol for on-line multimedia interactive services.',
          'kpasswd' => 'Kerberos change-password protocol (kpasswd) is a password changing service.',
          'FTP Software Agent System' => 'Registered with IANA on port 574 TCP/UDP.',
          'RMCP' => 'Remote Mail Checking Protocol, a mail checking service.',
          'Password Change' => 'Services Kerberos Change Password and Set Password Protocol requests.',
          'Key Server' => 'A system that receives and then serves existing cryptographickeysto users.',
          'lanserver' => 'Registered with IANA on port 637 TCP/UDP.',
          'CA Intl License Server' => 'Registered with IANA on port 216 TCP/UDP.',
          'Microsoft Rome' => 'Registered with IANA on port 569 TCP/UDP.',
          'ApplianceWare Managment Protocol' => 'Registered with IANA on port 688 TCP/UDP.',
          'WAP Push Secure' => 'WAP Push Secure is the secured version of WAP Push.',
          'Sitara Dir' => 'The Sitara Network Protocol (SNP) directory server.',
          'Mylex-mapd' => 'Registered with IANA on port 467 TCP/UDP.',
          'SUNDR' => 'Network file system designed to store data securely on untrusted servers.',
          'Timeserver' => 'Reads the actual time from a reference clock and distributes this information to its clients using a computer network.',
          'RSH-SPX' => 'RSH-SPX is an implementation of RSH (Remote Shell) over an IPX/SPX network.',
          'MPM' => 'Message Processing Module (MPM) is part of the Internet message system.',
          'nlogin' => 'Registered with IANA on port 758 TCP/UDP.',
          'mcns-sec' => 'Registered with IANA on port 638 TCP/UDP.',
          'AppleTalk Unused 208' => 'Registered with IANA on port 208 TCP/UDP.',
          'xact-backup' => 'Registered with IANA on port 911 TCP/UDP.',
          'VPPS-Via' => 'Registered with IANA on port 676 TCP/UDP.',
          'TPIP' => 'Registered with IANA on port 594 TCP/UDP.',
          'Teedtap' => 'Registered with IANA on port 559 TCP/UDP.',
          'uuidgen' => 'A program that generates a unique UUID for each system.',
          'NDMP' => 'Network Data Management Protocol.',
          'ISCSI' => 'Internet Small Computer System Interface, an IP protocol that allows storage systems to communicate.',
          'pump' => 'Registered with IANA on port 751 TCP/UDP.',
          'Cisco NAC' => 'Cisco Network Admission Control is an access control system.',
          'DCE endpoint resolution' => 'Registered with IANA on port 135 TCP/UDP.',
          'WCCP' => 'A Cisco-developed content-routing protocol that provides a mechanism to redirect traffic flows in real-time to web-caches.',
          'rmtis' => 'Remote MT Protocol, used during manipulation of magnetic tape drives.',
          'Fujitsu Device Control' => 'A system that controls devices within a house.',
          'Adobe PostScript' => 'A printing and imaging standard.',
          'Management Utility' => 'Registered with IANA on port 2 TCP/UDP.',
          'ICL coNETion server info' => 'Registered with IANA on port 887 TCP/UDP.',
          'IBM Director' => 'IBM Director is an element management system.',
          'Creative Server' => 'Registered with IANA on port 453 TCP/UDP.',
          'DEI-ICDA' => 'Registered with IANA on port 618 TCP/UDP.',
          'SAP' => 'SAP offers various software applications and solutions for businesses.',
          'cycleserv2' => 'Registered with IANA on port 772 TCP/UDP.',
          'WAP Push' => 'A message which includes a link to a Wireless Application Protocol address.',
          'PRM Sys Man' => 'The system manager manages the full set of resources that exist in a system.',
          'Nest Protocol' => 'Novell protocol that defines a systems architecture.',
          'TIA/EIA/IS-99 modem server' => 'A data services option standard for wideband spread spectrum digital cellular systems.',
          'tinc' => 'A Virtual Private Network (VPN) daemon.',
          'SNARE' => 'System iNtrusion Analysis and Reporting Environment, used to collect audit log data from a variety of operating systems.',
          'PureNoise' => 'Registered with IANA on port 663 TCP/UDP.',
          'PowerChute' => 'A control system for uninterruptible power supplies.',
          'SMUX' => 'SNMP multiplexing defines communications between the SNMP Agent and other processes.',
          'pirp' => 'Public Information Retrieval Protocol is a method of publishing information.',
          'srvloc' => 'Service Location Protocol is a service discovery protocol.',
          'entomb' => 'Registered with IANA on port 775 TCP/UDP.',
          'DataRamp Svr' => 'Registered with IANA on port 461 TCP/UDP.',
          'mdc-portmapper' => 'Registered with IANA on port 685 TCP/UDP.',
          'ESRO-EMSDP V1.3' => 'IANA tcp/udp port 642.',
          'LDP' => 'Label Distribution Protocol is a protocol that works with MPLS.',
          'TESLA' => 'Registered with IANA on port 7631 TCP.',
          'Hostname server' => 'Service for translating a hostname to a network address.',
          'VVPS-Qua' => 'Registered with IANA on port 672 TCP/UDP.',
          'Hybrid Point of Presence' => 'Takes TCP/IP packets from the Internet, modulates them into standard TV channels and feeds them to a TV system.',
          'vnas' => 'Registered with IANA on port 577 TCP/UDP.',
          'spsc' => 'Registered with IANA on port 478 TCP/UDP.',
          'TNS CML' => 'Registered with IANA on port 590 TCP/UDP.',
          'oracle' => 'Registered with IANA on port 1527 TCP/UDP.',
          'VATP' => 'Velazquez Application Transfer Protocol.',
          'Mailbox-LM' => 'Mailbox-LM is a used by FTP Daemon.',
          'SNNTP' => 'Secure Network News Transfer Protocol is NNTP over TLS.',
          'Netnews' => 'Netnews (Usenet) is a worldwide distributed Internet discussion system. It was developed from the general purpose UUCP architecture of the same name.',
          'streettalk' => 'Registered with IANA on port 566 TCP/UDP.',
          'Novell Netware over IP' => 'NetWare Over TCP/IP allows NetWare Core Protocol and Novell Directory Services to run over IP.',
          'SST' => 'SCSI on Scheduled Transfer (ST) standard (SST), a method of encapsulating SCSI packets inside ST Protocol.',
          'AppleTalk Routing Maintenance' => 'A protocol for AppleTalk routers to keep each other informed about the topology of the network.',
          'CVS pserver' => 'An insecure method of remote access to a Concurrent Versions System (CVS) repository.',
          'Service Status Update' => 'IANA tcp/udp port 633.',
          'VACDSM-APP' => 'Registered with IANA on port 671 TCP/UDP.',
          'AppleTalk Zone Information Protocol' => 'The Zone Information Protocol was the protocol by which AppleTalk network numbers were associated with zone names.',
          'IAFServer' => 'IAFServer is part of the Integrated Authentication Framework.',
          'netvmg-traceroute' => 'A network diagnostic tool used by NetVMG.',
          'appleqtcsrvr' => 'Registered with IANA on port 545 TCP/UDP.',
          'SRVFP' => 'Swift Remote Virtual File Protocol.',
          'ljk-login' => 'Registered with IANA on port 472 TCP/UDP.',
          'Internet Configuration Manager' => 'Registered with IANA on port 615 TCP/UDP.',
          'NSRMP' => 'Network Security Risk Management Protocol. Registered with IANA on port 359 tcp/udp.',
          'TDP' => 'Tag Distribution Protocol, used to communicate tag binding information to their peers.',
          'OCS_CMU' => 'Registered with IANA on port 428 TCP/UDP.',
          'Omginitialrefs' => 'Registered with IANA on port 900 TCP/UDP.',
          'utmpsd' => 'Registered with IANA on port 430 TCP/UDP.',
          'Intecourier' => 'Registered with IANA on port 495 TCP/UDP.',
          'XTP' => 'Xpress Transport Protocol is a transport layer protocol.',
          'EMC SmartPackets' => 'Registered with IANA on port 3218 TCP/UDP.',
          'Asipregistry' => 'Registered with IANA on port 687 TCP/UDP.',
          'asa-appl-proto' => 'Registered with IANA on port 502 TCP/UDP.',
          'Shockwave' => 'A multimedia platform used to add animation and interactivity to web pages.',
          'opalis-rdv' => 'opalis-rdv, Registered with IANA on port 536 TCP/UDP.',
          'Creative Partner' => 'Registered with IANA on port 455 TCP/UDP.',
          'maitrd' => 'Registered with IANA on port 997 TCP/UDP.',
          'MS Exchange Routing' => 'MS Exchange Routing is Used by Microsoft Exchange servers to exchange routing information.',
          'Websense' => 'Company which produces Cyber security related products.',
          'POV-Ray' => 'Persistence of Vision Raytracer (POV-Ray), a ray tracing program.',
          'MSA' => 'Mail Submission Agent, part of a variant SMTP system.',
          'Rmonitor' => 'A protocol used by remote network monitoring devices.',
          'openvms-sysipc' => 'Registered with IANA on port 557 TCP/UDP.',
          'npmp-gui' => 'Registered with IANA on port 611 TCP/UDP.',
          'Corerjd' => 'Registered with IANA on port 284 TCP/UDP.',
          'con' => 'Registered with IANA on port 759 TCP/UDP.',
          'New who' => 'Registered with IANA on port 550 TCP/UDP.',
          'QMQP' => 'Quick Mail Queuing Protocol, a protocol to share e-mail queues between several hosts.',
          'micom-pfs' => 'Registered with IANA on port 490 TCP/UDP.',
          'MPTN' => 'Multiprotocol Transport Networking, a general solution interconnected applications.',
          'IAX' => 'Inter-Asterisk eXchange, a protocol used by the Asterisk PBX.',
          'GIOP' => 'Communication between object request brokers.',
          'Eudora Set' => 'Protocol used by Eudora. IANA tcp/udp port 592.',
          'TenFold' => 'Registered with IANA on port 658 TCP/UDP.',
          'ISO SAP' => 'A Service Access Point (SAP) is an end-system in ISO networking.',
          'ipcd' => 'Registered with IANA on port 576 TCP/UDP.',
          'Quotad' => 'Registered with IANA on port 762 TCP/UDP.',
          'RRH' => 'Reverse Routing Header, used to learn a path back hop-by-hop.',
          'MobilIP-MN' => 'Registered with IANA on port 435 TCP/UDP.',
          'Synergy' => 'Lets users a mouse and keyboard between multiple computers.',
          'Micromuse-lm' => 'Registered with IANA on port 1534 TCP/UDP.',
          'QOTD' => 'Quote Of The Day service sends a short message without regard to the input.',
          'GSI-FTP' => 'The Globus GridFTP (GSI-FTP, Grid Security Infrastructure) is a secure FTP solution.',
          'Cabletron Management Protocol' => 'Registered with IANA on port 348 TCP/UDP.',
          'LWAPP' => 'Lightweight Access Point Protocol, a protocol that can control multiple Wi-Fi access points.',
          'Siam' => 'Registered with IANA on port 498 TCP/UDP.',
          'CadLock' => 'Cadlock is used to access AutoCad drawings protected by CadVault.',
          'Netnews Administration System' => 'A framework to simplify the administration and usage of network news (also known as Netnews) on the Internet.',
          'IMP Logical Address Maintenance' => 'Registered with IANA on port 51 TCP/UDP.',
          'VACDSM-SWS' => 'Registered with IANA on port 670 TCP/UDP.',
          'Radmin' => 'Remote Admin, a remote access solution.',
          'Commerce' => 'Registered with IANA on port 542 TCP/UDP.',
          'PKIX-3 CA/RA' => 'IANA tcp/udp port 829.',
          'trin00' => 'A set of computer programs to conduct a DDoS attack.',
          'CIMPLEX' => 'Registered with IANA on port 673 TCP/UDP.',
          'Orbix 2000 Locator over SSL' => 'Used by Progree Software Corporation in their Orbix software for enterprise COBRA solutions.',
          'DEC DLM' => 'Registered with IANA on port 625 TCP/UDP.',
          'contentserver' => 'A collaboration tool for web development.',
          'IEEE-MMS-SSL' => 'IEEE Media Management System, a distributed system for managing removable media.',
          'Klogin' => 'Registered with IANA on port 543 TCP/UDP.',
          'WAP secure connectionless session service' => 'Registered with IANA on port 9202 TCP/UDP.',
          'bmpp' => 'BMPP allows spammers to discover if a mailbox is willing to accept bulk email.',
          'SynOptics Trap' => 'Registered with IANA on port 412 UDP.',
          'AODV' => 'Ad hoc On-Demand Distance Vector (AODV) is a routing protocol for mobile ad hoc networks.',
          'Integra Software Management Environment' => 'Part of the Symantec Management Platform.',
          'cycleserv' => 'Registered with IANA on port 763 TCP/UDP.',
          'Omserv' => 'Registered with IANA on port 764 TCP/UDP.',
          'Aeolon Core Protocol' => 'Registered with IANA on port 599 TCP/UDP.',
          'RUSHD' => 'The Rush render queue allows users to manage image rendering jobs.',
          'DDM RRDA' => 'Distributed Data Management Remote Relational Database Access.',
          'MacOS Server Admin' => 'Remote administration/configuration tools for Mac OS X Server.',
          'rtip' => 'Registered with IANA on port 771 TCP/UDP.',
          'RAP' => 'Route Access Protocol, a general protocol for distributing routing information.',
          'RSVP' => 'Resource Reservation Protocol, a transport layer protocol.',
          'MaxDB' => 'SAP\'s relational database management system.',
          'NPP' => 'Network Printing Protocol, an old standard for network printing.',
          'Entrust-KMSH' => 'Entrust Key Management Service Handler is a cryptographic key management service.',
          'Internet telephony tool' => 'A set of data conferencing and telephony extensions for Netscape Navigator.',
          'DirectPlay' => 'Part of Microsoft\'s DirectX API.',
          'Radio Control Protocol' => 'Registered with IANA on port 469 TCP/UDP.',
          'Parsec Gameserver' => 'Parsec is a fast-paced non-commercial network space-shooter.',
          'Submit Protocol' => 'Registered with IANA on port 773 TCP.',
          'MSNP' => 'An instant messaging protocol developed by Microsoft for use by .NET Messenger Service and Windows Live Messenger.',
          'SDNS-KMP' => 'Secure Data Network System Key Management Protocol, a key management protocol for SDNS.',
          'AEP' => 'AppleTalk Echo Protocol.',
          'Loglogic' => 'Enterprise-class log management infrastructure.',
          'Tobit David Replica' => 'Enable a replication of the contents of any archives that are stored on different David Servers.',
          'digital-vrc' => 'Registered with IANA on port 466 TCP/UDP.',
          'OSUNMS' => 'OSU Network Monitoring System.',
          'XDMCP' => 'X Display Manager Control Protocol.',
          'PTP General' => 'Precision Time Protocol, used to synchronize clocks throughout a computer network.',
          'CMIP/TCP Manager' => 'Common Management Information Protocol, an OSI specified network management protocol.',
          'Phonebook' => 'Registered with IANA on port 767 TCP/UDP.',
          'Remote Method Invocation Activation' => 'Used with Java RMI.',
          'MPM FLAGS Protocol' => 'Registered with IANA on port 44 TCP/UDP.',
          'distcc' => 'Distributed Compiler Protocol is used with distributed compilers.',
          'ISO MMS' => 'Manufacturer Messaging Specification, the ISO session-layer protocol.',
          'InBusiness' => 'Administration of InBusiness line of small office network equipment. Registered with IANA on port 244/tcp.',
          'Microsoft System Center Operations Manager' => 'A cross-platform data center management system.',
          'campaign contribution disclosures' => 'Registered with IANA on port 667 TCP/UDP.',
          'Aurora CMGR' => 'Registered with IANA on port 364 TCP/UDP.',
          'DWR' => 'Registered with IANA on port 644 TCP/UDP.',
          'NBP' => 'AppleTalk Name Binding.',
          'Hardware Control Protocol Wismar' => 'Registered with IANA on port 686 TCP/UDP.',
          'AppleTalk Unused 207' => 'Registered with IANA on port 207 TCP/UDP.',
          'AMInet' => 'AMInet Protocol is used for communication and control of Alcorn McBride Inc. products.',
          'Netop Remote Control' => 'Remote management and support of enterprise IT infrastructure.',
          'dctp' => 'Registered with IANA on port 675 TCP/UDP.',
          'connendp' => 'Almanid Connection Endpoint (connendp) is a part of Novell Directory Services.',
          'Cybercash' => 'An online currency transfer system.',
          'smsd' => 'The smsd server is responsible for gathering system management data from the host and presenting that information to the SysMan Station client.',
          'McAfee AutoUpdate' => 'Update system used by McAfee products.',
          'ss7ns' => 'Registered with IANA on port 477 TCP/UDP.',
          'Virtual Presence Protocol' => 'Exchange of document based virtual presence information.',
          '3GPP' => 'GPRS Tunneling Protocol used for carrying user data.',
          'Kali' => 'An IPX network emulator for DOS and Windows.',
          'PTP Event' => 'Precision Time Protocol is a protocol used to synchronize clocks throughout a computer network.',
          'K-Block' => 'K-Block protects unattended logged-in terminals from unauthorized access in OpenVMS environments.',
          'dcLINK' => 'dcLINK Data Collection is inventory management software.',
          'errlog copy/server daemon' => 'Registered with IANA on port 704 TCP/UDP.',
          'Xfire' => 'Instant Messenger for gamers.',
          'RemoteFS' => 'RemoteFS is a network file system designed for use with home NAS.',
          'Microsoft Global Catalog' => 'A distributed data repository.',
          'World Fusion' => 'Registered with IANA on port 2595 TCP/UDP.',
          'ISO ILL Protocol' => 'Interlibrary Loan (ILL), for communication between various document exchange systems.',
          'Oracle TCP/IP Listener' => 'Registered with IANA on port 1525 TCP/UDP.',
          'Operations Manager - Health Service' => 'Health Monitoring Service is used to monitor web services installed in one or multiple sites.',
          'Covia' => 'Manages audio, video, data and other types of communication between multiple systems.',
          'PIM-RP-DISC' => 'Registered with IANA on port 496 TCP/UDP.',
          'Personal Link' => 'Registered with IANA on port 281 TCP/UDP.',
          'msg-icp' => 'Registered with IANA on port 29 TCP/UDP.',
          'Network Systems' => 'A collection of protocols layered atop Internet Datagram Protocol.',
          'Sitara Management' => 'The Sitara Network Protocol (SNP) manager.',
          'User Location Protocol' => 'Interface between a user location client and a user location server.',
          'ICL coNETion locate server' => 'Registered with IANA on port 886 TCP/UDP.',
          'ISO IP' => 'An ISO-specified network layer protocol.',
          'repscmd' => 'Repscmd is a protocol used by SupportSoft.',
          'IBM NetView DM' => 'IBM NetView Distribution Manager provides centralized management capabilities.',
          'P10' => 'An extension to Internet Relay Chat protocol (IRC) for server to server communications.',
          'auditd' => 'The audit daemon operates as a server, monitoring /dev/audit for local audit data.',
          'smpnameres' => 'Registered with IANA on port 901 TCP/UDP.',
          'Sitara Server' => 'The Sitara Network Protocol server.',
          'device' => 'Registered with IANA on port 801 TCP/UDP.',
          'Cray Network Semaphore server' => 'Registered with IANA on port 451 TCP/UDP.',
          'Applix ac' => 'Registered with IANA on port 999 UDP.',
          'WAP Session Service' => 'A component of Wireless Transaction Protocol (WTP).',
          'HP Network Management Center.' => 'Network and systems management product.',
          'Banyan VIP' => 'Banyan VINES Internet Protocol.',
          'Applejuice' => 'Peer-to-peer file sharing.',
          'PDL data streaming port' => 'Registered with IANA on port 9100 TCP/UDP.',
          'WAP vCard' => 'Internet Mail Consortium electronic business card.',
          'Hitachi Universal Storage Platform' => 'Hitachi brand enterprise storage arrays.',
          'Oracle Names' => 'Distributed naming service.',
          'NQS' => 'Network Queueing System, which allows users to submit batch jobs to queues.',
          'tn-tl-fd1' => 'IANA tcp/udp port 1571.',
          'RLZ Dbase' => 'Registered with IANA on port 635 TCP/UDP.',
          'Locus PC-Interface Conn Server' => 'Registered with IANA on port 127 TCP/UDP.',
          'Cray Unified Resource Manager' => 'Registered with IANA on port 606 TCP/UDP.',
          'ALPES' => 'Administration Delocalisee Par Emissions Securisee (ALPES) is a secure network administration protocol.',
          'PTC Name Service' => 'Used by Parametric Technology Corporation (PTC) in their products.',
          'entrust-aams' => 'Registered with IANA on port 681 TCP/UDP.',
          'Pharos psrserver' => 'Registered with IANA on port 2351 TCP/UDP.',
          'Oracle Remote Data Base' => 'IANA tcp/udp port 1571.',
          'Collaborator' => 'Registered with IANA on port 622 TCP/UDP.',
          'HELLO Port' => 'Part of Dynamic Tunnel Configuration Protocol (DTCP).',
          'VMware Fault Domain Manager' => 'High availability / fault tolerance protocol for VMware.',
          'Common Trace Facility' => 'Registered with IANA on port 84 TCP/UDP.',
          'Hamachi' => 'A hosted, secure VPN service.',
          'AppleTalk Unused 203' => 'Registered with IANA on port 203 TCP/UDP.',
          'War-rock' => 'Multiplayer first-person shooter game.',
          'Secure IRC' => 'Registered with IANA on port 994 TCP/UDP.',
          'SILC' => 'Secure Internet Live Conferencing, a protocol that provides IRC-like services.',
          'IBM NetView DM/6000 Server/Client' => 'IBM NetView Distribution Manager provides centralized management capabilities.',
          'Oracle Net8 CMan Admin' => 'Oracle Net8 CMan Admin refers to general administrative commands to Oracle Connection Manager.',
          'DDM DFM' => 'Distributed Data Management Distributed File Management.',
          'IRC-SERV' => 'A server software that implements the IRC Internet Relay Chat protocol.',
          'GDS DataBase' => 'Registered with IANA on port 3050 TCP/UDP.',
          'Konspire2b' => 'A content distribution system.',
          'Network based Rev. Cont. Sys.' => 'Registered with IANA on port 742 TCP/UDP.',
          'IBP' => 'Internet Backplane Protocol, middleware for managing and using remote storage.',
          'Ulpnet' => 'Registered with IANA on port 483 TCP/UDP.',
          'SANity' => 'SANity, Registered with IANA on port 643 TCP/UDP.',
          'AURP' => 'AppleTalk Update-based Routing Protocol (AURP) is an AppleTalk WAN routing protocol.',
          'SAFT' => 'Simple Asynchronous File Transfer, used by sendfile software.',
          'STUN over TLS' => 'Session Traversal Utilities for NAT using TLS encryption.',
          'CAB Protocol' => 'CAB Protocol exchanges real-time data between building automation systems.',
          'SUBNTBCST_TFTP' => 'Registered with IANA on port 247 TCP/UDP.',
          'Ident' => 'Protocol to identify the user who has opened an internet connection.',
          'Microsoft Shuttle' => 'Registered with IANA on port 568 TCP/UDP.',
          'NSIIOPS' => 'IIOP Name Service.',
          'MIT ML Device' => 'Registered with IANA on port 83 TCP/UDP.',
          'Direct TV Software Updates' => 'Registered with IANA on port 3335 TCP/UDP.',
          'intrinsa' => 'Registered with IANA on port 503 TCP/UDP.',
          'Meregister' => 'Registered with IANA on port 669 TCP/UDP.',
          'vsinet' => 'Registered with IANA on port 996 TCP/UDP.',
          'WAP vCal Secure' => 'Registered with IANA on port 9207 TCP/UDP.',
          'Tempo' => 'Calendar and appointment schedule app.',
          'Sonar' => 'Sonar is a network mirror service.',
          'WAP connectionless session service' => 'An open standard for maintaining high level WSD session.',
          'xvttp' => 'Registered with IANA on port 508 TCP/UDP.',
          'Retrospect' => 'A family of backup software applications.',
          'IPX over UDP' => 'Internetwork Packet Exchange encapsulated in UDP.',
          'Orbix 2000 Config' => 'Registered with IANA on port 3076 TCP/UDP.',
          'scx-proxy' => 'Registered with IANA on port 470 TCP/UDP.',
          'WLCCP' => 'Wireless LAN Context Control Protocol (WLCCP) is used by Cisco wireless devices to maintain Wireless Domain Services (WDS).',
          'DirecTV Data Catalog' => 'Consumer satellite data service.',
          'nCube License Manager' => 'A parallel computing protocol.',
          'CRYPTOAdmin' => 'CRYPTOAdmin a remote authentication solution.',
          'DataRampSrvSec' => 'Registered with IANA on port 462 TCP/UDP.',
          'Apertus Tech Load Distribution' => 'Registered with IANA on port 539 TCP/UDP.',
          'Vid' => 'Logitech Vid is a Video-over-IP service based on SightSpeed.',
          'NPMP Trap' => 'Registered with IANA on port 609 TCP/UDP.',
          'FLEXlm' => 'FlexNet license manager, a software license manager.',
          'DHCP Failover 2' => 'Provides synchronization between two DHCP servers.'
        };

--]]

require "DetectorCommon"

local DC = DetectorCommon

DetectorPackageInfo = {
    name = "content_group_port_services",
    proto =  DC.ipproto.tcp,
    client = {
        init =  'DetectorInit',
        clean =  'DetectorClean',
        minimum_matches =  1
    }
}

-- "AppId", "port", "protocol" (6 = TCP, 17 = UDP)
gPortServiceList = {

    -- ETOS
    {147, 377, 6},
    {147, 377, 17},
    {147, 378, 6},
    {147, 378, 17},

    -- 3Com AMP3
    {3000, 629, 6},
    {3000, 629, 17},

    -- Access Network
    {3001, 699, 6},
    {3001, 699, 17},

    -- AccessBuilder
    {3002, 888, 6},
    {3002, 888, 17},

    -- Ad hoc On-Demand Distance Vector Routing
    {3003, 654, 6},
    {3003, 654, 17},

    -- Adaptive Receive Node Scheduling
    {35, 384, 6},
    {35, 384, 17},

    -- Administration Delocalisee Par Emissions Securisee (remote administration using secured messages)
    {3005, 463, 6},
    {3005, 463, 17},

    -- Adobe PostScript
    {3006, 170, 6},
    {3006, 170, 17},

    -- Aeolon Core Protocol
    {3007, 599, 6},
    {3007, 599, 17},

    -- AgentX
    {3008, 705, 6},
    {3008, 705, 17},

    -- Almanid Connection Endpoint
    {3009, 693, 6},
    {3009, 693, 17},

    -- American Power Conversion PowerChute
    {3010, 2160, 6},
    {3010, 2161, 6},
    {3010, 2260, 6},
    {3010, 3052, 6},
    {3010, 3506, 6},
    {3010, 5454, 6},
    {3010, 5455, 6},
    {3010, 5456, 6},
    {3010, 6547, 6},
    {3010, 6548, 6},
    {3010, 6549, 6},
    {3010, 7845, 6},
    {3010, 7846, 6},
    {3010, 9950, 6},
    {3010, 9951, 6},
    {3010, 9952, 6},
    {3010, 2160, 17},
    {3010, 2161, 17},
    {3010, 2260, 17},
    {3010, 3052, 17},
    {3010, 3506, 17},
    {3010, 5454, 17},
    {3010, 5455, 17},
    {3010, 5456, 17},
    {3010, 6547, 17},
    {3010, 6548, 17},
    {3010, 6549, 17},
    {3010, 7845, 17},
    {3010, 7846, 17},
    {3010, 9950, 17},
    {3010, 9951, 17},
    {3010, 9952, 17},

    -- AMInet
    {3011, 2639, 6},
    {3011, 2639, 17},

    -- Apertus Tech Load Distribution
    {3012, 539, 6},
    {3012, 539, 17},

    -- appleqtcsrvr
    {3013, 545, 6},
    {3013, 545, 17},

    -- AppleTalk Echo
    {3014, 204, 6},
    {3014, 204, 17},

    -- AppleTalk Name Binding
    {3015, 202, 6},
    {3015, 202, 17},

    -- AppleTalk Routing Maintenance
    {3016, 201, 6},
    {3016, 201, 17},

    -- AppleTalk Unused
    {3017, 203, 6},
    {3017, 203, 17},

    -- AppleTalk Unused
    {3018, 205, 6},
    {3018, 205, 17},

    -- AppleTalk Unused
    {3019, 207, 6},
    {3019, 207, 17},

    -- AppleTalk Unused
    {3020, 208, 6},
    {3020, 208, 17},

    -- AppleTalk Update-based Routing Protocol
    {3021, 387, 6},
    {3021, 387, 17},

    -- AppleTalk Zone Information Protocol
    {3022, 206, 6},
    {3022, 206, 17},

    -- ApplianceWare Managment Protocol
    {3023, 688, 6},
    {3023, 688, 17},

    -- Application Configuration Access Protocol
    {3024, 674, 6},
    {3024, 674, 17},

    -- Applix ac
    {3025, 999, 6},
    {3025, 999, 17},

    -- Ariel2
    {3026, 421, 6},
    {3026, 421, 17},

    -- Ariel3
    {3027, 422, 6},
    {3027, 422, 17},

    -- AS Server Mapper
    {3028, 449, 6},
    {3028, 449, 17},

    -- asa-appl-proto
    {3029, 502, 6},
    {3029, 502, 17},

    -- Asipregistry
    {3030, 687, 6},
    {3030, 687, 17},

    -- ATEXSSTR
    -- {3031, 212, 6},
    -- {3031, 212, 17},

    -- Aurora CMGR
    {3032, 364, 6},
    {3032, 364, 17},

    -- ident
    {956, 113, 6},
    {956, 113, 17},

    -- Automated Data Collection Solution
    {3034, 6305, 6},
    {3034, 6800, 6},

    -- Avian
    {3035, 486, 6},
    {3035, 486, 17},

    -- Banyan VIP
    {3036, 573, 6},
    {3036, 573, 17},

    -- banyan-rpc
    {3037, 567, 6},
    {3037, 567, 17},

    -- Berkeley rshd with SPX auth
    {3038, 222, 6},
    {3038, 222, 17},

    -- bgs-nsi
    {3039, 482, 6},
    {3039, 482, 17},

    -- bmpp
    {3040, 632, 6},
    {3040, 632, 17},

    -- Borland DSJ
    {3041, 707, 6},
    {3041, 707, 17},

    -- Britton Lee IDM
    {65, 142, 6},
    {65, 142, 17},

    -- Building Automation and Control Networks
    {3043, 47808, 6},
    {3043, 47808, 17},

    -- CAB Protocol
    {3044, 595, 6},
    {3044, 595, 17},

    -- Cabletron Management Protocol
    {3045, 348, 6},
    {3045, 348, 17},

    -- CadLock
    {3046, 770, 6},
    {3046, 770, 17},

    -- Call of Duty
    {3047, 20500, 6},
    {3047, 20510, 6},
    {3047, 28960, 6},
    {3047, 20500, 17},

    -- campaign contribution disclosures
    {3048, 667, 6},
    {3048, 667, 17},

    -- Chat
    {3049, 531, 6},
    {3049, 531, 17},

    -- Chshell
    {3050, 562, 6},
    {3050, 562, 17},

    -- CIMPLEX
    {3051, 673, 6},
    {3051, 673, 17},

    -- Cisco NAC
    {3052, 8905, 17},
    {3052, 8906, 17},

    -- Citrix Static
    {3053, 1604, 6},
    {3053, 2512, 6},
    {3053, 2513, 6},
    {3053, 1604, 17},
    {3053, 2512, 17},
    {3053, 2513, 17},

    -- CMIP/TCP Manager
    {3054, 163, 6},
    {3054, 163, 17},

    -- Coherent File Distribution Protocol
    {3055, 120, 6},
    {3055, 120, 17},

    -- Collaborator
    {3056, 622, 6},
    {3056, 622, 17},

    -- Commerce
    {3057, 542, 6},
    {3057, 542, 17},

    -- Common Trace Facility
    {3058, 84, 6},
    {3058, 84, 17},

    -- Communications Integrator
    {3059, 64, 6},
    {3059, 64, 17},

    -- Compact Disc DataBase Protocol
    {3060, 8880, 6},
    {3060, 8880, 17},

    -- Compaq Insight Manager Service
    {3061, 2301, 6},
    {3061, 2301, 17},

    -- Computer Associates Intl License Server
    {3062, 216, 6},
    {3062, 216, 17},

    -- Computer Resources Sharing Application
    {3063, 24800, 6},

    -- Computer Supported Telecomunication Applications
    {3064, 450, 6},
    {3064, 450, 17},

    -- con
    {3065, 759, 6},
    {3065, 759, 17},

    -- contentserver
    {3066, 3365, 6},
    {3066, 3365, 17},

    -- Corejrd
    {3067, 284, 6},
    {3067, 284, 17},

    -- Courier Mail Server
    {3068, 530, 6},
    {3068, 530, 17},

    -- Cray Network Semaphore server
    {3069, 451, 6},
    {3069, 451, 17},

    -- Cray SFS config server
    {3070, 452, 6},
    {3070, 452, 17},

    -- Cray Unified Resource Manager
    {3071, 606, 6},
    {3071, 606, 17},

    -- Creative Partner
    {3072, 455, 6},
    {3072, 455, 17},

    -- Creative Server
    {3073, 453, 6},
    {3073, 453, 17},

    -- CRYPTOAdmin
    {3074, 624, 6},
    {3074, 624, 17},

    -- CSNET Mailbox Name Nameserver
    {3075, 105, 6},
    {3075, 105, 17},

    -- Customer Ixchange
    {3076, 528, 6},
    {3076, 528, 17},

    -- cvc_hostd
    {3077, 442, 6},
    {3077, 442, 17},

    -- CVS pserver
    {3078, 2401, 6},
    {3078, 2401, 17},

    -- Cybercash
    {3079, 551, 6},
    {3079, 551, 17},

    -- cycleserv
    {3080, 763, 6},
    {3080, 763, 17},

    -- cycleserv2
    {3081, 772, 6},
    {3081, 772, 17},

    -- Dantz Retrospect
    {3082, 497, 6},
    {3082, 497, 17},

    -- DataRamp Svr
    {3083, 461, 6},
    {3083, 461, 17},

    -- DataRampSrvSec
    {3084, 462, 6},
    {3084, 462, 17},

    -- DCE endpoint resolution
    {3085, 135, 6},
    {3085, 135, 17},

    -- dctp
    {3086, 675, 6},
    {3086, 675, 17},

    -- DDM Distributed File management
    {3087, 447, 6},
    {3087, 447, 17},

    -- DDM-Remote Relational Database Access
    {3088, 446, 6},
    {3088, 446, 17},

    -- DEC DLM
    {3089, 625, 6},
    {3089, 625, 17},

    -- decap
    {3090, 403, 6},
    {3090, 403, 17},

    -- Decbsrv
    {3091, 579, 6},
    {3091, 579, 17},

    -- Deception ToolKit
    {131, 365, 6},
    {131, 365, 17},

    -- DEI-ICDA
    {3093, 618, 6},
    {3093, 618, 17},

    -- Desknet's
    {3094, 52300, 6},

    -- device
    {3095, 801, 6},
    {3095, 801, 17},

    -- DHCP Failover
    {3096, 647, 6},
    {3096, 647, 17},

    -- DHCP-Failover 2
    {3097, 847, 6},
    {3097, 847, 17},

    -- DHCPv6 Client
    {3098, 546, 6},
    {3098, 546, 17},

    -- Digital Audit daemon
    {41, 48, 6},
    {41, 48, 17},

    -- digital-vrc
    {3100, 466, 6},
    {3100, 466, 17},

    -- Direct TV Software Updates
    {3101, 3335, 6},
    {3101, 3335, 17},

    -- Direct TV Tickers
    {3102, 3336, 6},
    {3102, 3336, 17},

    -- DirectPlay
    {3103, 2234, 6},
    {3103, 2234, 17},

    -- DirectPlay8
    {3104, 6073, 6},
    {3104, 6073, 17},

    -- DirecTV Data Catalog
    {3105, 3337, 6},
    {3105, 3337, 17},

    -- DirecTV Webcasting
    {3106, 3334, 6},
    {3106, 3334, 17},

    -- Distributed Compiler
    {3107, 3632, 6},
    {3107, 3632, 17},

    -- Distributed External Object Store
    {115, 76, 6},
    {115, 76, 17},

    -- Domino Domain Monitor database - Remote DB Access Using Secure Sockets
    {3109, 448, 6},
    {3109, 448, 17},

    -- DOOM
    {3110, 666, 6},
    {3110, 666, 17},

    -- DWR
    {3111, 644, 6},
    {3111, 644, 17},

    -- eDonkey Static
    {3112, 4661, 6},
    {3112, 4662, 6},
    {3112, 4663, 6},
    {3112, 4664, 6},
    {3112, 4665, 6},
    {3112, 4672, 6},
    {3112, 4673, 6},
    {3112, 4711, 6},
    {3112, 5662, 6},
    {3112, 5773, 6},
    {3112, 5783, 6},
    {3112, 4661, 17},
    {3112, 4662, 17},
    {3112, 4663, 17},
    {3112, 4664, 17},
    {3112, 4665, 17},
    {3112, 4672, 17},
    {3112, 4673, 17},
    {3112, 4711, 17},
    {3112, 5662, 17},
    {3112, 5773, 17},
    {3112, 5783, 17},

    -- EMC SmartPackets
    {3113, 3218, 6},
    {3113, 3218, 17},

    -- entomb
    {3114, 775, 6},
    {3114, 775, 17},

    -- Entrust Administration Service Handler
    {3115, 710, 6},
    {3115, 710, 17},

    -- Entrust Key Management Service Handler
    {3116, 709, 6},
    {3116, 709, 17},

    -- Entrust SPS
    {3117, 640, 6},
    {3117, 640, 17},

    -- entrust-aaas
    {3118, 680, 6},
    {3118, 680, 17},

    -- entrust-aams
    {3119, 681, 6},
    {3119, 681, 17},

    -- errlog copy/server daemon
    {3120, 704, 6},
    {3120, 704, 17},

    -- ESCP
    {3121, 621, 6},
    {3121, 621, 17},

    -- eSignal
    {3122, 2189, 6},
    {3122, 2194, 6},
    {3122, 2196, 6},

    -- eXtensible Data Transfer Protocol
    {3123, 3088, 6},
    {3123, 3088, 17},

    -- FirstClass Protocol
    {3124, 510, 6},
    {3124, 510, 17},

    -- Flexible License Manager
    {3125, 744, 6},
    {3125, 744, 17},

    -- FTP Software Agent System
    {3126, 574, 6},
    {3126, 574, 17},

    -- Fujitsu Device Control
    {3127, 747, 6},
    {3127, 747, 17},

    -- gdomap
    {3128, 538, 6},
    {3128, 538, 17},

    -- GDS DataBase
    {3129, 3050, 6},
    {3129, 3050, 17},

    -- ginad
    {3130, 634, 6},
    {3130, 634, 17},

    -- Globus GridFTP
    {3131, 2811, 6},
    {3131, 2811, 17},

    -- GNU Generation Foundation NCP
    {3132, 678, 6},
    {3132, 678, 17},

    -- GNU Generation Foundation NCP
    {3133, 128, 6},
    {3133, 128, 17},

    -- GNU Krell Monitors
    {3134, 19150, 6},

    -- GoBoogy
    {3135, 5325, 6},
    {3135, 5325, 17},

    -- GotoDevice
    {3136, 2217, 6},
    {3136, 2217, 17},

    -- Graphics
    {3137, 41, 6},
    {3137, 41, 17},

    -- GraphOn Login
    {3138, 491, 6},
    {3138, 491, 17},

    -- Groove
    {3139, 2492, 6},
    {3139, 2492, 17},

    -- GTP-User Plane (3GPP)
    {3140, 2152, 6},
    {3140, 2152, 17},

    -- ha-cluster
    {3141, 694, 6},
    {3141, 694, 17},

    -- Hardware Control Protocol Wismar
    {3142, 686, 6},
    {3142, 686, 17},

    -- HELLO Port
    {3143, 652, 6},
    {3143, 652, 17},

    -- Heroix Longitude
    {3144, 7220, 6},
    {3144, 7223, 6},

    -- Hierarchical Access System for Sequence Libraries in Europe
    {197, 375, 6},
    {197, 375, 17},

    -- High-Level Entity Management System
    {199, 151, 6},
    {199, 151, 17},

    -- Hitachi Universal Storage Platform
    {3147, 20016, 6},

    -- HMMP Indication
    {3148, 612, 6},
    {3148, 612, 17},

    -- HMMP Operation
    {3149, 613, 6},
    {3149, 613, 17},

    -- Host Access Protocol
    {3150, 661, 6},
    {3150, 661, 17},

    -- HP Network Management Center.
    {3151, 383, 6},
    {3151, 383, 17},

    -- HTTP Alternate
    --{3152, 8080, 6},
    --{3152, 8080, 17},

    -- HTTP RPC Ep Map
    {3153, 593, 6},
    {3153, 593, 17},

    -- Hybrid Point of Presence
    {3154, 473, 6},
    {3154, 473, 17},

    -- Hyperwave-ISP
    {3155, 692, 6},
    {3155, 692, 17},

    -- iafdbase
    {3156, 480, 6},
    {3156, 480, 17},

    -- IAFServer
    {3157, 479, 6},
    {3157, 479, 17},

    -- IBM Director
    {3158, 4490, 6},
    {3158, 4491, 6},
    {3158, 6090, 6},
    {3158, 14247, 6},
    {3158, 14248, 6},
    {3158, 14249, 6},
    {3158, 15988, 6},
    {3158, 15989, 6},
    {3158, 34572, 6},
    {3158, 14247, 17},
    {3158, 14248, 17},
    {3158, 14249, 17},
    {3158, 15988, 17},
    {3158, 15989, 17},
    {3158, 34572, 17},
    {3158, 4490, 17},
    {3158, 4491, 17},
    {3158, 6090, 17},
    {3158, 13991, 17},

    -- IBM NetView DM
    {3160, 730, 6},
    {3160, 730, 17},
    {3160, 731, 6},
    {3160, 731, 17},

    -- IBM NetView DM/6000 Server/Client
    {3161, 729, 6},
    {3161, 729, 17},

    -- ICL coNETion locate server
    {3162, 886, 6},
    {3162, 886, 17},

    -- ICL coNETion server info
    {3163, 887, 6},
    {3163, 887, 17},

    -- idfp
    {3164, 549, 6},
    {3164, 549, 17},

    -- IEEE-MMS-SSL
    {3165, 695, 6},
    {3165, 695, 17},

    -- NSIIOPS
    {338, 261, 6},
    {338, 261, 17},

    -- IMP Logical Address Maintenance
    {3167, 51, 6},
    {3167, 51, 17},

    -- Intecourier
    {3168, 495, 6},
    {3168, 495, 17},

    -- Integra Software Management Environment
    {3169, 484, 6},
    {3169, 484, 17},

    -- Intel InBusiness
    {228, 244, 6},
    {228, 244, 17},

    -- Interactive Mail Support Protocol
    {227, 406, 6},
    {227, 406, 17},

    -- Internet Backplane Protocol
    {3172, 6714, 6},
    {3172, 6714, 17},

    -- Internet Configuration Manager
    {3173, 615, 6},
    {3173, 615, 17},

    -- Internet telephony tool
    {3176, 6499, 6},

    -- Internet video conference system
    {3177, 7648, 6},
    {3177, 7649, 6},
    {3177, 7648, 17},
    {3177, 7649, 17},
    {3177, 24032, 17},

    -- Internetwork Packet Exchange Protocol
    {3178, 213, 6},
    {3178, 213, 17},

    -- intrinsa
    {3179, 503, 6},
    {3179, 503, 17},

    -- ipcd
    {3180, 576, 6},
    {3180, 576, 17},

    -- ipdd
    {3181, 578, 6},
    {3181, 578, 17},

    -- IPX network emulator for DOS and Windows
    {3182, 2213, 6},
    {3182, 2213, 17},

    -- IRC-SERV
    {3183, 529, 6},
    {3183, 529, 17},

    -- ISO ILL Protocol
    {3184, 499, 6},
    {3184, 499, 17},

    -- ISO Transport Class 2 Non-Control over TCP
    {3185, 399, 6},
    {3185, 399, 17},

    -- ISO Transport Service Access Point
    {3186, 102, 6},
    {3186, 102, 17},

    -- iso-ip
    {3843, 147, 6},
    {3843, 147, 17},

    -- ISO-TP0
    {3188, 146, 6},
    {3188, 146, 17},

    -- itm-mcell-s
    {3189, 828, 6},
    {3189, 828, 17},

    -- K-Block
    {249, 287, 6},
    {249, 287, 17},

    -- Kerberos Administration
    {3191, 749, 6},
    {3191, 749, 17},

    -- Key Server
    {3192, 584, 6},
    {3192, 584, 17},

    -- Klogin
    {3193, 543, 6},
    {3193, 543, 17},

    -- Konspire2b
    {3194, 6085, 6},
    {3194, 6085, 17},

    -- kpasswd
    {3195, 464, 6},
    {3195, 464, 17},

    -- kshell
    {3196, 544, 6},
    {3196, 544, 17},

    -- Label Distribution Protocol
    {3197, 646, 6},
    {3197, 646, 17},

    -- lanserver
    {3198, 637, 6},
    {3198, 637, 17},

    -- Lightweight Access Point Protocol
    {3199, 12222, 17},
    {3199, 12223, 17},

    -- List Processor
    {481, 372, 6},
    {481, 372, 17},

    -- ljk-login
    {3201, 472, 6},
    {3201, 472, 17},

    -- Locus PC-Interface Conn Server
    {3202, 127, 6},
    {3202, 127, 17},

    -- Loglogic
    {3203, 4514, 6},
    {3203, 11965, 6},

    -- MacOS Server Admin
    {3204, 660, 6},
    {3204, 660, 17},

    -- Mail Submission Agent
    {3205, 587, 17},

    -- Mailbox-LM
    {3206, 505, 6},
    {3206, 505, 17},

    -- maitrd
    {3207, 997, 6},
    {3207, 997, 17},

    -- Management Utility
    {3208, 2, 6},
    {3208, 2, 17},

    -- mcns-sec
    {3209, 638, 6},
    {3209, 638, 17},

    -- mdc-portmapper
    {3210, 685, 6},
    {3210, 685, 17},

    -- Memcomm
    {3211, 668, 6},
    {3211, 668, 17},

    -- Meregister
    {3212, 669, 6},
    {3212, 669, 17},

    -- Message Processing Module
    {300, 45, 6},
    {300, 45, 17},

    -- Meter
    {3214, 570, 6},
    {3214, 570, 17},

    -- micom-pfs
    {3215, 490, 6},
    {3215, 490, 17},

    -- MF Cobol
    {290, 86, 6},
    {290, 86, 17},

    -- Micromuse-lm
    {3217, 1534, 6},
    {3217, 1534, 17},

    -- Microsoft Global Catalog
    {3218, 3268, 6},
    {3218, 3268, 17},

    -- Microsoft Media Server
    {735, 1755, 6},
    {735, 1755, 17},

    -- Microsoft Rome
    {3220, 569, 6},
    {3220, 569, 17},

    -- Microsoft Shuttle
    {3221, 568, 6},
    {3221, 568, 17},

    -- Microsoft System Center Operations Manager
    {3222, 1270, 6},
    {3222, 1270, 17},

    -- Microsoft-DS
    --{3223, 445, 6},
    --{3223, 445, 17},

    -- MIT ML Device
    {3224, 83, 6},
    {3224, 83, 17},

    -- MobilIP-MN
    {3225, 435, 6},
    {3225, 435, 17},

    -- Mobility XE protocol
    {3226, 6997, 6},
    {3226, 6997, 17},

    -- Mondex
    {3227, 471, 6},
    {3227, 471, 17},

    -- Monitor
    {3228, 561, 6},
    {3228, 561, 17},

    -- MPM FLAGS Protocol
    {3229, 44, 6},
    {3229, 44, 17},

    -- MS Exchange Routing
    {3230, 691, 6},
    {3230, 691, 17},

    -- msg-icp
    {3231, 29, 6},
    {3231, 29, 17},

    -- Multi-link Multi-node PPP Bundle Discovery Protocol
    {3232, 581, 6},
    {3232, 581, 17},

    -- Multicast Routing Monitor
    {3233, 679, 6},
    {3233, 679, 17},

    -- Multiling HTTP
    {3234, 777, 6},
    {3234, 777, 17},

    -- Multiprotocol Transport Network
    {302, 397, 6},
    {302, 397, 17},

    -- Multisource File Transfer Protocol
    {291, 349, 6},
    {291, 349, 17},

    -- Mylex-mapd
    {3237, 467, 6},
    {3237, 467, 17},

    -- nCube License Manager
    {3238, 1521, 6},
    {3238, 1521, 17},

    -- Nest Protocol
    {3239, 489, 6},
    {3239, 489, 17},

    -- netGW
    {3240, 741, 6},
    {3240, 741, 17},

    -- Netix Message Posting Protocol
    {3241, 218, 6},
    {3241, 218, 17},

    -- Netnews
    {3242, 532, 6},
    {3242, 532, 17},

    -- Netnews Administration System
    {3243, 991, 6},
    {3243, 991, 17},

    -- Netop Remote Control
    {3244, 1970, 6},
    {3244, 1971, 6},
    {3244, 6502, 6},
    {3244, 1970, 17},
    {3244, 1971, 17},
    {3244, 6502, 17},
    {3244, 26137, 17},

    -- Network based Rev. Cont. Sys.
    {3245, 742, 6},
    {3245, 742, 17},

    -- Network Data Management Protocol
    {1096, 10000, 6},

    -- Network Innovations Multiplex
    {3247, 171, 6},
    {3247, 171, 17},

    -- Network Mapper
    {3248, 689, 6},
    {3248, 689, 17},

    -- Network Printing Protocol
    {337, 92, 6},
    {337, 92, 17},

    -- Network Queueing System
    {3250, 607, 6},
    {3250, 607, 17},

    -- Network Security Risk Management Protocol
    {339, 359, 6},
    {339, 359, 17},

    -- Network Systems
    {3252, 760, 6},
    {3252, 760, 17},

    -- Networked Media Streaming Protocol
    {3253, 537, 6},
    {3253, 537, 17},

    -- New who
    {3254, 550, 6},
    {3254, 550, 17},

    -- NFS Lock Daemon Manager
    {3255, 4045, 6},
    {3255, 4045, 17},

    -- NIC  Internet Hostname Server
    {671, 101, 6},
    {671, 101, 17},

    -- nlogin
    {3257, 758, 6},
    {3257, 758, 17},

    -- Novadigm Enterprise Desktop Manager
    {3258, 3460, 6},
    {3258, 3461, 6},
    {3258, 3462, 6},
    {3258, 3463, 6},
    {3258, 3464, 6},
    {3258, 3465, 6},
    {3258, 3460, 17},
    {3258, 3461, 17},
    {3258, 3462, 17},
    {3258, 3463, 17},
    {3258, 3464, 17},
    {3258, 3465, 17},

    -- Novell Netware over IP
    {3259, 396, 6},
    {3259, 396, 17},

    -- NPMP Trap
    {3260, 609, 6},
    {3260, 609, 17},

    -- npmp-gui
    {3261, 611, 6},
    {3261, 611, 17},

    -- npmp-local
    {3262, 610, 6},
    {3262, 610, 17},

    -- NSW User System FE
    {3263, 27, 6},
    {3263, 27, 17},

    -- OBject EXchange
    {3264, 650, 6},
    {3264, 650, 17},

    -- OCS_CMU
    {3265, 428, 6},
    {3265, 428, 17},

    -- Ohimsrv
    {3266, 506, 6},
    {3266, 506, 17},

    -- Omginitialrefs
    {3267, 900, 6},
    {3267, 900, 17},

    -- Omserv
    {3268, 764, 6},
    {3268, 764, 17},

    -- opalis-rdv
    {3269, 536, 6},
    {3269, 536, 17},

    -- openvms-sysipc
    {3270, 557, 6},
    {3270, 557, 17},

    -- Operations Manager - Health Service
    {3271, 5723, 6},
    {3271, 5723, 17},

    -- oracle
    {3272, 1527, 6},
    {3272, 1527, 17},

    -- Oracle coauthor
    {3273, 1529, 6},
    {3273, 1529, 17},

    -- Oracle Names
    {3274, 1575, 6},
    {3274, 1575, 17},

    -- Oracle Net8 Cman
    {3275, 1630, 6},
    {3275, 1630, 17},

    -- Oracle Net8 CMan Admin
    {3276, 1830, 6},
    {3276, 1830, 17},

    -- Oracle TCP/IP Listener
    {3277, 1525, 6},
    {3277, 1525, 17},

    -- Orbix 2000 Config
    {3278, 3076, 6},
    {3278, 3076, 17},

    -- Orbix 2000 Locator
    {3279, 3075, 6},
    {3279, 3075, 17},

    -- Orbix 2000 Locator over SSL
    {3280, 3077, 6},
    {3280, 3077, 17},

    -- OSU Network Monitoring System
    {358, 192, 6},
    {358, 192, 17},

    -- P10
    {3282, 6665, 6},
    {3282, 6666, 6},
    {3282, 6667, 6},
    {3282, 6668, 6},
    {3282, 6669, 6},
    {3282, 6665, 17},
    {3282, 6666, 17},
    {3282, 6667, 17},
    {3282, 6668, 17},
    {3282, 6669, 17},

    -- Parsec Gameserver
    {3283, 6582, 6},
    {3283, 6582, 17},

    -- PassGo Technologies Service
    {3285, 511, 6},
    {3285, 511, 17},
    {3285, 627, 6},
    {3285, 627, 17},

    -- Password Change
    {3286, 586, 6},
    {3286, 586, 17},

    -- PDL data streaming port
    {3287, 9100, 6},
    {3287, 9100, 17},

    -- Perf Analysis Workbench
    {361, 345, 6},
    {361, 345, 17},

    -- Persistence of Vision Raytracer
    {3289, 494, 6},
    {3289, 494, 17},

    -- Personal Link
    {3290, 281, 6},
    {3290, 281, 17},

    -- Pharos psrserver
    {3291, 2351, 6},
    {3291, 2351, 17},

    -- Philips Video-Conferencing
    {3292, 583, 6},
    {3292, 583, 17},

    -- Phonebook
    {3293, 767, 6},
    {3293, 767, 17},

    -- Photuris
    {3294, 468, 6},
    {3294, 468, 17},

    -- PIM-RP-DISC
    {3295, 496, 6},
    {3295, 496, 17},

    -- pirp
    {3296, 553, 6},
    {3296, 553, 17},

    -- Plus Fives MUMPS
    {3297, 188, 6},
    {3297, 188, 17},

    -- Precision Time Protocol Event
    {3298, 319, 6},
    {3298, 319, 17},

    -- Process Application Programming Interface
    {3299, 8211, 17},

    -- Prospero Resource Manager Node Man.
    {3300, 409, 6},
    {3300, 409, 17},

    -- Prospero Resource Manager Sys. Man
    {3301, 408, 6},
    {3301, 408, 17},

    -- PTC Name Service
    {3302, 597, 6},
    {3302, 597, 17},

    -- PTP General
    {3303, 320, 6},
    {3303, 320, 17},

    -- pump
    {3304, 751, 6},
    {3304, 751, 17},

    -- PureNoise
    {3305, 663, 6},
    {3305, 663, 17},

    -- qrh
    {3306, 752, 6},
    {3306, 752, 17},

    -- Queued File Transport
    {383, 189, 6},
    {383, 189, 17},

    -- Quick Mail Queuing Protocol
    {3308, 628, 6},
    {3308, 628, 17},

    -- Quick Mail Transfer Protocol
    {384, 209, 6},
    {384, 209, 17},

    -- Quotad
    {3310, 762, 6},
    {3310, 762, 17},

    -- Quote of the Day
    {385, 17, 6},
    {385, 17, 17},

    -- Radio Control Protocol
    {3312, 469, 6},
    {3312, 469, 17},

    -- Rational Method Composer
    {3313, 657, 6},
    {3313, 657, 17},

    -- REAL SQL Server
    {3314, 118, 6},
    {3314, 118, 17},

    -- Remote Admin
    {3315, 4899, 6},
    {3315, 4899, 17},

    -- Remote Database Access
    {3316, 630, 6},
    {3316, 630, 17},

    -- Remote Mail Checking Protocol
    {3317, 50, 6},
    {3317, 50, 17},

    -- Remote Method Invocation Activation
    {3318, 1098, 6},
    {3318, 1098, 17},

    -- Remote MT Protocol
    {3319, 411, 17},

    -- Remote-KIS
    {3320, 185, 6},
    {3320, 185, 17},

    -- RemoteFS
    {3321, 556, 6},
    {3321, 556, 17},

    -- repcmd
    {3322, 641, 6},
    {3322, 641, 17},

    -- repscmd
    {3323, 653, 6},
    {3323, 653, 17},

    -- Resource Reservation Protocol
    {3938, 1698, 6},
    {3948, 1698, 17},
    {3948, 1699, 6},
    {3948, 1699, 17},

    -- Reverse Routing Header
    {3326, 753, 6},
    {3326, 753, 17},

    -- RLZ Dbase
    {3327, 635, 6},
    {3327, 635, 17},

    -- rmiregistry
    {3328, 1099, 6},
    {3328, 1099, 17},

    -- Rmonitor
    {3329, 560, 6},
    {3329, 560, 17},

    -- Route Access Protocol
    {388, 38, 6},
    {388, 38, 17},

    -- Routing Diagnostics Tool
    {3331, 33435, 17},

    -- RSVP Tunnel
    {3332, 363, 6},
    {3332, 363, 17},

    -- rtip
    {3333, 771, 6},
    {3333, 771, 17},

    -- RUSHD
    {3334, 696, 6},
    {3334, 696, 17},

    -- Russell Info Sci Calendar Manager
    {3335, 748, 6},
    {3335, 748, 17},

    -- rxe
    {3336, 761, 6},
    {3336, 761, 17},

    -- SANity
    {3337, 643, 6},
    {3337, 643, 17},

    -- SAP
    {3338, 3200, 6},
    {3338, 3300, 6},
    {3338, 3600, 6},

    -- SCC Security
    {3339, 582, 6},
    {3339, 582, 17},

    -- SCO Desktop Administration Server
    {3340, 617, 6},
    {3340, 617, 17},

    -- SCO System Administration Server
    {3341, 616, 6},
    {3341, 616, 17},

    -- SCO Web Server Manager 3
    {3342, 598, 6},
    {3342, 598, 17},

    -- SCO WebServer Manager
    {3343, 620, 6},
    {3343, 620, 17},

    -- scohelp
    {3344, 457, 6},
    {3344, 457, 17},

    -- SCSI on ST
    {3345, 266, 6},
    {3345, 266, 17},

    -- scx-proxy
    {3346, 470, 6},
    {3346, 470, 17},

    -- Secure Data Network System Key Management Protocol
    {3347, 558, 6},
    {3347, 558, 17},

    -- Secure Electronic Transaction
    {419, 257, 6},
    {419, 257, 17},

    -- Secure Internet Live Conferencing
    {3349, 706, 6},
    {3349, 706, 17},

    -- Secure IRC
    {3350, 994, 6},
    {3350, 994, 17},

    -- Secure management and installation discovery
    {3351, 3211, 6},
    {3351, 3502, 6},
    {3351, 3871, 6},
    {3351, 3211, 17},
    {3351, 3502, 17},
    {3351, 3871, 17},

    -- Secure Neighbor Discovery
    {418, 169, 6},
    {418, 169, 17},

    -- Secure Network News Transfer Protocol
    {3353, 563, 6},
    {3353, 563, 17},

    -- Sender-Initiated/Unsolicited File Transfer
    {3354, 608, 6},
    {3354, 608, 17},

    -- Server Location
    {3355, 427, 6},
    {3355, 427, 17},

    -- Sflow Traffic Monitoring
    {3356, 6343, 6},
    {3356, 6343, 17},

    -- Siam
    {3357, 498, 6},
    {3357, 498, 17},

    -- Simple Asynchronous File Transfer
    {3358, 487, 6},
    {3358, 487, 17},

    -- Simple Network Time Protocol Heartbeat
    {3359, 580, 6},
    {3359, 580, 17},

    -- Sirius Systems
    {439, 166, 6},
    {439, 166, 17},

    -- Sitara Dir
    {3361, 2631, 6},
    {3361, 2631, 17},

    -- Sitara Management
    {3362, 2630, 6},
    {3362, 2630, 17},

    -- Sitara Server
    {3363, 2629, 6},
    {3363, 2629, 17},

    -- Skronk
    {3364, 460, 6},
    {3364, 460, 17},

    -- smartsdp
    {434, 426, 6},
    {434, 426, 17},

    -- smpnameres
    {3366, 901, 6},
    {3366, 901, 17},

    -- smsd
    {3367, 596, 6},
    {3367, 596, 17},

    -- SNMP Multiplexing
    {437, 199, 6},
    {437, 199, 17},

    -- Softros LAN Messenger and File Transfer
    {3369, 19880, 6},

    -- Sonar
    {3370, 572, 6},
    {3370, 572, 17},

    -- Speeded Up Robust Feature
    {3371, 1010, 6},
    {3371, 1010, 17},

    -- SPMP
    {3372, 656, 6},
    {3372, 656, 17},

    -- spsc
    {3373, 478, 6},
    {3373, 478, 17},

    -- ss7ns
    {3374, 477, 6},
    {3374, 477, 17},

    -- STMF
    {3375, 501, 6},
    {3375, 501, 17},

    -- Stock IXChange
    {3376, 527, 6},
    {3376, 527, 17},

    -- streettalk
    {3377, 566, 6},
    {3377, 566, 17},

    -- STUN over TLS
    {3378, 5349, 6},
    {3378, 5349, 17},

    -- Submit Protocol
    {3379, 773, 6},

    -- SUBNTBCST_TFTP
    {3380, 247, 6},
    {3380, 247, 17},

    -- Sun IPC server
    {3381, 600, 6},
    {3381, 600, 17},

    -- SUNDR
    {3382, 665, 6},
    {3382, 665, 17},

    -- Survey Measurement
    {3383, 243, 6},
    {3383, 243, 17},

    -- Swift Remote Virtural File Protocol
    {3384, 97, 6},
    {3384, 97, 17},

    -- SynOptics SNMP Relay Port
    {3385, 391, 6},
    {3385, 391, 17},

    -- SynOptics Trap Convention Port
    {3386, 412, 17},

    -- System iNtrusion Analysis and Reporting Environment
    {3387, 509, 6},
    {3387, 509, 17},

    -- Systems and network monitoring tool
    {3388, 1984, 6},
    {3388, 1984, 17},

    -- Tag Distribution Protocol
    {3389, 711, 6},
    {3389, 711, 17},

    -- TeamSound
    {3390, 40001, 6},
    {3390, 40001, 6},
    {3390, 40002, 6},
    {3390, 40003, 6},
    {3390, 40004, 6},
    {3390, 40011, 6},
    {3390, 40001, 17},
    {3390, 40002, 17},
    {3390, 40003, 17},
    {3390, 40004, 17},
    {3390, 40011, 17},

    -- Technical Analysis Software
    {3391, 11010, 6},
    {3391, 11020, 6},

    -- Teedtap
    {3392, 559, 6},
    {3392, 559, 17},

    -- tell
    {3393, 754, 6},
    {3393, 754, 17},

    -- TenFold
    {3394, 658, 6},
    {3394, 658, 17},

    -- TESLA System Messaging
    {3395, 7631, 6},

    -- TIA/EIA/IS-99 modem client
    {3396, 379, 6},
    {3396, 379, 17},

    -- TIA/EIA/IS-99 modem server
    {3397, 380, 6},
    {3397, 380, 17},

    -- Timeserver
    {3398, 525, 6},
    {3398, 525, 17},

    -- tinc
    {3399, 655, 6},
    {3399, 655, 17},

    -- TNS CML
    {3400, 590, 6},
    {3400, 590, 17},

    -- Tobit David Replica
    {3401, 268, 6},
    {3401, 268, 17},

    -- TPIP
    {3402, 594, 6},
    {3402, 594, 17},

    -- Transport Independent Convergence for FNA
    {3404, 492, 6},
    {3404, 492, 17},
    {3404, 493, 6},
    {3404, 493, 17},

    -- trin00
    {3405, 27665, 6},
    {3405, 27444, 17},
    {3405, 31335, 17},

    -- Ulpnet
    {3406, 483, 6},
    {3406, 483, 17},

    -- Unix time
    {3407, 519, 6},
    {3407, 519, 17},

    -- User Location Protocol
    {3408, 522, 6},
    {3408, 522, 17},

    -- UTMPCD
    {3409, 431, 6},
    {3409, 431, 17},

    -- utmpsd
    {3410, 430, 6},
    {3410, 430, 17},

    -- UUIDGEN
    {3411, 697, 6},
    {3411, 697, 17},

    -- VACDSM-APP
    {3412, 671, 6},
    {3412, 671, 17},

    -- VACDSM-SWS
    {3413, 670, 6},
    {3413, 670, 17},

    -- Velazquez Application Transfer Protocol
    {3414, 690, 6},
    {3414, 690, 17},

    -- vemmi
    {3415, 575, 6},
    {3415, 575, 17},

    -- Vid
    {3416, 769, 6},
    {3416, 769, 17},

    -- Videotex
    {3417, 516, 6},
    {3417, 516, 17},

    -- Virtual Presence Protocol
    {3418, 677, 6},
    {3418, 677, 17},

    -- VMware Fault Domain Manager
    {3419, 8182, 6},
    {3419, 8182, 17},

    -- vnas
    {3420, 577, 6},
    {3420, 577, 17},

    -- VPPS-Via
    {3421, 676, 6},
    {3421, 676, 17},

    -- vsinet
    {3422, 996, 6},
    {3422, 996, 17},

    -- VVPS-Qua
    {3423, 672, 6},
    {3423, 672, 17},

    -- WAP connectionless session service
    {3424, 9200, 6},
    {3424, 9200, 17},

    -- WAP PUSH
    {3425, 2948, 6},
    {3425, 2948, 17},

    -- WAP Push OTA-HTTP port
    {3426, 4035, 6},
    {3426, 4035, 17},

    -- WAP Push OTA-HTTP secure
    {3427, 4036, 6},
    {3427, 4036, 17},

    -- WAP Push Secure
    {3428, 2949, 6},
    {3428, 2949, 17},

    -- WAP secure connectionless session service
    {3429, 9202, 6},
    {3429, 9202, 17},

    -- WAP Secure Session Service
    {3430, 9203, 6},
    {3430, 9203, 17},

    -- WAP session service
    {3431, 9201, 6},
    {3431, 9201, 17},

    -- WAP vCal
    {3432, 9205, 6},
    {3432, 9205, 17},

    -- WAP vCal Secure
    {3433, 9207, 6},
    {3433, 9207, 17},

    -- WAP vCard
    {3434, 9204, 6},
    {3434, 9204, 17},

    -- WAP vCard Secure
    {3435, 9206, 6},
    {3435, 9206, 17},

    -- War-rock Online Gaming
    {3436, 5330, 6},
    {3436, 5340, 6},

    -- whoami
    {3437, 565, 6},
    {3437, 565, 17},

    -- Wireless LAN Context Control Protocol
    {3438, 2887, 6},
    {3438, 2887, 17},

    -- World Fusion
    {3439, 2595, 6},
    {3439, 2595, 17},

    -- wpgs
    {3440, 780, 6},
    {3440, 780, 17},

    -- X Display Manager Control Protocol
    {513, 177, 6},
    {513, 177, 17},

    -- xact-backup
    {3442, 911, 6},
    {3442, 911, 17},

    -- xvttp
    {3443, 508, 6},
    {3443, 508, 17},

    -- Airsoft Powerburst
    {3676, 485, 6},
    {3676, 485, 17},

    -- GSS HTTP
    {3677, 488, 6},
    {3677, 488, 17},

    -- Tempo
    {1795, 526, 6},
    {1795, 526, 17},

    -- NetWall
    {3678, 533, 6},
    {3678, 533, 17},

    -- GIOP
    {176, 535, 6},
    {176, 535, 17},

    -- Eudora Set
    {3679, 592, 6},
    {3679, 592, 17},

    -- Service Status Update
    {3680, 633, 6},
    {3680, 633, 17},

    -- ESRO-EMSDP V1.3
    {3681, 642, 6},
    {3681, 642, 17},

    -- ISO MMS
    {2313, 651, 6},
    {2313, 651, 17},

    -- OLSR
    {3682, 698, 6},
    {3682, 698, 17},

    -- PKIX-3 CA/RA
    {3683, 829, 6},
    {3683, 829, 17},

    -- PIP
    {367, 321, 6},
    {367, 321, 17},
    {367, 1321, 6},  
    {367, 1321, 17},

    -- Oracle Remote Data Base
    {3684, 1571, 6},
    {3684, 1571, 17},

    -- Shockwave
    {824, 1626, 6},
    {824, 1626, 17},

    -- MSNP
    {307, 1863, 6},
    {307, 1863, 17},

    -- ISCSI
    {3685, 3260, 6},

    -- SVN
    {2887, 3690, 6},
    {2887, 3690, 17},

    -- Tapeware
    {3686, 3817, 6},
    {3686, 3817, 17},

    -- iax
    {3687, 4569, 6},
    {3687, 4569, 17},

    -- CVSup
    {3688, 5999, 6},
    {3688, 5999, 17},

    -- MSOC File Transfer
    {3689, 6891, 6},

    -- MaxDB
    {2327, 7210, 6},
    
    -- McAfee AutoUpdate
    {3690, 8801, 6},
    
    -- Applejuice
    {29, 9022, 6},
    {29, 9022, 17},

    -- AMANDA
    {3691, 10080, 6},
    {3691, 10080, 17},

    -- Hamachi
    {1156, 12975, 6},

    -- Oracle Business Intelligence
    {3692, 9703, 6},
    {3692, 9704, 6},

    -- webster
    {3693, 765, 6},
    {3693, 765, 17},

    -- Xfire
    {2794, 25999, 6},

    -- tn-tl-fd1
    {3694, 476, 6},
    {3694, 476, 17},

    -- WCCP
    {498, 2048, 6},
    {498, 2048, 17},

    -- Websense
    {2790, 15868, 6},
    {2790, 15871, 17},

}

function DetectorInit(detectorInstance)

    gDetector = detectorInstance;

    if gDetector.portOnlyService then
        for i,v in ipairs(gPortServiceList) do
            gDetector:portOnlyService(v[1], v[2], v[3]);
        end
    end
    return gDetector;
end

function DetectorClean()
end
