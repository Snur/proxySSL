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
detection_name: Content Group "Port Services 2Pac_old"
version: 13
description: Group of Port Service detectors.
bundle_description: $VAR1 = {
          'UUCP' => 'Unix-to-Unix Copy.',
          'Character Generator' => 'Software for inserting text into media streams.',
          'KIS' => 'KIS Protocol.',
          'ACR-NEMA' => 'A standard for handling, storing, printing, and transmitting medical imaging. Registered with IANA on port 104 tcp/udp.',
          'Webfilter' => 'Registered with IANA on port 1046 tcp/udp.',
          'Jargon' => 'Jargon protocol.',
          'SNA Gateway' => 'SNA Gateway Access Server enables users to exchange information and share resources between configured OpenVMS systems in DECnet and/or TCP/IP environments in a bidirectional manner.',
          'Openport' => 'Openport.',
          'NCLD' => 'Registered with IANA on port 405 tcp/udp.',
          'DPSI' => 'Desktop Paging Software, Inc. Registered with IANA on port 315 tcp/udp.',
          'ESRO' => 'The Efficient Short Remote Operations service is a Remote Procedure Call service.',
          'Nessus' => 'Active network scanner.',
          'Hyper-G' => 'A publishing system designed to offer features more advanced than HTTP.',
          'UIS' => 'Registered with IANA on port 390 tcp/udp.',
          'SMAKYNET' => 'SMAKYNET Protocol.',
          'Citrix SLG' => 'Storage Link Gateway. Discovery and access to various storage services.',
          'Tobit David' => 'David Service Layer, also known as FaxWare, is a program for Windows NT and NetWare that allows FAXes to be sent over the network.',
          'MSP' => 'An application layer protocol used to send a short message between nodes on a network.',
          'Cisco SLA' => 'Monitors Service Level Agreements.',
          'Cisco FNATIVE' => 'Registered with IANA on port 130 tcp/udp.',
          'NIP' => 'Amiga Envoy Network Inquiry Protocol. Registered with IANA on port 376 tcp/udp.',
          'MATIP' => 'Airline reservation, ticketing, and messaging system.',
          'DTAG' => 'Protocols developed by Deutsche Telekom AG. Registered with IANA on port 352 tcp/udp.',
          'Stat Service' => 'Statistics Service for collecting STAT data from hosts.',
          'LLMNR' => 'Link-local Multicast Name Resolution. Used by Windows for local name resolution.',
          'Bnet' => 'Registered with IANA on port 415 tcp/udp.',
          'BlazeFS' => 'Blaze File Server is a remote file sharing system designed specifically for Macs.',
          'Meta5' => 'Business analytic software. Allows users to create reports that can access multiple corporate data sources. Registered with IANA on port 393 tcp/udp.',
          'OCBinder' => 'Binding service for Microsoft Office Communications Server.',
          'PWDGEN' => 'Password Generator Protocol, rfc 972.',
          'NNSP' => 'An Internet application protocol used for transporting Usenet news articles (netnews) between news servers and for reading and posting articles by end user client applications.',
          'Xyplex' => 'Xyplex.',
          'Remote Job Service' => 'Registered with IANA on port 71 tcp/udp.',
          'NDS Auth' => 'A software module from Symantec Corporation.',
          'Linuxconf' => 'Linux system configurator.',
          'Zebra' => 'A high-performance, general-purpose structured text indexing and retrieval engine. It reads structured records in a variety of input formats (eg. email, XML, MARC) and allows access to them through exact boolean search expressions and relevance-ranked free-text queries.',
          'NI Mail' => 'A mass email client with socks proxy support.',
          'Clearcase' => 'Software revision control system.',
          'AUDIT' => 'Unisys Audit SITP.',
          'Ariel' => 'Infotrieve Ariel. Cloud-based system for converting and storing image scans as PDF.',
          'X font server' => 'Service that allows the use of server-rendered fonts.',
          'Groupwise' => 'A messaging and collaborative software platform from Novell that supports email, calendaring, personal information management, instant messaging, and document management.',
          'CL1' => 'Network Innovations CL/1, registered with IANA on port 172 tcp/udp.',
          'Citrix RTMP' => 'Registered with IANA on port 2897 tcp/udp.',
          'McIDAS' => 'Man-computer Interactive Data Access System, a data transmission protocol.',
          'Magenta Logic' => 'Registered with IANA on port 313 tcp/udp.',
          'Tripwire' => 'A free software security and data integrity tool useful for monitoring and alerting on specific file change(s) on a range of systems.',
          'talk' => 'Unix messaging protocol.',
          'ISI Graphics' => 'ISI Graphics Language.',
          'DLS' => 'Directory Location Service, registered with IANA on port 197 tcp/udp.',
          'XNS Clearinghouse' => 'Xerox Networking Services Clearinghouse Protocol.',
          'CAP' => 'Registered with IANA on port 1026 tcp/udp.',
          'SGCP' => 'A communications protocol used within a Voice over Internet Protocol system. It has been superseded by the Media Gateway Control Protocol architecture.',
          'MAILQ' => 'Registered with IANA on port 174 tcp/udp.',
          'DCP' => 'An application level protocol optimized for the integration, monitoring and control of devices on a network. Registered with IANA on port 93 tcp/udp.',
          'PDAP' => 'Prospero data access protocol.',
          'ActiveSync' => 'Microsoft software that allows synchronization of data between handheld devices and desktop computers.',
          'RLP' => 'Resource Location Protocol is used to help find network services.',
          'MobileIP' => 'An IETF standard for mobile IP networks.',
          'PKIX Timestamp' => 'The PKIX TS specifies the format of packets, along with some possible transport protocols and some verifications to be done by the server and the client.',
          'CompressNET' => 'CompressNET is a commercial WAN compression/acceleration protocol.',
          'IBM App' => 'IBM systems software.',
          'DSP3270' => 'Display Systems Protocol. Registered with IANA on port 246 tcp/udp.',
          'XNS Time' => 'XNS Time Protocol.',
          'ASA' => 'Registered with IANA on port 386 tcp/udp.',
          'CDC' => 'Certificate Distribution Center, registered with IANA on port 223 tcp/udp.',
          'Avocent' => 'Registered with IANA on port 1078 tcp/udp.',
          'mit-ml-dev' => 'MIT ML Device, registered with IANA on port 83 tcp/udp.',
          'IPP' => 'Internet Printing Protocol.',
          'NI FTP' => 'Network Independent File Transfer Program.',
          'POP2' => 'Post Office Protocol, used by local e-mail clients to retrieve e-mail from a remote server.',
          'SMPTE' => 'Registered with IANA on port 420 tcp/udp.',
          'ANSI Z39.50' => 'A client-server protocol for searching and retrieving information from remote computer databases.',
          'ERPC' => 'Encore Expedited Remote Procedure Call.',
          'Sybase SQL' => 'Database management suite.',
          'Lotus Notes' => 'IBM\'s enterprise collaboration suite.',
          'Cisco TNATIVE' => 'Registered with IANA on port 131 tcp/udp.',
          'DEC Auth' => 'Digital Equipment Corporation authentication protocol. Registered with IANA on port 316 tcp/udp.',
          'ntalk' => 'A later implementation of talk, a Unix messaging utility.',
          'Unify' => 'Unify protocol, registered with IANA on port 181 tcp/udp.',
          'RSVD' => 'Resource and Service Validation Daemon.',
          'DEC LaDebug' => 'Remote source code debugging protocol.',
          'DSP' => 'Display Support Protocol. Registered with IANA on port 33 tcp/udp.',
          'Semantix' => 'Language translation and definition service.',
          'GIST' => 'General Internet Signalling Transport.',
          'NSS' => 'NSS Routing.',
          'Mini SQL' => 'A lightweight database management system.',
          'MSMQ' => 'MSMQ is essentially a messaging protocol that allows applications running on separate servers/processes to communicate in a failsafe manner.',
          'HP Perf' => 'Performance Data Collector for HP OpenVMS.',
          'Aurora' => 'IBM AURORA Performance Visualizer. IANA TCP/UDP port 9084.',
          'HDAP' => 'Microsoft HDA Protocol.',
          'Citrix Licensing' => 'Citrix Licensing traffic. Registered with IANA on port 7279 tcp/udp.',
          'Legent' => 'Protocols for legent-1, registered with IANA on port 373 tcp/udp, and legent-2, registered with IANA on port 374 tcp/udp.',
          'Blackjack' => 'Registered with IANA on port 1025 tcp/udp.',
          'NSSTP' => 'Nebula Secure Segment Transfer Protocol. Registered with IANA on port 1036 tcp/udp.',
          'KFTP' => 'File Transfer Protocol with Kerberos authentication and encryption.',
          'Gss X License Verification' => 'Authentication for Cisco\'s GSS loadbalancing product.',
          'Cisco DRP' => 'Director Response Protocol enables Cisco\'s DistributedDirector product to query routers on a network for BGP route information.',
          'Genie' => 'A network management/diagnostic protocol.',
          'DATEX-ASN' => 'A data communications protocol generally used to allow communication between highway traffic control devices. Registered with IANA on port 355 tcp/udp.',
          'OPC-UA' => 'Cross platform framework standards for accessing the real and historical data.',
          'Metagram' => 'Metagram Relay.',
          'Kryptolan' => 'Registered with IANA on port 398 tcp/udp.',
          'BHFHS' => 'Registered with IANA on port 248 tcp/udp.',
          'NeXTStep' => 'NeXTStep Window Server.',
          'NovaBACKUP' => 'NovaStor develops and markets data protection and availability software. NovaBACKUP offers support for multi-OS environments and is capable of handling thousands of servers and petabytes of information.',
          'Vchat' => 'An Internet conferencing protocol.',
          'NXEdit' => 'Registered with IANA on port 126 tcp/udp.',
          'NCED' => 'Registered with IANA on port 404 tcp/udp.',
          'mck-ivpip' => 'Citel\'s VoIP extender ipvip protocol.',
          'SMSP' => 'Storage Management Services Protocol, registered with IANA on port 413 tcp/udp.',
          'Remote Telnet' => 'Remote Telnet.',
          'Qbik' => 'Qbik products such as WinGate, WinGate VPN, and NetPatrol.',
          'BFTP' => 'Background File Transfer Program.',
          'Zannet' => 'A combination Windows 95 network client and Unix server that providing Windows 95 network drive access to your server files.',
          'MortgageWare' => 'A product developed by Interlinq Software Corp that automates all components of the loan originating process.',
          'OpenVPN' => 'A free and open source software application that implements virtual private network (VPN) techniques for creating secure point-to-point or site-to-site connections.',
          'Netinfo' => 'Registered with IANA on port 1033 tcp/udp.',
          'MSG' => 'Registered with IANA on port 29 tcp/udp; Registered with IANA on port 31 tcp/udp.',
          'RIPng' => 'A later version of Routing Information Protocol that supports IPv6.',
          'AppleShare' => 'AppleShare IP WebAdmin.',
          'RPC2PMAP' => 'An ONC RPC service that runs on network nodes that provide other ONC RPC services.',
          'EMFIS Data' => 'EMFIS Service, port 140 tcp/udp.',
          'SGMP' => 'Simple Gateway Monitoring Protocol is a protocol that preceeded SNMP.',
          'AED512' => 'AED 512 Emulation service, registered with IANA on port 149 tcp/udp.',
          'Cisco SYSMAINT' => 'Registered with IANA on port 132 tcp/udp.',
          'GENRAD' => 'Registered with IANA on port 176 tcp/udp.',
          'ICP' => 'Registered with IANA on port 1112 tcp/udp.',
          'OCS' => 'Microsoft Office Communications Server, also known as Lync Server, is an enterprise IM, file sharing, peer to peer, and IP telephony server.',
          'KNETCMP' => 'KNET/VM Command/Message Protocol.',
          'PFTP' => 'Port-FTP transfers files, directories and data to other hosts running pftp.',
          'NAMP' => 'Neighbor Aware Multicast Routing Protocol.',
          'XNS' => 'Xerox Network Services.',
          'Sender Rewriting Scheme' => 'Registered with IANA on port 362 tcp/udp.',
          'RJE' => 'The process of sending jobs to Mainframe computers from remote workstations and by extension the process of receiving output from mainframe jobs at a remote workstation.',
          'GACP' => 'Gateway Access Control Protocol, registered with IANA on port 190 tcp/udp.',
          'Ktelnet' => 'Telnet with Kerberos authentication and encryption.',
          'Xbone' => 'X-Bone Control is a system for the automated deployment, management, coodination, and monitoring of IP overlay networks.',
          'COMSCM' => 'Registered with IANA on port 437 tcp/udp.',
          'SRMP' => 'Spider Remote Monitoring Protocol.',
          'HP VMM' => 'HP Virtual Machine Manager.',
          'VSLMP' => 'Registered with IANA on port 312 tcp/udp.',
          'PROSPERO' => 'Prospero Directory Service is a name server based on the virtual system model.',
          'Citrix IMA' => 'Independent Management Architeture protocol. Used for licensing and server load updates.',
          'Xfer' => 'The Xfer Utility is used for DNS zone transfers.',
          '914CG' => 'Texas Instruments 914C/G terminal, registered with IANA on port 211 tcp/udp.',
          'vettcp' => 'Registered with IANA on port 78 tcp/udp.',
          'ODMR' => 'An SMTP extension standardized in RFC 2645 that allows e-mail to be relayed after the sender has been authenticated. It uses the extended SMTP command ATRN It is similar to the ETRN command but works with dynamically assigned IP addresses.',
          'BHMDS' => 'Registered with IANA on port 310 tcp/udp.',
          'DNA-CML' => 'Registered with IANA on port 436 tcp/udp.',
          'BGMP' => 'Border Gateway Multicast Protocol.',
          'Active Networks' => 'A networking technology used to enable unique processing of each network packet.',
          'ARCISDMS' => 'Registered with IANA on port 262 tcp/udp.',
          'BHEVENT' => 'Registered with IANA on port 357 tcp/udp.',
          'TCPMUX' => 'TCP Port Service Multiplexer is a multiplexing service that may be accessed with a network protocol to contact any one of a number of available TCP services of a host on a single, well-known port number.',
          'WINS' => 'Microsoft\'s implementation of NetBIOS Name Service (NBNS), a name server and service for NetBIOS computer names.',
          'Fatmen' => 'Registered with IANA on port 347 tcp/udp.',
          'RIS' => 'Relational Interface System Intergraph Corporation\'s middleware for connecting client software and DBMS.',
          'InfoSeek' => 'A 90s-era internet search engine.',
          'NetScout' => 'Control traffic for NetScout Systems\' network traffic monitoring products. Registered with IANA on port 395 tcp/udp.',
          'IMGames' => 'Registered with IANA on port 1077 tcp/udp.',
          'PROFILE' => 'PROFILE Naming System.',
          'SecurSight' => 'A public-key architecture that combines authentication, authorization, and secure communications.',
          'DCAP' => 'An application layer protocol used between workstations and routers to transport SNA/NetBIOS traffic over TCP sessions.',
          'UMA' => 'Universal Management Architecture.',
          'HTTPMGT' => 'HTTP Management.',
          'RMT' => 'Remote MT protocol. Registered with IANA on port 411 tcp.',
          'CMIP' => 'Common Management Information Protocol.',
          'Alias' => 'Registered with IANA on port 1187 tcp/udp.',
          'VM PWSCS' => 'Registered with IANA on port 214 tcp/udp.',
          'ANSA REX Trader' => 'ANSA REX Trader, registered with IANA on port 124 tcp/udp.',
          'XNS Mail' => 'Xerox Networking Services Mail.',
          'DIXIE' => 'A lightweight directory assistence protocol, registered with IANA on port 96 tcp/udp.',
          'UPS' => 'Uninterruptible Power Supply, registered with IANA on port 401 tcp/udp.',
          'Sco I2 Dialog Daemon' => 'Registered with IANA on port 360 tcp/udp.',
          'Shrinkwrap' => 'A public key infrastructure protocol that uses internet security key management protocols.',
          'RTSPS' => 'A secure network control protocol designed for use in entertainment and communications systems to control streaming media servers. The protocol is used for establishing and controlling media sessions between end points.',
          'Netware' => 'A network operating system developed by Novell, Inc.',
          'DASP' => 'This protocol is designed to provide an unordered, reliable, secure session for full-duplex datagram exchange that can be implemented for low power wireless networks and low cost devices.',
          'MIT Spooler' => 'MIT Dover Spooler. Registered with IANA on port 91 tcp/udp.',
          'Masqudialer' => 'The masqudialer system allows authorized LAN users to manipulate the network interface, usually a modem, that gives Internet access on a Linux box without having to use Telnet.',
          'SoftPC' => 'Software emulation of x86 hardware.',
          'DECVMS' => 'Registered with IANA on port 441 tcp/udp.',
          'ACA Services' => 'DEC\'s Application Control Architecture services, registered with IANA on port 62 tcp/udp.',
          'BH611' => 'Registered with IANA on port 354 tcp/udp.',
          'ANSA Notify' => 'ANSA REX Notify, registered with IANA on port 116 tcp/udp.',
          'Opalis Robot' => 'System management and automation solution. Provides real-time monitoring, notification, corrective action and event driven job scheduling.',
          'Diameter' => 'Diameter AAA. IANA TCP port 3868.',
          'OFTPS' => 'Odette FTP over SSL/TLS is used primarily for Electronic Data Interchange between two communications business partners.',
          'Cisco GDP' => 'Gateway Discovery Protocol allows hosts to dynamically detect the arrival of new routers as well as determine when a router goes down.',
          'Su-Mit Telnet' => 'Su-Mit Telnet Gateway.',
          'Silverplatter' => 'Commercial reference database.',
          'PDRE' => 'Peer Direct Replication Engine, allows for distribution of databases and applications.',
          'EntrustTime' => 'Time protocol for Entrust, Inc\'s security software. Registered with IANA on port 309 tcp/udp.',
          'Cableport AX' => 'Registered with IANA on port 282 tcp/udp.',
          'Locus Map' => 'Registered with IANA on port 125 tcp/udp.',
          'MS CRS' => 'Microsoft Content Replication System. Registered with IANA on port 507 tcp/udp.',
          'LINK' => 'Registered with IANA on port 245 tcp/udp.',
          'MS OLAP' => 'An online analytical processing capability that is a component of Microsoft SQL Server.',
          'Systat' => 'System diagnostics information.',
          'OFTP' => 'Odette File Transfer Protocol is used for EDI electronic data interchange between two communications business partners.',
          'ESP' => 'Encapsulating Security Payload, a part of the IPSec security protocol suite.',
          'AFP' => 'Apple Filing Protocol over tcp/udp. Registered with IANA on port 548 tcp/udp.',
          'SRC' => 'IBM System Resource Controller facilitates the management and control of complex subsystems.  The SRC is a subsystem controller.',
          'PCMAIL' => 'PCMail Server.',
          'KWDB' => 'Remote Kernel debugger communication.',
          'SUPDUP' => 'The SUPDUP protocol provides for login to a remote system over a network with terminal-independent output.',
          'DSFGW' => 'Registered with IANA on port 438 tcp/udp.',
          'UAAC' => 'UAAC Protocol.',
          'OCServer' => 'Server side of Microsoft Office Communications Server.',
          '3COM-TSMUX' => '3COM-TSMUX Queuing service, registered with IANA on port 106 tcp/udp.',
          'MC-FTP' => 'Multicast File Transfer Protocol.',
          'FileMaker' => 'A cross-platform relational database application.',
          'Time' => 'A network protocol in the Internet Protocol Suite defined in 1983 in RFC 868. Its purpose is to provide a site-independent, machine readable date and time.',
          'EMBLNDT' => 'Registered with IANA on port 394 tcp/udp.',
          'Texar' => 'Policy-based authorization system.',
          'NETSC' => 'Registered with IANA on ports 154 tcp/udp.',
          'DNSIX' => 'DNSIX stands for DODIIS (Department of Defence Intelligence Information System) Network Security Information Exchange. Network security protocols defined by the U.S. Defense Intelligence Agency.',
          'SNPP' => 'A protocol for delivering pages to pagers over the Internet.',
          'Coda Auth' => 'Registered with IANA on port 370 tcp/udp.',
          'ACI' => 'Application Communication Interface, registered with IANA on port 187 tcp/udp.',
          'NFA' => 'A network file system that acts as a client for a remote file access protocol, providing access to files on a server.',
          'Onmux' => 'Registered with IANA on port 417 tcp/udp.',
          'VMNET' => 'Registered with IANA on port 175 tcp/udp.',
          'GPFS' => 'IBM General Parallel File System is a high-performance shared-disk clustered file system. Registered with IANA on port 1191 tcp/udp.',
          'KFTPDATA' => 'File Transfer Protocol with Kerberos authentication and encryption.',
          'CORBA' => 'Common Object Request Broker Architecture is a protocol that allows software written in different languages and on different platforms to interoperate.',
          'SCCP' => 'SCCP (Skinny Call Control Protocol) traffic is generated by setting up and controlling voice over IP calls.',
          'OPC' => 'IBM\'s Operations Planning and Control, an older version of Tivoli.',
          'RIP' => 'Routing Information Protocol is a dynamic routing protocol.',
          'L2TP' => 'A tunneling protocol used in VPNs and DSL customer loops.',
          'PCoIP' => 'A remote desktop system.',
          'dBase' => 'An old database management system for microcomputers that run Unix and VMS.',
          'HiveStor' => 'HiveStor Distributed File System.',
          'Oracle SQLNET' => 'Networking software that allows remote data-access between programs and the Oracle Database, or among multiple Oracle Databases.',
          'RRP' => 'Registry Registrar Protocol.',
          'XNS Authentication' => 'Xerox Networking Services Authentication.',
          'IASD' => 'Registered with IANA on port 432 tcp/udp.',
          'ResCap' => 'Resource capabilities discovery protocol.',
          'UARPS' => 'Unisys ARPs.',
          'Unidata LDM' => 'Event-driven data distribution system, includes network client and server programs and their shared protocols.',
          'ICAD' => 'A knowledge-based engineering system written in Lisp.',
          'Meeting Maker' => 'A cross-platform personal calendar and group scheduling software application.',
          'FXP' => 'File eXchange Protocol uses FTP to transfer data from one remote server to another without routing this data through the client\'s connection.',
          'KVM' => 'KVM (Keyboard/Video/Mouse) over IP Management Service.',
          'CLOANTO' => 'The cloanto.net infrastructure provides redundant hosting, email and telecommunications services.',
          'IngresNET' => 'Protocol that allows access to Ingres databases.'
        };

--]]

require "DetectorCommon"

local DC = DetectorCommon

DetectorPackageInfo = {
    name = "content_group_port_services_2pac_old",
    proto =  DC.ipproto.tcp,
    client = {
        init =  'DetectorInit',
        clean =  'DetectorClean',
        minimum_matches =  1
    }
}

-- "AppId", "port", "protocol" (6 = TCP, 17 = UDP)
gPortServiceList = {

    -- WINS
    {505, 1512, 6},
    {505, 1512, 17},

    -- 3COM-TSMUX
    {2, 106, 6},
    {2, 106, 17},

    -- 914CG
    {4, 211, 6},
    {4, 211, 17},

    -- ACA Services
    {5, 62, 6},
    {5, 62, 17},

    -- ACI
    {6, 187, 6},
    {6, 187, 17},

    -- ACR-NEMA
    {7, 104, 6},
    {7, 104, 17},

    -- AED512
    {19, 149, 6},
    {19, 149, 17},

    -- AFP
    {20, 548, 6},
    {20, 548, 17},

    -- ANET
    {3607, 212, 6},
    {3607, 212, 17},

    -- ANSA Notify
    {26, 116, 6},
    {26, 116, 17},

    -- ANSA REX Trader
    {27, 124, 6},
    {27, 124, 17},

    -- ANSI Z39.50
    {525, 210, 6},
    {525, 210, 17},

    -- ARCISDMS
    {33, 262, 6},
    {33, 262, 17},

    -- ASA
    {37, 386, 6},
    {37, 386, 17},

    -- ActiveSync
    {9, 1034, 6},
    {9, 1034, 17},

    -- Alias
    {23, 1187, 6},
    {23, 1187, 17},

    -- Ariel
    {34, 419, 6},
    {34, 419, 17},

    -- Avocent
    {46, 1078, 6},
    {46, 1078, 17},

    -- BFTP
    {52, 152, 6},
    {52, 152, 17},

    -- BGMP
    {53, 264, 6},
    {53, 264, 17},

    -- BH611
    {54, 354, 6},
    {54, 354, 17},

    -- BHEVENT
    {55, 357, 6},
    {55, 357, 17},

    -- BHFHS
    {56, 248, 6},
    {56, 248, 17},

    -- BHMDS
    {57, 310, 6},
    {57, 310, 17},

    -- Blackjack
    {63, 1025, 6},
    {63, 1025, 17},

    -- BlazeFS
    {64, 1150, 6},
    {64, 1150, 17},

    -- Bnet
    {66, 415, 17},

    -- CAP
    {70, 1026, 6},
    {70, 1026, 17},

    -- CL1
    {91, 172, 6},
    {91, 172, 17},

    -- CLOANTO
    {93, 356, 6},
    {93, 356, 17},
    {93, 3397, 6},
    {93, 3397, 17},

    -- CMIP
    {94, 164, 6},
    {94, 164, 17},

    -- COMSCM
    {98, 437, 6},
    {98, 437, 17},

    -- Cableport AX
    {67, 282, 6},
    {67, 282, 17},

    -- Cisco DRP
    {76, 1974, 6},
    {76, 1974, 17},

    -- Cisco FNATIVE
    {77, 130, 6},
    {77, 130, 17},

    -- Cisco GDP
    {78, 1997, 6},
    {78, 1997, 17},

    -- Cisco SLA
    {79, 1167, 6},
    {79, 1167, 17},

    -- Cisco SYSMAINT
    {80, 132, 6},
    {80, 132, 17},

    -- Cisco TNATIVE
    {81, 131, 6},
    {81, 131, 17},

    -- Citrix IMA
    {84, 2598, 6},
    {84, 2598, 17},

    -- Citrix Licensing
    {86, 7279, 6},
    {86, 7279, 17},

    -- Citrix RTMP
    {88, 2897, 6},
    {88, 2897, 17},

    -- Citrix SLG
    {89, 24754, 6},

    -- Clearcase
    {92, 371, 6},
    {92, 371, 17},

    -- Coda Auth
    {95, 370, 6},
    {95, 370, 17},

    -- CompressNET
    {97, 3, 6},
    {97, 3, 17},

    -- DASP
    {106, 439, 6},
    {106, 439, 17},

    -- DATEX-ASN
    {107, 355, 6},
    {107, 355, 17},

    -- DCAP
    {109, 22125, 6},

    -- DCP
    {111, 93, 6},
    {111, 93, 17},

    -- DEC Auth
    {112, 316, 6},
    {112, 316, 17},

    -- DEC LaDebug
    {113, 410, 6},
    {113, 410, 17},

    -- DECVMS
    {114, 441, 6},
    {114, 441, 17},

    -- DIXIE
    {120, 96, 6},
    {120, 96, 17},

    -- DLS
    {121, 197, 6},
    {121, 197, 17},

    -- DNA-CML
    {122, 436, 6},
    {122, 436, 17},

    -- DNSIX
    {123, 90, 6},
    {123, 90, 17},

    -- DPSI
    {124, 315, 6},
    {124, 315, 17},

    -- DSFGW
    {126, 438, 6},
    {126, 438, 17},

    -- DSP
    {128, 33, 6},
    {128, 33, 17},

    -- DSP3270
    {127, 246, 6},
    {127, 246, 17},

    -- DTAG
    {130, 352, 6},
    {130, 352, 17},

    -- EMBLNDT
    {138, 394, 6},
    {138, 394, 17},

    -- EMFIS Data
    {139, 140, 6},
    {139, 140, 17},

    -- ERPC
    {142, 121, 6},
    {142, 121, 17},

    -- ESRO
    {145, 259, 6},
    {145, 259, 17},

    -- EntrustTime
    {140, 309, 6},
    {140, 309, 17},

    -- FXP
    {169, 286, 6},
    {169, 286, 17},

    -- Fatmen
    {154, 347, 6},
    {154, 347, 17},

    -- FileMaker
    {155, 5013, 6},
    {155, 5013, 17},

    -- GACP
    {170, 190, 6},
    {170, 190, 17},

    -- GENRAD
    {174, 176, 6},
    {174, 176, 17},

    -- GIST
    {177, 270, 17},

    -- GPFS
    {188, 1191, 6},
    {188, 1191, 17},

    -- Genie
    {173, 402, 6},
    {173, 402, 17},

    -- Groupwise
    {190, 1677, 6},
    {190, 1677, 17},

    -- HDAP
    {198, 263, 6},
    {198, 263, 17},

    -- HP Perf
    {206, 381, 6},
    {206, 381, 17},

    -- HP VMM
    {207, 1124, 6},
    {207, 1124, 17},

    -- HiveStor
    {200, 4884, 6},
    {200, 4884, 17},

    -- Hyper-G
    {211, 418, 6},
    {211, 418, 17},

    -- IASD
    {212, 432, 6},
    {212, 432, 17},

    -- IBM App
    {678, 385, 6},
    {678, 385, 17},

    -- ICAD
    {215, 425, 6},
    {215, 425, 17},

    -- ICP
    {221, 1112, 6},
    {221, 1112, 17},

    -- IMGames
    {226, 1077, 6},
    {226, 1077, 17},

    -- IPP
    {1095, 631, 6},
    {1095, 631, 17},

    -- ISI Graphics
    {244, 55, 6},
    {244, 55, 17},

    -- InfoSeek
    {230, 414, 6},
    {230, 414, 17},

    -- IngresNET
    {232, 134, 6},
    {232, 134, 17},

    -- Jargon
    {247, 148, 6},
    {247, 148, 17},

    -- KFTP
    {251, 6621, 6},
    {251, 6621, 17},

    -- KFTPDATA
    {250, 6620, 6},
    {250, 6620, 17},

    -- KIS
    {252, 186, 6},
    {252, 186, 17},

    -- KNETCMP
    {253, 157, 6},
    {253, 157, 17},

    -- KVM
    {257, 1132, 6},
    {257, 1132, 17},

    -- KWDB
    {258, 1127, 6},
    {258, 1127, 17},

    -- Kryptolan
    {254, 398, 6},
    {254, 398, 17},

    -- Ktelnet
    {255, 6623, 17},

    -- LINK
    {263, 245, 6},
    {263, 245, 17},

    -- LLMNR
    {267, 5355, 6},
    {267, 5355, 17},

    -- Legent
    {262, 373, 6},
    {262, 373, 17},

    -- Locus Map
    {269, 125, 6},
    {269, 125, 17},

    -- Lotus Notes
    {720, 1352, 6},
    {720, 1352, 17},

    -- MAILQ
    {275, 174, 6},
    {275, 174, 17},

    -- MATIP
    {279, 350, 6},
    {279, 350, 17},

    -- MC-FTP
    {281, 6622, 6},
    {281, 6622, 17},

    -- MIT Spooler
    {294, 91, 6},
    {294, 91, 17},

    -- MS CRS
    {303, 507, 6},
    {303, 507, 17},

    -- MS OLAP
    {309, 2282, 6},
    {309, 2282, 17},

    -- MSMQ
    {306, 1801, 6},
    {306, 1801, 17},

    -- MSP
    {311, 2438, 6},
    {311, 2438, 17},

    -- Magenta Logic
    {273, 313, 6},
    {273, 313, 17},

    -- Masqudialer
    {278, 224, 6},
    {278, 224, 17},

    -- McIDAS
    {282, 112, 6},
    {282, 112, 17},

    -- Meeting Maker
    {287, 2272, 6},
    {287, 2272, 17},

    -- Meta5
    {288, 393, 6},
    {288, 393, 17},

    -- Metagram
    {289, 99, 6},
    {289, 99, 17},

    -- Mini SQL
    {292, 1114, 6},
    {292, 1114, 17},

    -- MobileIP
    {296, 434, 6},
    {296, 434, 17},

    -- MortgageWare
    {297, 367, 6},
    {297, 367, 17},

    -- NAMP
    {318, 167, 6},
    {318, 167, 17},

    -- NCED
    {320, 404, 6},
    {320, 404, 17},

    -- NCLD
    {321, 405, 6},
    {321, 405, 17},

    -- NDS Auth
    {322, 353, 6},
    {322, 353, 17},

    -- NETSC
    {327, 154, 6},
    {327, 154, 17},

    -- NFA
    {330, 1155, 6},
    {330, 1155, 17},

    -- NI FTP
    {332, 47, 6},
    {332, 47, 17},

    -- NI Mail
    {333, 61, 6},
    {333, 61, 17},

    -- NIP
    {334, 376, 6},
    {334, 376, 17},

    -- NNSP
    {335, 433, 6},
    {335, 433, 17},

    -- NSS
    {340, 4159, 6},
    {340, 4159, 17},

    -- NSSTP
    {341, 1036, 6},
    {341, 1036, 17},

    -- NXEdit
    {342, 126, 6},
    {342, 126, 17},

    -- NeXTStep
    {343, 178, 6},
    {343, 178, 17},

    -- NetScout
    {328, 395, 6},
    {328, 395, 17},

    -- Netinfo
    {324, 1033, 6},
    {324, 1033, 17},

    -- Netware
    {329, 1366, 6},
    {329, 1366, 17},

    -- NovaBACKUP
    {336, 308, 6},
    {336, 308, 17},

    -- OCBinder
    {344, 183, 6},
    {344, 183, 17},

    -- OCServer
    {345, 184, 6},
    {345, 184, 17},

    -- ODMR
    {347, 366, 6},
    {347, 366, 17},

    -- OFTP
    {348, 3305, 6},
    {348, 3305, 17},

    -- OFTPS
    {349, 6619, 6},
    {349, 6619, 17},

    -- OPC-UA
    {2042, 4840, 6},
    {2042, 4840, 17},

    -- Onmux
    {350, 417, 6},
    {350, 417, 17},

    -- Opalis Robot
    {351, 314, 6},
    {351, 314, 17},

    -- OpenVPN
    {353, 1194, 6},
    {353, 1194, 17},

    -- Openport
    {352, 260, 6},
    {352, 260, 17},

    -- Oracle SQLNET
    {355, 66, 6},
    {355, 66, 17},

    -- PCMAIL
    {362, 158, 6},
    {362, 158, 17},

    -- PCoIP
    {1189, 4172, 6},
    {1189, 4172, 17},

    -- PDAP
    {363, 344, 6},
    {363, 344, 17},

    -- PDRE
    {119, 242, 6},
    {119, 242, 17},

    -- PFTP
    {365, 662, 6},
    {365, 662, 17},

    -- PKIX Timestamp
    {368, 9318, 6},
    {368, 9318, 17},
    {368, 318, 6},
    {368, 318, 17},

    -- POP2
    {370, 109, 6},
    {370, 109, 17},

    -- PROFILE
    {377, 136, 6},
    {377, 136, 17},

    -- PROSPERO
    {378, 191, 6},
    {378, 191, 17},

    -- PWDGEN
    {381, 129, 6},
    {381, 129, 17},

    -- Qbik
    {382, 368, 6},
    {382, 368, 17},

    -- RIP
    {395, 520, 17},

    -- RIS
    {396, 180, 6},
    {396, 180, 17},

    -- RLP
    {399, 39, 6},
    {399, 39, 17},

    -- RMT
    {400, 411, 6},

    -- RPC2PMAP
    {401, 369, 6},
    {401, 369, 17},

    -- RRP
    {402, 648, 6},
    {402, 648, 17},

    -- RSVD
    {404, 168, 6},
    {404, 168, 17},

    -- RTSPS
    {408, 322, 6},
    {408, 322, 17},

    -- Remote Job Service
    {391, 71, 6},
    {391, 71, 17},

    -- Remote Telnet
    {392, 107, 6},
    {392, 107, 17},

    -- ResCap
    {393, 283, 6},
    {393, 283, 17},

    -- SCCP
    {2940, 2000, 6},
    {2940, 2000, 17},

    -- SGCP
    {421, 440, 6},
    {421, 440, 17},

    -- SGMP
    {422, 153, 6},
    {422, 153, 17},

    -- SMAKYNET
    {433, 122, 6},
    {433, 122, 17},

    -- SMPTE
    {435, 420, 6},
    {435, 420, 17},

    -- SMSP
    {436, 413, 6},
    {436, 413, 17},

    -- SNA Gateway
    {438, 108, 6},
    {438, 108, 17},

    -- SNPP
    {440, 444, 6},
    {440, 444, 17},

    -- SRC
    {444, 200, 6},
    {444, 200, 17},

    -- SRMP
    {445, 193, 6},
    {445, 193, 17},

    -- SUPDUP
    {453, 95, 6},
    {453, 95, 17},

    -- Sco I2 Dialog Daemon
    {412, 360, 6},
    {412, 360, 17},

    -- SecurSight
    {416, 2478, 6},
    {416, 2478, 17},

    -- Semantix
    {417, 361, 6},
    {417, 361, 17},

    -- Sender Rewriting Scheme
    {446, 362, 6},
    {446, 362, 17},

    -- Shrinkwrap
    {424, 358, 6},
    {424, 358, 17},

    -- Silverplatter
    {425, 416, 6},
    {425, 416, 17},

    -- SoftPC
    {441, 215, 6},
    {441, 215, 17},

    -- Stat Service
    {449, 133, 6},
    {449, 133, 17},

    -- Su-Mit Telnet
    {451, 89, 6},
    {451, 89, 17},

    -- Sybase SQL
    {458, 1498, 6},
    {458, 1498, 17},

    -- Systat
    {463, 11, 6},
    {463, 11, 17},

    -- TAC News
    --{465, 98, 6},
    --{465, 98, 17},

    -- TCPMUX
    {466, 1, 6},
    {466, 1, 17},

    -- Texar
    {468, 333, 6},
    {468, 333, 17},

    -- Time
    {470, 37, 6},
    {470, 37, 17},

    -- Tobit David
    {472, 267, 6},
    {472, 267, 17},

    -- Tripwire
    {474, 1169, 6},
    {474, 1169, 17},

    -- UAAC
    {476, 145, 6},
    {476, 145, 17},

    -- UARPS
    {477, 219, 6},
    {477, 219, 17},

    -- UIS
    {480, 390, 6},
    {480, 390, 17},

    -- UMA
    {482, 1797, 6},
    {482, 1797, 17},

    -- UPS
    {486, 401, 6},
    {486, 401, 17},

    -- UTMP
    {489, 430, 6},
    {489, 430, 17},

    -- UUCP
    {490, 540, 6},
    {490, 540, 17},

    -- Unidata LDM
    {484, 388, 6},
    {484, 388, 17},

    -- Unify
    {485, 181, 6},
    {485, 181, 17},

    -- VM PWSCS
    {494, 214, 6},
    {494, 214, 17},

    -- VMNET
    {493, 175, 6},
    {493, 175, 17},

    -- VSLMP
    {496, 312, 6},
    {496, 312, 17},

    -- Vchat
    {491, 1168, 6},
    {491, 1168, 17},

    -- Webfilter
    {499, 1046, 6},
    {499, 1046, 17},

    -- XNS
    {520, 165, 6},
    {520, 165, 17},

    -- XNS Authentication
    {516, 56, 6},
    {516, 56, 17},

    -- XNS Clearinghouse
    {517, 54, 6},
    {517, 54, 17},

    -- XNS Mail
    {518, 58, 6},
    {518, 58, 17},

    -- XNS Time
    {519, 52, 6},
    {519, 52, 17},

    -- Xfer
    {514, 82, 6},
    {514, 82, 17},

    -- Xyplex
    {521, 173, 6},
    {521, 173, 17},

    -- Zannet
    {526, 317, 6},
    {526, 317, 17},

    -- Zebra
    {527, 346, 6},
    {527, 346, 17},

    -- dBase
    {108, 217, 6},
    {108, 217, 17},

    -- mck-ivpip
    {283, 2698, 6},
    {283, 2698, 17},

    -- mit-ml-dev
    {293, 85, 6},
    {293, 85, 17},

    -- vettcp
    {492, 78, 6},
    {492, 78, 17},

    -- RIPng
    {3836, 521, 6},
    {3836, 521, 17},

    -- aAurora
    {3837, 9084, 6},
    {3837, 9084, 17},

    -- Diameter
    {3839, 3868, 6},
    {3839, 3868, 17},

    -- Chargen
    {586, 19, 6},
    {586, 19, 17},

    -- rje
    {397, 5, 6},
    {397, 5, 17},

    -- OPC
    {1098, 423, 6},
    {1098, 423, 17},
    {1098, 424, 6},
    {1098, 424, 17},

    -- OCS
    {346, 429, 6},
    {346, 429, 17},

    -- HTTPMGMT
    {209, 280, 6},
    {209, 280, 17},

    -- MSG
    {305, 31, 6},
    {305, 31, 17},

    --CORBA
    {99, 683, 6},
    {99, 683, 17}, 

    -- CDC
    {71, 223, 6},
    {71, 223, 17},

    -- AUDIT
    {42, 182, 6},
    {42, 182, 17},

    -- AppleShare
    {30, 311, 6},
    {30, 311, 17},

    -- XBONE
    {511, 265, 6},
    {511, 265, 17},

    -- GSS License Verification
    {192, 128, 6},
    {192, 128, 17},

    -- l2tp
    {259, 1701, 6},
    {259, 1701, 17},

    -- ESP
    {3886, 2070, 6},
    {3886, 2070, 17},
    {3886, 2797, 6},
    {3886, 2797, 17},

    -- Linuxconf
    {715, 98, 6},
    {715, 98, 17},

    -- Nessus
    {752, 1241, 6},
    {752, 1241, 17},

    -- ntalk
    {766, 518, 6},
    {766, 518, 17},

    -- talk
    {857, 517, 6},
    {857, 517, 17},

    -- X font server
    {919, 7100, 6},
    {919, 7100, 17},

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
