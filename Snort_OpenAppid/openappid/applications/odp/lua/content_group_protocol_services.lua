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
detection_name: Content Group "Protocol Services"
version: 10
description: Group of Protocol Service detectors.
bundle_description: $VAR1 = {
          'TCF' => 'Target Communication Framework is a network protocol used mainly for embedded systems.',
          'Encapsulation Header' => 'Encapsulation Protocol is an IP over IP tunneling protocol.',
          'IPX over IP' => 'Internetwork Packet Exchange encapsulated in IP.',
          'Schedule Transfer Protocol' => 'Scheduled Transfer Protocol is a new ANSI specifed connection-oriented data transfer protocol.',
          'Wang Span' => 'Registered with IANA as IP Protocol 74.',
          'IGMP' => 'Internet Group Messaging Protocol, used to help form multicast networks.',
          'IRTP' => 'Internet Reliable Transaction Protocol, a transport level host-to-host protocol.',
          'SATNET and Backroom EXPAK' => 'Registered with IANA as IP Protocol 64.',
          'GGP' => 'Gateway to Gateway Protocol, an obsolete transport protocol.',
          'UTI' => 'Registered with IANA as IP Protocol 120.',
          'Semaphore Sec Pro' => 'Registered with IANA as IP Protocol 96.',
          'EtherIP' => 'EtherIP is a protocol used for tunneling Ethernet packets across an IP internet.',
          'IDRP' => 'Inter-Domain Routing Protocol, an exterior gateway protocol.',
          'SKIP' => 'Simple Key-Management for Internet Protocol is for the sharing of encryption keys.',
          'IGRP' => 'Cisco\'s Interior Gateway Routing Protocol is a distance vector interior routing protocol.',
          'Leaf-2' => 'The Leaf File Access Protocol is one of the first protocols to enable remote access to files.',
          'Packet Radio Measurement' => 'Registered with IANA as IP Protocol 21.',
          'IPv6 encapsulation' => 'A packet is encapsulated and carried as payload within an IPv6 packet.',
          'i-nlsp' => 'Integrated Net Layer Security Protocol, a proposed security protocol.',
          'TP++' => 'Transport Protocol++. Registered with IANA as IP Protocol 39.',
          'Leaf-1' => 'The Leaf File Access Protocol is one of the first protocols to enable remote access to files.',
          'NSFNET-IGP' => 'An interior gateway protocol developed by NSFNET.',
          'EGP' => 'Exterior Gateway Protocol, predecessor of BGP. Used between Autonomous Systems.',
          'ICMP for IPv6' => 'Internet Control Message Protocol version 6 (ICMPv6) is the implementation of the Internet Control Message Protocol (ICMP) for Internet Protocol version 6 (IPv6).',
          'ISIS' => 'Intermediate System-to-Intermediate System is an interior gateway routing protocol.',
          'OSPF' => 'Open Shortest Path First, a link state routing protocol.',
          'Wideband Monitoring' => 'Registered with IANA as IP Protocol 78.',
          'BBN RCC' => 'Registered with IANA as IP Protocol 10.',
          'Active Networks' => 'A networking technology used to enable unique processing of each network packet.',
          'IDPR Control Message' => 'Constructs and maintains routes between source and destination domains in an IDPR network.',
          'ST' => 'Internet Stream Protocol (ST or ST2) is a QoS protocol.',
          'IPLT' => 'Registered with IANA as IP Protocol 129.',
          'Emission Control Protocol' => 'Registered with IANA as IP Protocol 14.',
          'MTP' => 'Media Transfer Protocol is a set of custom extensions to the Picture Transfer Protocol.',
          'SNP' => 'Sitara Network Protocol, a network control protocol.',
          'DDP' => 'Datagram Delivery Protocol is a member of the AppleTalk networking protocol suite.',
          'IFMP' => 'Ipsilon Flow Management Protocol, is a label-switching protocol.',
          'SMP' => 'Simple Message Protocol is reliable thread-to-thread communications medium.',
          'PIM' => 'Protocol-Independent Multicast is a family of multicast routing protocols for IP.',
          'TPCP' => 'Third Party Connect Protocol.',
          'GRE' => 'Generic Routing Encapsulation, tunnels one network layer protocol over another.',
          'ISO IP' => 'An ISO-specified network layer protocol.',
          'IPCU' => 'Internet Packet Core Utility, registered with IANA as IP Protocol 71.',
          'VRRP' => 'Virtual Router Redundancy Protocol is a network protocol.',
          'SSCOPMCE' => 'Service Specific Connection Oriented Protocol in a Multilink and Connectionless Environment.',
          'Wideband EXPAK' => 'Registered with IANA as IP Protocol 79.',
          'any host' => 'Registered with IANA as IP Protocol 61.',
          'SCPS' => 'Space Communications Protocol Specifications, a set of extensions to existing protocols to improve performance in space environments.',
          'RVD' => 'Remote Virtual Disk protocol is a remote disk reading device driver.',
          'RSVP-E2E-IGNORE' => 'A Protocol used in Aggregation of RSVP for IPv4 and IPv6 Reservations.',
          'SM' => 'Registered with IANA as IP Protocol 122.',
          'BNA' => 'BNA is a suite of networking protocols for mainframes.',
          'IATP' => 'Interactive Agent Transfer Protocol.',
          'CP Heart Beat' => 'Registered with IANA as IP Protocol 73.',
          'TP4' => 'Transport Protocol Class 4 (TP4), an ISO-specified transport protocol.',
          'SUN NDP' => 'Registered with IANA as IP Protocol 77.',
          'Trunk-2 Protocol' => 'Registered with IANA as IP Protocol 24.',
          'SATNET Monitoring' => 'A protocol used for the monitoring and control of multiple-access satellite networks.',
          'HIP' => 'Host Identity Protocol, host identification technology.',
          'SATNET' => 'Registered with IANA as IP Protocol 76.',
          'Cross Net Debugger' => 'Cross Net Debugger is a networked debugger.',
          'UDP Lite' => 'A connectionless datagram protocol that only checksums a portion of the datagrams.',
          'SDRP' => 'Source Demand Routing Protocol calculates routes by source.',
          'ARIS' => 'Aggregate Route-Based IP Switching establishes switched paths through a network.',
          'IP Mobility' => 'An IETF standard communications protocol for mobile devices.',
          'IP in IP' => 'Tunneling IP within IP.',
          'Sprite RPC' => 'RPC for the Sprite operating system.',
          'Combat Radio Transport Protocol' => 'Transports the combat radio\'s data through in an internet network.',
          'Combat Radio User Datagram' => 'Registered with IANA as IP Protocol 127.',
          'PNNI' => 'Private Network-to-Network Interface is an ATM-related suite of protocols.',
          'Swipe' => 'An experimental IP security protocol.',
          'IDPR' => 'Inter-Domain Policy Routing Protocol.',
          'MPLS' => 'Multiprotocol Label Switching allows one to run the data link layer over the network layer.',
          'ESP' => 'Encapsulating Security Payload, a part of the IPSec security protocol suite.',
          'Compaq-Peer' => 'Proprietary protocol used by HP to set up peer-to-peer networks.',
          'PIPE' => 'Private IP Encapsulation within IP is an IP-within-IP tunneling protocol.',
          'RSVP' => 'Resource Reservation Protocol, a transport layer protocol.',
          'DSR' => 'Dynamic Source Routing is a routing protocol for wireless mesh networks.',
          'PARC Universal Packet' => 'An early transport protocol.',
          'VMTP' => 'Versatile Message Transaction Protocol is a transport protocol for RPC.',
          'NVP' => 'Network Voice Protocol, for transporting human speech over packetized communications networks.',
          'Fire' => 'Registered with IANA as IP Protocol 125.',
          'MFE' => 'Registered with IANA as IP Protocol 31.',
          'Reliable Datagram Protocol' => 'Reliable Datagram Protocol, a transport layer protocol.',
          'PGM RTP' => 'Pragmatic General Multicast Reliable Transport Protocol, a multicast protocol.',
          'IPComp' => 'IP Payload Compression Protocol, reduces the size of IP datagrams.',
          'CBT' => 'The Core-Based Trees protocol is a multicast technology.',
          'MERIT Internodal Protocol' => 'An uncommonly used transport protocol.',
          'MICP' => 'Mobile Internetworking Control Protocol.',
          'SRP' => 'SpectraLink Radio Protocol is a proprietary wireless protocol.',
          'GMTP' => 'Graphical Media Transfer Protocol, a lightweight graphical MTP media client for UNIX.',
          'NARP' => 'NBMA Address Resolution Protocol.',
          'iFCP' => 'Internet Fibre Channel Protocol.',
          'HMP' => 'Host Monitoring Protocol is a connectionless transport protocol.',
          'D-II' => 'Registered with IANA as IP Protocol 116.',
          'L2TP' => 'A tunneling protocol used in VPNs and DSL customer loops.',
          'Trunk-1 Protocol' => 'Registered with IANA as IP Protocol 23.',
          'CP Network Executive' => 'Registered with IANA as IP Protocol 72.',
          'DCN Measurement Subsystems' => 'Registered with IANA as IP Protocol 19.',
          'cFTP' => 'Client-Oriented File Transfer Protocol is a PHP-based file transfer protocol.',
          'AX.25' => 'AX.25 is a data link layer protocol derived from the X.25 protocol suite.',
          'Argus' => 'Registered with IANA as IP Protocol 13.',
          'PTP' => 'Performance Transparency Protocol.',
          'QNX' => 'A commercial Unix-like real-time operating system.',
          'Pluribus Packet Core' => 'Registered with IANA as IP Protocol 67.',
          'NETBLT' => 'NETwork BLock Transfer, a transport layer protocol.',
          'IDP' => 'Xerox Internet Datagram Protocol',
          'Locus ARP' => 'Registered with IANA as IP Protocol 91.',
          'SPS' => 'Secure Packet Shield, an early competitor of IPSEC.',
          'ICMP' => 'Internet Control Message Protocol.',
          'TTP' => 'Registered with IANA as IP Protocol 84.',
          'PVP' => 'Packet Video Protocol (PVP) is a set of extensions to the Network Voice Protocol.',
          'IL' => 'The Internet Link Protocol or IL is a connection-based transport layer protocol.',
          'CHAOSNet' => 'CHAOSNet is one of the earliest local area network hardware implementations.',
          'EIGRP' => 'Enhanced Interior Gateway Routing Protocol is a Cisco interior gateway protocol.'
        };

--]]

require "DetectorCommon"

local DC = DetectorCommon

DetectorPackageInfo = {
    name = "content_group_protocol_services",
    proto =  DC.ipproto.tcp,
    client = {
        init =  'DetectorInit',
        clean =  'DetectorClean',
        minimum_matches =  1
    }
}

-- "AppId", "port", "protocol" (6 = TCP, 17 = UDP)
gPortServiceList = {

    -- Internet Control Message Protocol
    {3501, 0, 1},

    -- Internet Group Messaging Protool
    {3842, 0, 2},

    -- IP in IP
    {3504, 0, 94},

    -- Stream
    {3505, 0, 5},

    -- Core-Based Trees
    {3507, 0, 7},

    -- Exterior Gateway Protocol
    {3508, 0, 8},

    -- Cisco Interior Gateway Routing Protocol
    {3509, 0, 9},

    -- BBN RCC Monitoring
    {3510, 0, 10},

    -- Network Voice Protocol
    {3511, 0, 11},

    -- Argus
    {3513, 0, 13},

    -- Emission Control Protocol
    {3514, 0, 14},

    -- Cross Net Debugger
    {3515, 0, 15},

    -- CHAOSNet
    {3516, 0, 16},

    -- DCN Measurement Subsystems
    {3519, 0, 19},

    -- Host Monitoring Protocol
    {3520, 0, 20},

    -- Packet Radio Measurement
    {3521, 0, 21},

    -- Trunk-1
    {3523, 0, 23},

    -- Trunk-2 Protocol
    {3524, 0, 24},

    -- Leaf-1
    {3525, 0, 25},

    -- Leaf-2
    {3526, 0, 26},

    -- Reliable Data Protocol
    {3527, 0, 27},

    -- Internet Reliable Transaction
    {3528, 0, 28},

    -- ISO Transport Protocol Class 4
    {3529, 0, 29},

    -- Bulk Data Transfer Protocol
    {3530, 0, 30},

    -- MFE Network Services Protocol
    {3531, 0, 31},

    -- Third Party Connect Protocol
    {3534, 0, 34},

    -- Inter-Domain Policy Routing Protocol
    {3535, 0, 35},

    -- Xpress Transport Protocol
    {3123, 0, 36},

    -- Datagram Delivery Protocol
    {3537, 0, 37},

    -- IDPR Control Message Transport Protocol
    {3538, 0, 38},

    -- TP++ Transport Protocol
    {3539, 0, 39},

    -- Internal Link Transport Protocol
    {3540, 0, 40},

    -- IPv6 encapsulation
    {3541, 0, 41},

    -- Source Demand Routing Protocol
    {3542, 0, 42},

    -- Inter-Domain Routing Protocol
    {3545, 0, 45},

    -- Resource Reservation Protocol
    {3948, 0, 46},

    -- Generic Route Encapsulation
    {3654, 0, 47},

    -- Dynamic Source Routing Protocol
    {3548, 0, 48},

    -- BNA
    {3549, 0, 49},

    -- ESP
    {3886, 0, 50},

    -- Integrated Net Layer Security Protocol
    {3552, 0, 52},

    -- Swipe
    {3553, 0, 53},

    -- NBMA Address Resolution Protocol
    {3554, 0, 54},

    -- IP Mobility
    {3555, 0, 55},

    -- Simple Key-Management for Internet Protocol
    {3557, 0, 57},

    -- ICMP for IPv6
    {3558, 0, 58},

    -- any host internal protocol
    {3561, 0, 61},

    -- cFTP
    {3562, 0, 62},

    -- SATNET and Backroom EXPAK
    {3564, 0, 64},

    -- MIT Remote Virtual Disk Protocol
    {3566, 0, 66},

    -- Internet Pluribus Packet Core
    {3567, 0, 67},

    -- SATNET Monitoring
    {3569, 0, 69},

    -- Internet Packet Core Utility
    {3571, 0, 71},

    -- Computer Protocol Network Executive
    {3572, 0, 72},

    -- Computer Protocol Heart Beat
    {3573, 0, 73},

    -- Wang Span Network
    {3574, 0, 74},

    -- Packet Video Protocol
    {3575, 0, 75},

    -- Backroom SATNET Monitoring
    {3576, 0, 76},

    -- SUN ND PROTOCOL-Temporary
    {3577, 0, 77},

    -- WIDEBAND Monitoring
    {3578, 0, 78},

    -- Wideband EXPAK
    {3579, 0, 79},

    -- ISO IP
    {3843, 0, 80},
    {3843, 0, 80},

    -- VERSATILE MESSAGE TRANSACTION PROTOCOL
    {3582, 0, 81},
    {3582, 0, 82},

    -- TTP
    {3584, 0, 84},

    -- NSFNET-IGP
    {3585, 0, 85},

    -- TCF
    {3587, 0, 87},

    -- Interior Gateway Routing Protocol
    {3588, 0, 88},

    -- Open Shortest Path First
    {3589, 0, 89},

    -- Sprite RPC Protocol
    {3590, 0, 90},

    -- Locus Address Resolution Protocol
    {3591, 0, 91},

    -- Multicast Transport Protocol
    {3592, 0, 92},

    -- AX.25 Frames
    {3593, 0, 93},

    -- IP-within-IP Encapsulation Protocol
    -- {3594, 0, 94},

    -- Mobile Internetworking Control Protocol
    {3595, 0, 95},

    -- Semaphore Communications Sec. Pro.
    {3596, 0, 96},

    -- Ethernet-within-IP Encapsulation
    {3597, 0, 97},

    -- Encapsulation Header
    {3598, 0, 98},

    -- GMTP
    {3600, 0, 100},

    -- Ipsilon Flow Management Protocol
    {3601, 0, 101},

    -- Private Network-to-Network Interface over IP
    {3602, 0, 102},

    -- Protocol Independent Multicast
    {3862, 0, 103},

    -- Aggregate Route-Based IP Switching
    {3604, 0, 104},

    -- Space Communications Protocol Specifications
    {3605, 0, 105},

    -- QNX
    {3606, 0, 106},

    -- Active Networks
    {3607, 0, 107},

    -- IP Payload Compression Protocol
    {3863, 0, 108},

    -- Sitara Network Protocol
    {3609, 0, 109},

    -- Compaq-Peer Protocol
    {3610, 0, 110},

    -- IPX in IP
    {3611, 0, 111},

    -- Virtual Router Redundancy Protocol
    {3612, 0, 112},

    -- PGM Reliable Transport Protocol
    {3613, 0, 113},

    -- D-II Data Exchange
    {3616, 0, 116},

    -- Interactive Agent Transfer Protocol
    {3617, 0, 117},

    -- Schedule Transfer Protocol
    {3618, 0, 118},

    -- SpectraLink Radio Protocol
    {3619, 0, 119},

    -- UTI
    {3620, 0, 120},

    -- Simple Message Protocol
    {3621, 0, 121},

    -- SM
    {3622, 0, 122},

    -- Performance Transparency Protocol
    {3623, 0, 123},

    -- ISIS
    {3624, 0, 124},

    -- Fire
    {3625, 0, 125},

    -- Combat Radio Transport Protocol
    {3626, 0, 126},

    -- Combat Radio User Datagram
    {3627, 0, 127},

    -- SSCOPMCE
    {3628, 0, 128},

    -- IPLT
    {3629, 0, 129},

    -- Secure Packet Shield
    {3630, 0, 130},

    -- Private IP Encapsulation within IP
    {3631, 0, 131},

    -- Fibre Channel
    {3633, 0, 133},

    -- RSVP-E2E-IGNORE
    {3634, 0, 134},

    -- MPLS-in-IP
    {3637, 0, 137},

    -- Host Identity Protocol
    {3639, 0, 139},

    -- DCCP
    {110, 0, 33},
    
    -- GGP
    {3695, 0, 3},

    -- MANET
    {276, 0, 138},
    
    -- MERIT Internodal Protocol     
    {3696, 0, 32},

    -- PARC Universal Packet
    {3864, 0, 12},

    -- IDP
    {3865, 0, 22},

    -- UDP Lite
    {3699, 0, 136},    

    -- l2tp
    {259, 0, 115},

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
