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
detection_name: SSL Group "Queen"
version: 15
description: Group of SSL Host detectors.
bundle_description: $VAR1 = {
          'Wimbledon' => 'Tennis related website.',
          'Jetsetz' => 'Travel booking and price comparison site.',
          'TwitchTV' => 'Justin.tv gaming specific livestreaming platform.',
          'ooVoo' => 'Video chat and instant messaging.',
          'The Huffington Post' => 'Online news website.',
          'Zendesk' => 'Customer support web application.',
          'Verizon Wireless' => 'Telecom and Internet provider.',
          'Yahoo! Calendar' => 'Yahoo! online calendar app.',
          'Liberty Mutual' => 'Insurance company.',
          'Vine' => 'Mobile App for sharing photos and videos clips.',
          'OpenSUSE' => 'Official website for OpenSUSE, Linux based OS.',
          'Red Hat' => 'Open-source software products.',
          'Yammer' => 'Enterprise social networking site.',
          'Geico' => 'Insurance company.',
          'Bitcoin Forum' => 'Forums for discussing BitCoin mining and exchange.',
          'J.P. Morgan' => 'Financial services arm of J.P. Morgan Chase & Co.',
          'Allstate' => 'Insurance company.',
          'State Farm' => 'Insurance company.',
          'Path' => 'Private instant messaging.',
          'FriendFinder' => 'Online friend finder and dating site.',
          'Bitbucket' => 'Source code hosting site.',
          'Nuance' => 'Airline services and travel planner.',
          'Windows Azure' => 'Cloud computing by Microsoft.',
          'Box' => 'File storage and transfer site.',
          'United Airlines' => 'Online Flight reservation from United Airlines.',
          'FedEx' => 'Courier delivery services.',
          'TextNow' => 'Instant text and voice services.',
          'Adobe Software' => 'Adobe software and updates.',
          'BoldChat' => 'Live Chat software for website.',
          'Eventbrite' => 'Event organization and invite site.',
          'American Airlines' => 'Airline services and travel planner.',
          'iTunes U' => 'Access to courses from the leading universities.',
          'Windows Live SkyDrive' => 'Cloud based file hosting service.',
          'Fidelity' => 'Mutual fund and financial services company.',
          'DSW' => 'Designer Shoe Warehouse - branded footwear.',
          'Nvidia' => 'Video chipset manufacturer.',
          'PNC Bank' => 'Banking and Financial services.',
          'Bing Maps' => 'Microsoft online mapping and directions service.',
          'Progressive' => 'Insurance company.',
          'lynda.com' => 'Online education site focusing on aspects of web design.',
          'StudentUniverse' => 'Travel booking and price comparison site for students.',
          'Game Center' => 'Social gaming app for iOS.',
          'Audible.com' => 'Digital audio version for books, magazines, information and other entertainments.',
          'MLive' => 'News local to the American state of Michigan.',
          'Woopra' => 'Real time customer service and solutions.',
          'Netflix' => 'Rental and on-demand internet television and movie streaming website.',
          'Starbucks' => 'Mobile application for a ubiquitous chain of coffee shops.',
          'GoBank' => 'A bank that focuses on mobile banking.'
        };

--]]

require "DetectorCommon"


local DC = DetectorCommon

DetectorPackageInfo = {
    name =  "ssl_host_group_reo",
    proto =  DC.ipproto.tcp,
    client = {
        init =  'DetectorInit',
        clean =  'DetectorClean',
        minimum_matches =  1
    }
}

--serviceId, clientId, ClientType, PayloadId, PayloadType, hostPattern, pathPattern, schemePattern, queryPattern
gSSLHostPatternList = {

    -- OpenSuse
    { 0, 2056, 'opensuse.org' },
    -- DSW 
    { 0, 2059, 'dsw.tt.omtrdc.net' },
    { 0, 2059, 'dsw.com' },
    -- BoldChat
    { 0, 2067, 'boldchat.com' },
    -- Woopra 
    { 0, 2069, 'woopra.com' },
    -- iTunes U
    { 1, 2073, 'itunesu.itunes.apple.com' },
    -- Bitcoin Forum
    { 0, 2085, 'bitcointalk.org' },
    -- lynda.com
    { 0, 2086, 'lynda.com' },
    -- Game Center
    { 1, 2092, 'service.gc.apple.com' },
    { 0, 2092, 'gc.apple.com' },
    -- FriendFinder
    { 0, 2093, 'friendfinder.com' },
    -- Audible.com
    { 0, 2094, 'audible.com' },
    { 0, 2094, 'audible.112.2o7.net' },
    { 0, 2094, 'audible.tt.omtrdc.net' },
    -- Bing Maps
    { 0, 1197, 'virtualearth.net' },
    -- Windows Azure
    { 0, 2111, 'windowsazure.com' },
    { 0, 2111, 'windows.net' },
    { 0, 2111, 'azurewebsites.net' },
    -- Windows Live Skydrive
    { 0, 911, 'skyapi.live.net' },
    { 0, 911, 'skydrivesync,policies.live.net' },
    { 0, 911, 'storage.live.com' },
    { 0, 911, 'storage.msn.com' },
    { 0, 911, 'live.filestore.com' },
    -- Box
    { 0, 1326, 'boxcloud.com' },
    { 0, 1326, 'box.com' },
    { 0, 1326, 'box.net' },
    { 0, 1326, 'box.org' },
    { 0, 1326, 'boxuniversity.litmos.com' },
    -- Eventbrite
    { 0, 2139, 'eventbrite.com' },
    -- Fidelity
    { 0, 636, 'fidelity.com' },
    -- J.P. Morgan
    { 0, 2140, 'jpmorgan.com' },
    { 0, 2140, 'jpmm.com' },
    -- GoBank
    { 0, 2141, 'gobank.com' },
    -- Verizon Wireless
    { 0, 1388, 'verizonwireless.com' },
    { 0, 1388, 'myvzw.com' },
    { 0, 1388, 'vzw.com' },
    -- Path
    { 0, 2142, 'path.com' },
    -- pROGRESSIVE, INC
    { 0, 2152, 'onlineservice3.progrssive.com' },
    { 0, 2152, 'www.progressive.com' },
    -- State Farm
    { 0, 2153, 'online2.statefarm.com' },
    { 0, 2153, 'www.statefarm.com' },
    -- Allstate
    { 0, 2154, 'myaccount.allstate.com' },
    -- geico
    { 0, 2155, 'service.geico.com' },
    { 0, 2155, 'www.geico.com' },
    { 0, 2155, 'geico.com' },
    -- Liberty Mutual
    { 0, 2156, 'online.libertymutual.com' },
    -- TwitchTV
    { 0, 1051, 'twitch.tv' },
    -- PNC Bank
    { 0, 2172, 'pnc.com' },
    { 0, 2172, 'pncmc.com' },
    { 0, 2172, 'pncactivepay.com' },
    -- Red Hat
    { 0, 2173, 'redhat.com' },
    -- StudentUniverse
    { 0, 2161, 'studentuniverse.com' },
    -- StudentUniverse
    { 0, 2160, 'jetsetz.com' },
    -- United Airlines
    { 0, 2174, 'united.com' },
    -- Nvidia
    { 0, 2150, 'nvidia.com' },
    -- Nvidia
    { 0, 2128, 'zendesk.com' },
    -- Adobe Software
    { 0, 541, 'macromedia.com' },
    -- Netflix 
    { 0, 756, 'nflximg.net' },
    -- TextNow 
    { 1, 2176, 'textnow.me' },
    { 0, 2176, 'textnow.com' },
    -- FedEx 
    { 0, 2177, 'fedex.com' },
    { 0, 2177, 'fedex.tt.omtrdc.net' },
    -- American Airlines
    { 0, 2178, 'aa.com' },
    { 0, 2178, 'aavacations.com' },
    -- Huffingtonpost 
    { 0, 1370, 'huffingtonpost.com' },
    { 0, 1370, 'huffpost.com' },
    -- Nuance
    { 0, 2179, 'nuance.com' },
    { 0, 2179, 'nuan.netmng.com' },
    -- Wimbledon
    { 0, 2181, 'shop.wimbledon.com' },
    -- MLive
    { 0, 2182, 'mlive.com' },
    -- Vine
    { 0, 1700, 'vine.co' },
    -- Bitbucket
    { 0, 2185, 'bitbucket.org' },
    -- ooVoo
    { 0, 2190, 'oovoo.com' },
    -- Yahoo! Mail
    { 0, 946, 'mail.yahoo.com' },
    -- Yahoo!
    { 0, 524, 'yahooapis.com' },
    -- Yahoo! Calednar
    { 0, 2196, 'caldav.calendar.yahoo.com' },
    { 0, 2196, 'calendar.yahoo.com' },
    -- Yammer
    { 0, 2198, 'www.yammer.com' },
    { 0, 2198, 'yammer.com' },

}

function DetectorInit(detectorInstance)

    gDetector = detectorInstance;

    if gDetector.addSSLCertPattern then
        for i,v in ipairs(gSSLHostPatternList) do
            gDetector:addSSLCertPattern(v[1],v[2],v[3]);
        end
    end
    return gDetector;
end

function DetectorClean()
end

