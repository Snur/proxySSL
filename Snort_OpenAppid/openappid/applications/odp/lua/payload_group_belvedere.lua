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
detection_name: Payload Group "Belvedere"
version: 16
description: Group of payload detectors.
bundle_description: $VAR1 = {
          'Pinger' => 'Allows SMS text messaging via a data connection.',
          'Akamai' => 'Internet content delivery network and SSL certificate provider.',
          'Taringa' => 'Argentinian Social network.',
          '500px' => 'Online photo sharing.',
          'iCloud' => 'Apple cloud storage service.',
          'The Telegraph' => 'Online news portal.',
          'Aili' => 'Chinese web portal for news and reviews about fashion.',
          'TextMe' => 'VoIP based software for video calls and instant messaging.',
          'ClearSea SIP Client' => 'ClearSea SIP Client.',
          'Invitemedia' => 'Advertising portal.',
          'Cisco SIP Gateway' => 'Cisco SIP gateway.',
          'Facebook search' => 'Using the search bar on Facebook.',
          'Yieldmanager' => 'Online advertising delivery portal.',
          'Jingdong (360buy.com)' => 'Chinese e-commerce site.',
          'FreeSWITCH' => 'Open source implementation for VoIP.',
          'Livedoor' => 'Japanese Internet service provider.',
          'Nuance Voice Platform' => 'Nuance Voice Platform.',
          'The Xinhuanet' => 'Chinese official website for the news agency Xinhua.',
          'Rediff.com' => 'Online news, information and web portal.',
          'Xlite SIP Client' => 'XTen X-lite SIP Client.',
          'X-PRO SIP Client' => 'XTen X-PRO SIP Client.',
          'Aliexpress' => 'Online shopping portal.',
          'UOL' => 'Brazilian web portal for news and entertainment.',
          'Magicland' => 'Facebook game application.',
          'Linphone' => 'VoIP application using SIP.',
          'Dwolla' => 'Online Payment service.',
          'Loyalty Innovations' => 'Reward programs and solutions for both online and offline.',
          'Adcash' => 'Advertising network.',
          'Nero SIP Client' => 'Nero SIP Client.',
          'LeTV' => 'Chinese online video portal.',
          '58 City' => 'Classified information about 58 cities in China.',
          'Apple Developer' => 'Web portal for Apple Developer.',
          'CSDN' => 'Chinese IT community/forum for Software related issues.',
          'Facebook event' => 'A message or page view of a social event on Facebook.',
          'Shutterstock' => 'Online collection of Stock photographs and illustrations.',
          'WarriorForum' => 'Internet Marketing Forums.',
          'Facebook post' => 'A status update on Facebook.',
          'Indiatimes' => 'Online news portal.',
          'Spiegel Online' => 'Web portal for the Germans magazine Der Speigel.',
          'Vonage' => 'Vonage is a VoIP company that provides telephone service via a broadband connection.',
          'Facebook video' => 'Viewing video posted on Facebook.',
          'Sharepoint' => 'Microsoft collaboration, file sharing and web publishing system.',
          'Asterisk PBX' => 'PBX implementation to support VoIP and PSTN.',
          'Yandex' => 'Russian search engine.',
          'The Guardian' => 'Online news portal.',
          'Bria' => 'VoIP based software for video calls and instant messaging.',
          'Facebook Apps' => 'Any facebook add on, generally games, puzzles, gifts, classifieds.',
          'OpenSIPS' => 'Open source implementation of SIP.',
          'sipXecs' => 'Open source for VoIP.',
          'Facebook video chat' => 'Video chat on Facebook.',
          'Rakuten' => 'Japanese e-commerce site.',
          'Urban Airship' => 'Mobile app developer.',
          'iTunes' => 'Apple\'s media player and online store.',
          'Tianya' => 'Chinese forum for blogging, microblogging and photo album services.',
          'textPlus' => 'Application which support free text, group chat and calls.'
        };

--]]

require "DetectorCommon"


local DC = DetectorCommon

DetectorPackageInfo = {
    name =  "payload_group_belvedere",
    proto =  DC.ipproto.tcp,
    client = {
        init =  'DetectorInit',
        clean =  'DetectorClean',
        minimum_matches =  1
    }
}

--serviceId, clientId, ClientType, PayloadId, PayloadType, hostPattern, pathPattern, schemePattern, queryPattern
gUrlPatternList = {

   --Apple Developer 
    { 0, 0, 0, 692,22, "developer.apple.com", "/", "http:", "", 1596},
    { 0, 0, 0, 692,22, "devforums.apple.com", "/", "http:", "", 1596},
    { 0, 0, 0, 692,22, "webobjects.com", "/", "http:", "", 1596},
    { 0, 0, 0, 692,22, "devimages.apple.com", "/", "http:", "", 1596},
   --Shutterstock 
    { 0, 0, 0, 808,22, "shutterstock.com", "/", "http:", "", 1614},
   --Aili
    { 0, 0, 0, 809,22, "aili.com", "/", "http:", "", 1615},
   --Yandex
    { 0, 0, 0, 810,22, "yandex.net", "/", "http:", "", 1616},
    { 0, 0, 0, 810,22, "yandex.ru", "/", "http:", "", 1616},
    { 0, 0, 0, 810,22, "yandex.st", "/", "http:", "", 1616},
    { 0, 0, 0, 810,22, "yandex.com", "/", "http:", "", 1616},
    { 0, 0, 0, 810,22, "yandex.com.tr", "/", "http:", "", 1616},
    { 0, 0, 0, 810,22, "yandex.ua", "/", "http:", "", 1616},
    { 0, 0, 0, 810,22, "yandex.by", "/", "http:", "", 1616},
    { 0, 0, 0, 810,22, "yandex.kz", "/", "http:", "", 1616},
   --Adcash
    { 0, 0, 0, 811,22, "adcash.com", "/", "http:", "", 1617},
   --The Guardian
    { 0, 0, 0, 812,22, "guardiannews.com", "/", "http:", "", 1618},
    { 0, 0, 0, 812,22, "guardian.co.uk", "/", "http:", "", 1618},
    { 0, 0, 0, 812,22, "guardianapis.com", "/", "http:", "", 1618},
    { 0, 0, 0, 812,22, "guim.co.uk", "/", "http:", "", 1618},
   --The Telegraph
    { 0, 0, 0, 813,22, "telegraph.co.uk", "/", "http:", "", 1620},
   --Livedoor
    { 0, 0, 0, 814,22, "livedoor.com", "/", "http:", "", 1621},
   --WarriorForum
    { 0, 0, 0, 815,22, "warriorforum.com", "/", "http:", "", 1622},
   --Indiatimes
    { 0, 0, 0, 816,22, "indiatimes.com", "/", "http:", "", 1623},
   --Rediff.com
    { 0, 0, 0, 817,22, "rediff.com", "/", "http:", "", 1624},
   --Spiegel Online
    { 0, 0, 0, 818,22, "spiegel.de", "/", "http:", "", 1625},
    { 0, 0, 0, 818,22, "spiegel.ivwbox.de", "/", "http:", "", 1625},
   --UOL
    { 0, 0, 0, 819,22, "uol.com.br", "/", "http:", "", 1626},
    { 0, 0, 0, 819,22, "uol.com", "/", "http:", "", 1626},
    { 0, 0, 0, 819,22, "imguol.com", "/", "http:", "", 1626},
    { 0, 0, 0, 819,22, "jsuol.com", "/", "http:", "", 1626},
   --Jingdong (360buy.com)
    { 0, 0, 0, 820,22, "360buy.com", "/", "http:", "", 1627},
    { 0, 0, 0, 820,22, "360buyimg.com", "/", "http:", "", 1627},
    { 0, 0, 0, 820,22, "jd.com", "/", "http:", "", 1627},
   --The Xinhuanet
    { 0, 0, 0, 821,22, "xinhuanet.com", "/", "http:", "", 1628},
   --CSDN 
    { 0, 0, 0, 822,22, "csdn.net", "/", "http:", "", 1646},
   --Taringa
    { 0, 0, 0, 823,22, "taringa.net", "/", "http:", "", 1647},
   --Aliexpress
    { 0, 0, 0, 824,22, "aliexpress.com", "/", "http:", "", 1648},
   --58 City 
    { 0, 0, 0, 825,22, "58.com", "/", "http:", "", 1649},
   --LeTV 
    { 0, 0, 0, 826,22, "letv.com", "/", "http:", "", 1650},
    { 0, 0, 0, 826,22, "letvimg.com", "/", "http:", "", 1650},
    { 0, 0, 0, 826,22, "letvcdn.com", "/", "http:", "", 1650},
    { 0, 0, 0, 826,22, "letv.allyes.com", "/", "http:", "", 1650},
   --Tianya
    { 0, 0, 0, 827,22, "tianya.cn", "/", "http:", "", 1651},
    { 0, 0, 0, 827,22, "tianyaui.com", "/", "http:", "", 1651},
   --Rakuten
    { 0, 0, 0, 828,22, "rakuten.com", "/", "http:", "", 1652},
    { 0, 0, 0, 828,22, "rakuten.co.jp", "/", "http:", "", 1652},
   --500px 
    { 0, 0, 0, 829,22, "500px.com", "/", "http:", "", 1654},
   --Invitemedia
    { 0, 0, 0, 830,22, "invitemedia.com", "/", "http:", "", 1656},
   --Urban Airship
    { 0, 0, 0, 835,22, "urbanairship.com","/", "http:", "", 1657},
   --Playfish 
   -- { 0, 0, 0, 836,22, "playfish.com","/", "http:", "", 1658},
   --Akamai
    { 0, 0, 0, 837,22, "akamai.com","/", "http:", "", 1659},
    { 0, 0, 0, 837,22, "akamaihd.net","/", "http:", "", 1659},
   --Loyalty Innovations
    { 0, 0, 0, 838,22, "loyaltyinnovation.com","/", "http:", "", 1660},
   --Sharepoint
    { 0, 0, 0, 840,22, "sharepoint.microsoft.com","/", "http:", "", 423},
    { 0, 0, 0, 840,22, "office.microsoft.com", "/en-us/sharepoint", "http:", "", 423},
   --Facebook search
    { 0, 0, 0, 841,22, "facebook.com","/ajax/typeahead/search", "http:", "", 1282},
    { 0, 0, 0, 841,22, "facebook.com","/find-friends/browser", "http:", "", 1282},
   --Facebook event 
    { 0, 0, 0, 842,22, "facebook.com","/events/", "http:", "", 1283},
    { 0, 0, 0, 842,22, "facebook.com","/ajax/pagelet", "http:", "", 1283},
   --Facebook post  
    { 0, 0, 0, 843,22, "facebook.com","/ajax/updatestatus.php", "http:", "", 1284},
    { 0, 0, 0, 843,22, "facebook.com","/ajax/composerx/attachment/status", "http:", "", 1284},
   --Facebook video chat
    { 0, 0, 0, 844,22, "facebook.com","/ajax/chat/video", "http:", "", 1285},
    { 0, 0, 0, 844,22, "facebook.com","/videocall/incall", "http:", "", 1285},
   --Facebook message   
    { 0, 0, 0, 845,22, "facebook.com","/messages", "http:", "", 1286},
   --Facebook video    
    { 0, 0, 0, 846,22, "facebook.com","/ajax/video", "http:", "", 1287},
    { 0, 0, 0, 846,22, "facebook.com","/video", "http:", "", 1287},
   --Dwolla
    { 0, 0, 0, 848,22, "dwolla.com","/", "http:", "", 1664},
   --iCloud
    { 0, 0, 0, 691,22, "icloud.com","/", "http:", "", 1187},
    { 0, 0, 0, 691,22, "me.com","/", "http:", "", 1187},
    { 0, 0, 0, 691,22, "mobileme.co","/", "http:", "", 1187},
   --iTunes
    { 0, 0, 0, 850,22, "itunes.com","/", "http:", "", 689},
    { 0, 0, 0, 850,22, "phobos.apple.com","/", "http:", "", 689},
    -- Vonage
    { 0, 0, 0, 851, 21, "vonage.com", "/", "http:", "", 495}, 
    -- Facebook Apps
    { 0, 0, 0, 852, 21, "apps.facebook.com", "/", "http:", "", 149}, 
    -- Magicland
    { 0, 0, 0, 853, 21, "facebook.com", "/magicland", "http:", "", 1666}, 
    { 0, 0, 0, 853, 21, "apps.facebook.com", "/magicland", "http:", "", 1666}, 
    -- LINE
    { 0, 0, 0, 853, 21, "facebook.com", "/magicland", "http:", "", 1666}, 
    -- Yieldmanager
    { 0, 0, 0, 862, 21, "yieldmanager.com", "/", "http:", "", 1619}, 

}

gSipServerPatternList = {

    -- Entry Format is <clientAppId <int>, clientVersion (string), multipart pattern (string)> 
    -- Testplus sip client
    { 1611, "", "proxy%&%gogii.com"},

}

gSipUserAgentPatternList = {

    -- Entry Format is <clientAppId <int>, clientVersion (string), multipart pattern (string)> 
    -- from http://www.voip-info.org/wiki/view/SIP+user+agent+identification
   --Xlite SIP Client
    { 1570, "1101", "X-Lite %&% build 1101"},
    { 1570, "1061", "X-Lite %&% build 1061"},
    { 1570, "1082", "X-Lite %&% build 1082"},
    { 1570, "1095", "X-Lite %&% build 1095"},
    { 1570, "1103a", "X-Lite %&% release 1103a"},
    { 1570, "5.0.0", "X-Lite %&% release 5.0.0 "},
    { 1570, "1103m", "X-Lite %&% release 1103m"},
    { 1570, "", "X-Lite"},
    -- XTen X-PRO SIP Client.
    { 1571, "1082", "X-PRO %&% build 1082"},
    { 1571, "1103a", "X-PRO %&% release 1103a"},
    { 1571, "1103v", "X-PRO %&% release 1103v"},
    { 1571, "", "X-PRO"},
    -- Nero SIP Client.
    { 1572, "2.0.51.16", "Nero SIPPS IP Phone%&%2.0.51.16"},
    { 1572, "", "Nero SIPPS IP Phone"},
    -- ClearSea SIP Client
    { 1573, "8.1.0", "LifeSize ClearSea Client %&% 8.1.0"},
    { 1573, "", "LifeSize ClearSea Client"},
    -- Bria     
    { 1604, "2.2.1", "Bria iOS %&%2.2.1"},
    { 1604, "", "Bria iOS"},
    -- sipXecs  
    { 1605, "3.10.2", "sipXecs/3.10.2 sipXecs/registry (Linux)"},
    { 1605, "", "sipXecs"},
    -- Linphone 
    { 1606, "3.5.2", "Linphone/3.5.2 (eXosip2/3.6.0)"},
    { 1606, "", "Linphone"},
    -- openSIPS 
    { 1607, "", "OpenSIPS"},
    -- TextMe
    { 1608, "2.0", "TextMe/2.0"},
    { 1608, "", "TextMe"},
    -- FreeSWITCH
    { 1609, "", "FreeSWITCH"},
    -- Asterisk
    { 1610, "1.6.0.6", "Asterisk PBX 1.6.0.6"},
    { 1610, "", "Asterisk PBX"},
    -- Cisco SIP Gateway 
    { 1612, "", "Cisco-SIPGateway/IOS-12.x"},
    -- Nuance Voice Platform
    { 1613, "", "Nuance/Core-Mariner_SP03-B03_2008_07_15"},
    -- Pinger
    { 1148, "", "Pinger Softphone"},
}


function DetectorInit(detectorInstance)

    gDetector = detectorInstance;

    gDetector:addHttpPattern(2, 5, 0, 223, 1, 0, 0, 'textPlus/', 1611, 1); 

    if gDetector.addAppUrl then
        for i,v in ipairs(gUrlPatternList) do
            gDetector:addAppUrl(v[1],v[2],v[3],v[4],v[5],v[6],v[7],v[8],v[9],v[10]);
        end
    end

    if gDetector.addSipServer then
        for i,v in ipairs(gSipServerPatternList) do
            gDetector:addSipServer(v[1],v[2],v[3]);
        end
    end

    if gDetector.addSipUserAgent then
        for i,v in ipairs(gSipUserAgentPatternList) do
            gDetector:addSipUserAgent(v[1],v[2],v[3]);
        end
    end

    return gDetector;
end

function DetectorClean()
end

