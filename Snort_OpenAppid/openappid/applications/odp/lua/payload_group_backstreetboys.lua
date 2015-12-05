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
detection_name: Payload Group "backstreetboys"
version: 3
description: Group of payload detectors.
bundle_description: $VAR1 = {
          'goo.ne.jp' => 'Japanese web portal.',
          'w3schools.com' => 'A web development learning website.',
          'Viewsurf' => 'French video streaming and download site.',
          'Media6Degrees' => 'Advertisement site.',
          'Yabuka' => 'Advertisement site.',
          'Periscope' => 'Mobile app for live video streaming.',
          'Webtrends' => 'Advertisement site.',
          'GOMTV.com' => 'Korean sports-related website.',
          'Windows Live' => 'A collection of Microsoft\'s online services.',
          'Surikate' => 'Ad site.',
          '1000mercis' => 'Advertising and analytics site.',
          'Zanox' => 'Advertising and analytics site.',
          'Undertone' => 'Advertisement site.',
          'Wretch' => 'Taiwanese community website.',
          'wikidot' => 'Site that provides wikis.',
          'Multiupload' => 'Aggregator site for upload sites such as Megaupload, Filesonic, etc.',
          'BV! Media' => 'Advertisement site.',
          'Panda' => 'Panda Security Antivirus/Security software download and updates.',
          'Eset' => 'Eset Antivirus/Security software download and updates.',
          'Telecom Express' => 'Advertisement site.',
          'Windows Phone sites' => 'Windows phone related websites.',
          'Exponential Interactive' => 'Advertisement site.',
          'Vibrant' => 'Advertisement site.',
          'Uploading.com' => 'File transfer website.',
          'Google ads' => 'Google targeted advertising.',
          'VoiceFive' => 'Advertisement site.',
          'Adify' => 'Advertisement site.',
          'Freewheel' => 'Advertisement site.',
          'eXelate' => 'Advertisement site.',
          'Pando' => 'File upload and download helper.',
          'Ganji' => 'Chinese website for classified information.',
          'TubeMogul' => 'Advertisement site.',
          'McAfee' => 'McAfee Antivirus/Security softare download and updates.',
          'Dynamic Logic' => 'Advertisement site.',
          'Piksel' => 'Video streaming service.',
          'Ybrant Digital' => 'Advertisement site.',
          'Level 3' => 'Level 3 Communications content delivery network.',
          'Wordpress' => 'An online blogging community.',
          'VPNReactor' => 'An anonymizer that obfuscates web usage.',
          'The Trade Desk' => 'Advertisement site.',
          'XiTi' => 'Advertising and analytics site.',
          'iMesh' => 'A media and file sharing client with online social network features.',
          'Freelancer' => 'Site for job listings for temporary work.',
          'FriendFeed' => 'FriendFeed is a real-time feed aggregator from social media sites.',
          'The Internet Archive' => 'Internet content provider.',
          'TLVMedia' => 'Advertisement site.',
          'Forbes' => 'Website for Forbes, a business news magazine.',
          'Freee TV' => 'International television streaming.',
          'GOMTV.net' => 'International video game news from the GOM network.',
          'Federated Media' => 'Advertisement site.',
          'VIEWON' => 'Video ad site.',
          'L\'equipe.fr' => 'French sports news site.',
          'MSN2Go' => 'Third-party Windows Messaging service.',
          'Evidon' => 'Advertisement site.',
          'DC Storm' => 'Advertisement site.',
          'Wikispaces' => 'Wiki hosting site.',
          'LINE Games' => 'Games played using LINE.',
          'Weebly' => 'Free, online website creation tool.',
          'Filer.cx' => 'A file hosting service that provides free web space for documents, pictures, music and movies.',
          'Cedexis' => 'Advertising and analytics site.',
          'In.com' => 'Entertainment news and media.',
          'Media Innovation Group' => 'Advertisement site.',
          'Zol.com.cn' => 'Online website for IT professional.',
          'Adobe Analytics' => 'Traffic going to Adobe Analytics websites such as scene7.com, demdex.net, omtrdc.net, and 2o7.net.',
          'Glype Proxy' => 'Anonymous web proxy server.',
          'iTunes Radio' => 'Internet radio by Apple.',
          'X Plus One' => 'Advertisement site.',
          'Xaxis' => 'Advertisement site.',
          'Goal' => 'Football news and statistics.',
          'eNovance' => 'Advertisement site.',
          'Weborama' => 'Video ad site.',
          'Google Maps' => 'Google map and directions service.',
          'Ad4mat' => 'Ad site.',
          'Hao123.com' => 'Chinese website for personalized local news.',
          'Kaspersky' => 'Kaspersky Antivirus/Security software download and updates.',
          'Achetez Facile' => 'French online shopping site.',
          'Proxistore' => 'Advertising and analytics site.',
          'ContextWeb' => 'Advertisement site.',
          'Theme Forest' => 'An Envato marketplace for themes and skins.',
          'Xanga' => 'A website that hosts weblogs, photoblogs, and social networking profiles.',
          'Webs' => 'Photo, video, and file sharing, and online marketplace.',
          'eyeReturn' => 'Advertisement site.',
          'Ligatus' => 'Advertising and analytics site.',
          'Xbox Live sites' => 'XBox Live related websites.',
          'CyberGhost VPN' => 'An anonymizer that obfuscates web usage.',
          'Dotomi' => 'Advertisement site.',
          'Groupon' => 'Gift certificate website.',
          'Zoho' => 'A Web- based online office suite containing word processing, spreadsheets, presentations, databases, note-taking, wikis, CRM, project management, invoicing and other applications developed by ZOHO Corporation.',
          'Foursquare' => 'Location-based social networking.',
          'Channel 4' => 'British based streaming television.',
          'Y8' => 'Internet gaming website.',
          'KAT' => 'A torrent download site.',
          'BitDefender' => 'BitDefender Antivirus/Security software download and updates.',
          'Grooveshark' => 'Online music search engine and streaming service.'
        };

--]]

require "DetectorCommon"



local DC = DetectorCommon

DetectorPackageInfo = {
    name =  "payload_group_backstreetboys",
    proto =  DC.ipproto.tcp,
    client = {
        init =  'DetectorInit',
        clean =  'DetectorClean',
        minimum_matches =  1
    }
}

--serviceId, clientId, ClientType, PayloadId, PayloadType, hostPattern, pathPattern, schemePattern, queryPattern
gUrlPatternList = {
    -- Groupon
    { 0, 0, 0, 1699,22, "groupon.com", "/", "http:", "", 2361},
    { 0, 0, 0, 1699,22, "grouponcdn.com", "/", "http:", "", 2361},
    -- FriendFeed
    { 0, 0, 0, 1700,22, "friendfeed.com", "/", "http:", "", 164},
    -- Dynamic Logic
    { 0, 0, 0, 1701,16, "dynamiclogic.com", "/", "http:", "", 2580},
    -- Federated Media 
    { 0, 0, 0, 1702,16, "federatedmedia.net", "/", "http:", "", 2559},
    -- Foursquare
    { 0, 0, 0, 1703,5, "foursquare.com", "/", "http:", "", 2357},
    { 0, 0, 0, 1703,5, "4sqi.net", "/", "http:", "", 2357},
    -- Freelancer 
    { 0, 0, 0, 1704,22, "freelancer.com", "/", "http:", "", 2483},
    { 0, 0, 0, 1704,22, "freelancer.ca", "/", "http:", "", 2483},
    { 0, 0, 0, 1704,22, "freelancer.cl", "/", "http:", "", 2483},
    { 0, 0, 0, 1704,22, "freelancer.co.id", "/", "http:", "", 2483},
    { 0, 0, 0, 1704,22, "freelancer.co.nz", "/", "http:", "", 2483},
    { 0, 0, 0, 1704,22, "freelancer.co.uk", "/", "http:", "", 2483},
    { 0, 0, 0, 1704,22, "freelancer.co.za", "/", "http:", "", 2483},
    { 0, 0, 0, 1704,22, "freelancer.com.au", "/", "http:", "", 2483},
    { 0, 0, 0, 1704,22, "freelancer.com.bd", "/", "http:", "", 2483},
    { 0, 0, 0, 1704,22, "freelancer.com.es", "/", "http:", "", 2483},
    { 0, 0, 0, 1704,22, "freelancer.com.jm", "/", "http:", "", 2483},
    { 0, 0, 0, 1704,22, "freelancer.com.pe", "/", "http:", "", 2483},
    { 0, 0, 0, 1704,22, "freelancer.de", "/", "http:", "", 2483},
    { 0, 0, 0, 1704,22, "f-cdn.com", "/", "http:", "", 2483},
    { 0, 0, 0, 1704,22, "freelancer.ec", "/", "http:", "", 2483},
    -- Grooveshark
    { 0, 0, 0, 1705,13, "grooveshark.com", "/", "http:", "", 941},
    { 0, 0, 0, 1705,13, "grooveshark.im", "/", "http:", "", 941},
    -- Hao123.com  
    { 0, 0, 0, 1706,22, "hao123.com", "/", "http:", "", 2855},
    { 0, 0, 0, 1706,22, "hao123img.com", "/", "http:", "", 2855},
    { 0, 0, 0, 1706,22, "imgshao123.com", "/", "http:", "", 2855},    
    --MSN2Go
    { 0, 0, 0, 1707,10, "msn2go.com", "/", "http:", "", 1221},
    --Multiupload
    { 0, 0, 0, 1708,22, "multiupload.com", "/", "http:", "", 1220},
    { 0, 0, 0, 1708,22, "multiupload.nl", "/", "http:", "", 1220},
    --L'equipe.fr
    { 0, 0, 0, 1709,22, "lequipe.fr", "/", "http:", "", 3711},
    { 0, 0, 0, 1709,22, "lequipe21.fr", "/", "http:", "", 3711},
    { 0, 0, 0, 1709,22, "lequipemagazine.fr", "/", "http:", "", 3711},
    { 0, 0, 0, 1709,22, "sportetstyle.fr", "/", "http:", "", 3711},
    { 0, 0, 0, 1709,22, "sportetstyle.wui.fr", "/", "http:", "", 3711},
    { 0, 0, 0, 1709,22, "logc215.xiti.com", "/", "http:", "", 3711},
    --KAT
    { 0, 0, 0, 1710,22, "kat.ph", "/", "http:", "", 1218},
    { 0, 0, 0, 1710,22, "kastatic.com", "/", "http:", "", 1218},
    { 0, 0, 0, 1710,22, "kat.cr", "/", "http:", "", 1218},
    --wikidot
    { 0, 0, 0, 1711,22, "wikidot.com", "/", "http:", "", 2352},
    { 0, 0, 0, 1711,22, "wdfiles.com", "/", "http:", "", 2352},
    --w3schools.com
    { 0, 0, 0, 1712,22, "w3schools.com", "/", "http:", "", 1180},
    --Ybrant Digital
    { 0, 0, 0, 1713,22, "ybrantdigital.com", "/", "http:", "", 2546},
    { 0, 0, 0, 1713,22, " lycos.com", "/", "http:", "", 2546},
    { 0, 0, 0, 1713,22, "lygo.com", "/", "http:", "", 2546},
    { 0, 0, 0, 1713,22, "ybrantmobile.com", "/", "http:", "", 2546},
    { 0, 0, 0, 1713,22, "positivemobileapps.com", "/", "http:", "", 2546},
    { 0, 0, 0, 1713,22, "maxinteractive.com.au", "/", "http:", "", 2546},
    { 0, 0, 0, 1713,22, "www.volomp.com", "/", "http:", "", 2546},
    --Wretch
    { 0, 0, 0, 1714,22, "wretch.cc", "/", "http:", "", 1262},
    --Xanga
    { 0, 0, 0, 1715,22, "xanga.com", "/", "http:", "", 510},
    --Weebly
    { 0, 0, 0, 1716,22, "weebly.com", "/", "http:", "", 1181},
    { 0, 0, 0, 1716,22, "weeblyimages1.com", "/", "http:", "", 1181},
    --Zoho
    { 0, 0, 0, 1717,22, "zoho.com", "/", "http:", "", 528},
    { 0, 0, 0, 1717,22, "zohostatic.com", "/", "http:", "", 528},
    --Wordpress
    { 0, 0, 0, 1718,22, "wordpress.com", "/", "http:", "", 506},
    { 0, 0, 0, 1718,22, "wordpress.org", "/", "http:", "", 506},
    { 0, 0, 0, 1718,22, "wp.com", "/", "http:", "", 506},
    --Filer.cx
    { 0, 0, 0, 1719,22, "filer.cx", "/", "http:", "", 156},
    --goo.ne.jp
    { 0, 0, 0, 1720,22, "goo.ne.jp", "/", "http:", "", 1216},
    --ContextWeb
    { 0, 0, 0, 1721,22, "contextweb.com", "/", "http:", "", 2571},
    --Dotomi
    { 0, 0, 0, 1722,22, "dotomi.com", "/", "http:", "", 2515},
    --eyeReturn
    { 0, 0, 0, 1723,22, "eyeReturn.com", "/", "http:", "", 2526},
    { 0, 0, 0, 1723,22, "eyereturnmarketing.com", "/", "http:", "", 2526},
    --Ganji
    { 0, 0, 0, 1724,22, "ganji.com", "/", "http:", "", 2854},
    { 0, 0, 0, 1724,22, "ganjistatic1.com", "/", "http:", "", 2854},    
    --TubeMogul
    { 0, 0, 0, 1725,22, "tubemogul.com", "/", "http:", "", 2534},  
    --Yabuka
    { 0, 0, 0, 1726,22, "yabuka.com", "/", "http:", "", 2545},
    --Y8
    { 0, 0, 0, 1727,22, "y8.com", "/", "http:", "", 1263},
    --Webs
    { 0, 0, 0, 1728,22, "webs.com", "/", "http:", "", 1228},
    { 0, 0, 0, 1728,22, "freewebs.com", "/", "http:", "", 1228},
    { 0, 0, 0, 1728,22, "websimages.com", "/", "http:", "", 1228},
    --The Internet Archive
    { 0, 0, 0, 1729,22, "archive.org", "/", "http:", "", 2358},
    --Uploading.com
    { 0, 0, 0, 1730,22, "uploading.com", "/", "http:", "", 2366},
    --VoiceFive
    { 0, 0, 0, 1731,22, "VoiceFive.com", "/", "http:", "", 2584},
    { 0, 0, 0, 1731,22, "voicefive.com", "/", "http:", "", 2584},
    --Vibrant
    { 0, 0, 0, 1732,22, "vibrantmedia.com", "/", "http:", "", 2519},
    --TLVMedia
    { 0, 0, 0, 1733,22, "tlvmedia.com", "/", "http:", "", 2536},
    --Media6Degrees
    { 0, 0, 0, 1734,22, "media6degrees.com", "/", "http:", "", 2522},
    --eXelate
    { 0, 0, 0, 1735,22, "exelator.com", "/", "http:", "", 2517},
    { 0, 0, 0, 1735,22, "exelate.com", "/", "http:", "", 2517},
    --Evidon
    { 0, 0, 0, 1736,22, "evidon.com", "/", "http:", "", 2510},
    --Wikispaces
    { 0, 0, 0, 1737,22, "wikispaces.com", "/", "http:", "", 2488},
    { 0, 0, 0, 1737,22, "wikicdn.com", "/", "http:", "", 2488},
    { 0, 0, 0, 1737,22, "wikispaces.net", "/", "http:", "", 2488},
    --Undertone
    { 0, 0, 0, 1738,22, "undertone.com", "/", "http:", "", 2583},
    --Webtrends
    { 0, 0, 0, 1739,22, "webtrends.com", "/", "http:", "", 2587},
    { 0, 0, 0, 1739,22, "webtrendslive.com", "/", "http:", "", 2587},
    --Adify
    { 0, 0, 0, 1740,22, "adify.com", "/", "http:", "", 2570},
    --Xaxis
    { 0, 0, 0, 1741,22, "xaxis.com", "/", "http:", "", 2541},
    --Freewheel
    { 0, 0, 0, 1742,22, "freewheel.tv", "/", "http:", "", 2574},
    --Piksel
    { 0, 0, 0, 1743,13, "piksel.com", "/", "http:", "", 3716},
    { 0, 0, 0, 1743,13, "kitd.com", "/", "http:", "", 3716},
    --Level 3
    { 0, 0, 0, 1744,22, "level3.com", "/", "http:", "", 3805},
    --X Plus One
    { 0, 0, 0, 1745,22, "xplusone.com", "/", "http:", "", 2549},
    --BV! Media
    { 0, 0, 0, 1746,22, "bvmediasolutions.com", "/", "http:", "", 2576},
    { 0, 0, 0, 1746,22, "bvmedia.it", "/", "http:", "", 2576},
    --DC Storm
    { 0, 0, 0, 1747,22, "dc-storm.com", "/", "http:", "", 2589},
    --Cedexis
    { 0, 0, 0, 1748,22, "cedexis.com", "/", "http:", "", 3705},
    { 0, 0, 0, 1748,22, "cedexis-radar.net", "/", "http:", "", 3705},
    --Ligatus
    { 0, 0, 0, 1749,22, "ligatus.com", "/", "http:", "", 3712},
    { 0, 0, 0, 1749,22, "ligatus.ch", "/", "http:", "", 3712},
    { 0, 0, 0, 1749,22, "ligatus.at", "/", "http:", "", 3712},
    { 0, 0, 0, 1749,22, "ligatus.es", "/", "http:", "", 3712},
    { 0, 0, 0, 1749,22, "ligatus.be", "/", "http:", "", 3712},
    { 0, 0, 0, 1749,22, "ligatus.nl", "/", "http:", "", 3712},
    { 0, 0, 0, 1749,22, "ligatus.it", "/", "http:", "", 3712},
    { 0, 0, 0, 1749,22, "ligatus.fr", "/", "http:", "", 3712},
    { 0, 0, 0, 1749,22, "ligatus.de", "/", "http:", "", 3712},
    --VIEWON
    { 0, 0, 0, 1750,22, "viewon.fr", "/", "http:", "", 3721},
    { 0, 0, 0, 1750,22, "viewontv.com", "/", "http:", "", 3721},
    --Ad4mat
    { 0, 0, 0, 1751,22, "ad4mat.com", "/", "http:", "", 3702},
    { 0, 0, 0, 1751,22, "ad4mat.net", "/", "http:", "", 3702},
    { 0, 0, 0, 1751,22, "ad4mat.de", "/", "http:", "", 3702},
    --Surikate
    { 0, 0, 0, 1752,22, "surikate.com", "/", "http:", "", 3719},
    --eNovance
    { 0, 0, 0, 1753,22, "enovance.com", "/", "http:", "", 2567},
    --Zanox
    { 0, 0, 0, 1754,22, "zanox.com", "/", "http:", "", 3725},
    --XiTi
    { 0, 0, 0, 1755,22, "xiti.com", "/", "http:", "", 3724},
    { 0, 0, 0, 1755,22, "atinternet.com", "/", "http:", "", 3724},
    --Exponential Interactive
    { 0, 0, 0, 1756,22, "exponential.com", "/", "http:", "", 2518},
    --Weborama
    { 0, 0, 0, 1757,22, "weborama.com", "/", "http:", "", 3723},
    { 0, 0, 0, 1757,22, "weborama.fr", "/", "http:", "", 3723},
    --Forbes
    { 0, 0, 0, 1758,22, "forbes.com", "/", "http:", "", 2347},
    { 0, 0, 0, 1758,22, "forbesimg.com", "/", "http:", "", 2347},
    { 0, 0, 0, 1758,22, "forbes.servedbyopenx.com", "/", "http:", "", 2347},
    --Telecom Express
    { 0, 0, 0, 1759,22, "www.telecomexpress.co.uk", "/", "http:", "", 2588},
    --Media Innovation Group
    { 0, 0, 0, 1760,22, "themig.com", "/", "http:", "", 2523},
    --Viewsurf
    { 0, 0, 0, 1761,22, "viewsurf.com", "/", "http:", "", 3722},
    --The Trade Desk
    { 0, 0, 0, 1762,22, "thetradedesk.com", "/", "http:", "", 2499},
    --Achetez Facile
    { 0, 0, 0, 1763,22, "achetezfacile.com", "/", "http:", "", 3701},
    --1000mercis
    { 0, 0, 0, 1764,22, "1000mercis.com", "/", "http:", "", 3715},
    --Proxistore
    { 0, 0, 0, 1765,22, "proxistore.com", "/", "http:", "", 3717},
    --Freee TV
    { 0, 0, 0, 1766,22, "freeetv.com", "/", "http:", "", 2348},
    --Theme Forest
    { 0, 0, 0, 1767,22, "themeforest.net", "/", "http:", "", 1227},
    --Google ads
    { 0, 0, 0, 1768,22, "googleadservices.com", "/", "http:", "", 2403},
    --Goal
    { 0, 0, 0, 1769,22, "goal.com", "/", "http:", "", 2484},
    --Channel 4
    { 0, 0, 0, 1770,22, "c4assets.com", "/", "http:", "", 3811},
    { 0, 0, 0, 1770,22, "channel4.com", "/", "http:", "", 3811},    
    --Xbox Live sites
    { 0, 0, 0, 1771,22, "xbox.com", "/", "http:", "", 2626},
    --Windows Phone sites
    { 0, 0, 0, 1772,22, "windowsphone.com", "/", "http:", "", 2627},
    --Periscope
    { 0, 0, 0, 1691,22, "periscope.tv", "/", "http:", "", 3992},
    --iTunes Radio 
    { 0, 0, 0, 1190,22, "itsliveradiobackup.apple.com", "/", "http:", "", 2669},
    { 0, 0, 0, 1190,22, "itsliveradio.apple.com", "/", "http:", "", 2669},
    --McAfee
    { 0, 0, 0, 1773, 13, "mcafee.com", "/", "http:", "", 280},
    { 0, 0, 0, 1773, 13, "mcafee12.tt.omtrdc.net", "/", "http:", "", 280},
    --Eset
    { 0, 0, 0, 1774, 13, "eset.eu", "/", "http:", "", 143},
    { 0, 0, 0, 1774, 13, "eset.sk", "/", "http:", "", 143},
    { 0, 0, 0, 1774, 13, "eset.com", "/", "http:", "", 143},
    --BitDefender
    { 0, 0, 0, 1775, 13, "bitdefender.com","/", "http:", "", 59},
    --Panda
    { 0, 0, 0, 1776, 13, "pandasecurity.com","/", "http:", "", 359},
    { 0, 0, 0, 1776, 13, "pandasoftware.com","/", "http:", "", 359},
    { 0, 0, 0, 1776, 13, "panda.ctmail.com","/", "http:", "", 359},
    --LINE Games
    { 0, 0, 0, 1777, 5, "dl.appresource.line.naver.jp","/", "http:", "", 3713},
    { 0, 0, 0, 1777, 5, "linegame.jp","/", "http:", "", 3713},
    { 0, 0, 0, 1777, 5, "game.line.naver.jp","/", "http:", "", 3713},
    { 0, 0, 0, 1777, 5, "linegame.jp:10080","/", "http:", "", 3713},
    { 0, 0, 0, 1777, 5, "linegame.jp:10010","/", "http:", "", 3713},
    { 0, 0, 0, 1777, 5, "line-apps.com","lg/LGRANGERS/", "http:", "", 3713},
    { 0, 0, 0, 1777, 5, "line.me","v1/LGCHASER/", "http:", "", 3713},
    { 0, 0, 0, 1777, 5, "line-apps.com","hsp/LGCAR/", "http:", "", 3713},
    --Kaspersky
    { 0, 0, 0, 1778, 13, "kaspersky.com","/", "http:", "", 248},
    { 0, 0, 0, 1778, 13, "kaspersky.122.2o7.net","/", "http:", "", 248},
    --Pando
    { 0, 0, 0, 1779, 9, "pando.com","/", "http:", "", 957},
    --Google Maps
    { 0, 0, 0, 1780, 22, "maps.google.com","/", "http:", "", 1183},
    --Glype Proxy
    { 0, 0, 0, 1781, 46, "glypeproxy.com","/", "http:", "", 1215},
    --Windows Live
    { 0, 0, 0, 1782, 22, "msn.com","/", "http:", "", 502},
    { 0, 0, 0, 1782, 22, "live.com","/", "http:", "", 502},
    --In.com
    { 0, 0, 0, 1784, 22, "in.com", "/", "http:", "", 2372},
    --CyberGhost VPN
    { 0, 0, 0, 1785, 46, "cyberghostvpn.com", "/", "http:", "", 3653},
    --Adobe Analytics 
    { 0, 0, 0, 1786, 22, "207.net", "/", "http:", "", 2846},
    { 0, 0, 0, 1786, 22, "omniture.com", "/", "http:", "", 2846},
    { 0, 0, 0, 1786, 22, "adobe.tt.omtrdc.net", "/", "http:", "", 2846},
    { 0, 0, 0, 1786, 22, "demdex.net", "/", "http:", "", 2846},
    { 0, 0, 0, 1786, 22, "demdex.com", "/", "http:", "", 2846},
    { 0, 0, 0, 1786, 22, "adobetag.com", "/", "http:", "", 2846},
    --iMesh
    { 0, 0, 0, 1787, 9, "imesh.com", "/", "http:", "", 944},
    --Zol.com.cn
    { 0, 0, 0, 1788, 22, "zol.com.cn", "/", "http:", "", 2866},
    { 0, 0, 0, 1788, 22, "zol-img.com.cn", "/", "http:", "", 2866}, 
   --VPNReactor
    { 0, 0, 0, 1789, 46, "vprsecure.com", "/", "http:", "", 3652},
    { 0, 0, 0, 1789, 46, "vprupdate.com", "/", "http:", "", 3652},
    { 0, 0, 0, 1789, 46, "vpnreactor.com", "/", "http:", "", 3652},
    { 0, 0, 0, 1789, 46, "vpnreactorsupport.com", "/", "http:", "", 3652},
    { 0, 0, 0, 1789, 46, "vprdownload.com", "/", "http:", "", 3652},
    --GOMTV.com
    { 0, 0, 0, 1790, 22, "gomtv.com", "/", "http:", "", 2640},
    { 0, 0, 0, 1790, 22, "gomtv.co.kr", "/", "http:", "", 2640},
    --GOMTV.net
    { 0, 0, 0, 1791, 22, "gomtv.net", "/", "http:", "", 2639},
   }

function DetectorInit(detectorInstance)

    gDetector = detectorInstance;
 
    -- McAfee
    gDetector:addHttpPattern(2, 5, 0, 489, 25, 0, 0, 'McAfee', 280, 1);
    gDetector:addHttpPattern(2, 5, 0, 489, 25, 0, 0, 'McHttp', 280, 1); 
    -- Eset
    gDetector:addHttpPattern(2, 5, 0, 490, 25, 0, 0, 'ESS Update', 143, 1);
    -- Goal     
    gDetector:addHttpPattern(2, 5, 0, 491, 25, 0, 0, 'Goal', 2484, 1);
    -- Panda
    gDetector:addHttpPattern(2, 5, 0, 494, 25, 0, 0, 'Panda IS', 359, 1);
    gDetector:addHttpPattern(2, 5, 0, 494, 25, 0, 0, 'Panda Software', 359, 1); 
    -- LINE Games
    gDetector:addHttpPattern(2, 5, 0, 495, 25, 0, 0, 'DashGirl', 3713, 1);
    gDetector:addHttpPattern(2, 5, 0, 495, 25, 0, 0, 'LineLetsGolf', 3713, 1);
    gDetector:addHttpPattern(2, 5, 0, 495, 25, 0, 0, 'HB_BURST', 3713, 1);
    gDetector:addHttpPattern(2, 5, 0, 495, 25, 0, 0, 'HiddenCatch', 3713, 1);
    gDetector:addHttpPattern(2, 5, 0, 495, 25, 0, 0, 'SJLGCOFEE', 3713, 1);
    gDetector:addHttpPattern(2, 5, 0, 495, 25, 0, 0, 'LineFishingMaster', 3713, 1);
    gDetector:addHttpPattern(2, 5, 0, 495, 25, 0, 0, 'NinjaStriker', 3713, 1);
    gDetector:addHttpPattern(2, 5, 0, 495, 25, 0, 0, 'paku', 3713, 1);
    gDetector:addHttpPattern(2, 5, 0, 495, 25, 0, 0, 'androidapp.lineplay', 3713, 1);
    gDetector:addHttpPattern(2, 5, 0, 495, 25, 0, 0, 'LINEPONG', 3713, 1);
    gDetector:addHttpPattern(2, 5, 0, 495, 25, 0, 0, 'LINE%20Rangers', 3713, 1);
    gDetector:addHttpPattern(2, 5, 0, 495, 25, 0, 0, 'ZOOKEEPER%20LINE', 3713, 1);
    gDetector:addHttpPattern(2, 5, 0, 495, 25, 0, 0, 'LINE', 3713, 1);
    --GOMTV.com
    gDetector:addHttpPattern(2, 5, 0, 496, 25, 0, 0, 'GOM', 2640, 1);
    if gDetector.addAppUrl then
        for i,v in ipairs(gUrlPatternList) do
            gDetector:addAppUrl(v[1],v[2],v[3],v[4],v[5],v[6],v[7],v[8],v[9],v[10]);
        end
    end
    return gDetector;
end

function DetectorClean()

end
