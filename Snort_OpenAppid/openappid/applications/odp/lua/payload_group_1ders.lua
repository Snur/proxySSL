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
detection_name: Payload Group "1derss"
version: 7
description: Group of payload detectors.
bundle_description: $VAR1 = {
          'Pinger' => 'Allows SMS text messaging via a data connection.',
          'Nexage' => 'Advertisement site.',
          'ShowMyPC' => 'Cloud-based remote support and desktop sharing.',
          'Nielsen' => 'Global information and measurement company.',
          'QDown' => 'Korean Entertainment web portal.',
          'SpotXchange' => 'Advertisement site.',
          'Krux' => 'Cloud-based online marketing and monetization service.',
          'Mgoon' => 'Korean Entertainment web portal.',
          'Plaxo' => 'An online address book and social networking service that provides automatic updating of contact information.',
          'IBM' => 'Website for IBM.',
          'TeamViewer' => 'Remote desktop control and file transfer software.',
          'Sogou' => 'Chinese web portal.',
          'PPStream' => 'Chinese video streaming software.',
          'Olive Media' => 'Advertisement site.',
          'Enet' => 'Web portal for Chinese-speaking IT workers.',
          'Motrixi' => 'Advertisement site.',
          'Meta5' => 'Business analytic software. Allows users to create reports that can access multiple corporate data sources. Registered with IANA on port 393 tcp/udp.',
          'InSkin Media' => 'Advertisement site.',
          'TechInline' => 'Website that offers remote desktop control.',
          'Sourceforge' => 'Site for sharing open source software projects.',
          'Infonline' => 'Malware-generated online advertisements.',
          'Integral Ad Science' => 'Advertisement site.',
          'Delta Search' => 'A search engine, with a toolbar that is commonly installed by mistake.',
          'Nugg' => 'Advertisement site.',
          'Rubicon Project' => 'Online advertising infrastructure company.',
          'HowardForums' => 'Cellular phone forums.',
          'Neustar Information Services' => 'Advertisement site.',
          'MyBuys' => 'Advertisement site.',
          'Rambler' => 'Russian search engine.',
          'Softonic' => 'Software download site.',
          'SBS' => 'Korean Online TV shows and Movies.',
          'Google Hangouts' => 'Google cross-platform messenger application.',
          'Woolik' => 'Analytics and search engine boosting.',
          'MUZU TV' => 'Music video site.',
          'Doof' => 'Online gaming site.',
          'Apple Maps' => 'Apple maps and navigation.',
          'LA Times' => 'News site for the west coast newspaper.',
          'Soku' => 'Youku\'s search engine.',
          'Mercado Livre' => 'Brazil online auction and shopping website.',
          'Open Webmail' => 'Webmail service.',
          'Komli Media' => 'Online marketing and advertising.',
          'PDBox' => 'Korean file-sharing site.',
          'Hupu' => 'Sports news website.',
          'Marca' => 'Primarily Spanish video streaming site.',
          'Polldaddy' => 'Advertisement site.',
          'Quake Live' => 'Online video game by id Software.',
          'Hotspot Shield' => 'Anonymizer and tunnel that encrypts communications.',
          'comScore' => 'Digital business analytics.',
          'engage BDR' => 'Advertisement site.',
          'NetSeer' => 'Advertisement site.',
          'Meetup' => 'Social networking website.',
          'MissLee' => 'Korean Instant Messenger.',
          'ListProc' => 'ListProcessor, mailing list management software.',
          'Squidoo' => 'Social blogging site.',
          'Smart AdServer' => 'Advertisement site.',
          'iPerceptions' => 'Online marketing analysis provider.',
          'Alipay' => 'Online payment service.',
          'Luminate' => 'Advertisement site.',
          'Last.fm' => 'A social networking music streaming site.',
          'Leboncoin' => 'Auction and classified seller website.',
          'East Money' => 'Chinese financial news portal.',
          'Softpedia' => 'Software download site.',
          'SlideShare' => 'A web-based slide show service.',
          'MLN Advertising' => 'Managing/Organising advertisements and its content delivery.',
          'TowerData' => 'Formerly RapLeaf, an advertisement site.',
          'Mixpanel' => 'Advertisement site.',
          'Telemetry' => 'Advertisement site.',
          'Resonate Networks' => 'Advertisement site.',
          'NovaBACKUP' => 'NovaStor develops and markets data protection and availability software. NovaBACKUP offers support for multi-OS environments and is capable of handling thousands of servers and petabytes of information.',
          'Rocket Fuel' => 'Advertisement site.',
          'news.com.au' => 'News site based in Australia.',
          'Drawbridge' => 'Advertisement site.',
          'Ohana' => 'Advertisement site.',
          'SVN' => 'Managing Subversion servers.',
          'Effective Measure' => 'Advertisement site.',
          'Scorecard Research' => 'Online marketing research community.',
          'Line2' => 'Mobile VoIP application with support for text messaging.',
          'LeadBolt' => 'Advertisement site.',
          'iStock' => 'Online royalty-free stock images.',
          'LiveRail' => 'Advertisement site.',
          'MyWebSearch' => 'Web portal.',
          'Google Helpouts' => 'A social networking and instant messaging system for expert advice on various topics.',
          'SendSpace' => 'File sharing and hosting.',
          'SuperNews' => 'A Usenet/newsgroup service provider.',
          'MediaV' => 'Advertisement site.',
          'Mozilla' => 'Website for many open source software projects, including the Firefox browser.',
          'MdotM' => 'Advertisement site.',
          'RadiumOne' => 'Advertisement site.',
          'Tango' => 'Mobile social networking app that provides voice, chat, and gaming services.',
          'MediaMath' => 'Advertising and business analytics.',
          'Lotame' => 'Online advertising and marketing research platform.',
          'LogMeIn' => 'Remote access and PC desktop control.',
          'OpenX' => 'Closed advertising platform.',
          'Optimizely' => 'Advertisement site.',
          'Letitbit' => 'File hosting and sharing website.',
          'SPC Media' => 'New media production company.',
          'Mojiva' => 'Advertisement site.',
          'Mop.com' => 'Chinese webportal acting as bulletin board for pop culture, games and other entertainments.',
          'Pchome' => 'Computer and electronics retailer.',
          'OpenCandy' => 'Advertising and marketing.',
          'DomainTools' => 'A domain name registrar.',
          'Adenin' => 'A web portal.',
          'Quote.com' => 'Financial research and trading website.',
          'EQ Ads' => 'Advertisement site.',
          'Ifeng.com' => 'Chinese webportal from Phoenix New media.',
          'Bootstrap CDN' => 'Free and public content delivery network.',
          'ShareThis' => 'Social advertising widgets.',
          'iCall' => 'Free voice, video chat, and text messaging app.',
          'Mobile Theory' => 'Advertisement site.',
          'SurveyMonkey' => 'A site for distributing surveys.',
          'SiteScout' => 'Company targetting powerful and easy-to-use tech for real-time ads.',
          'SLI Systems' => 'Advertisement site.',
          'QQ' => 'Chinese instant messaging software.',
          'Soso' => 'Chinese search engine.',
          'Image Venue' => 'Free image hosting site.',
          'Netease' => 'Chinese web portal.',
          'HubPages' => 'Social blogging site.',
          'Netfolder.in' => 'Free online file sharing.',
          'SopCast' => 'P2P audio and video streaming.',
          'Match.com' => 'Dating website.',
          'Kooora.com' => 'Webportal for Sports related news.',
          'Etao' => 'Chinese web portal.',
          'it168' => 'Chinese social media website.',
          'Skimlinks' => 'Advertisement site.',
          'Apple Update' => 'Apple software updating tool.',
          'Silverpop' => 'Email marketing service.',
          'Monetate' => 'Advertisement site.',
          'Online File Folder' => 'Cloud-based file storage.',
          'MaxPoint Interactive' => 'Advertisement site.',
          'Envato' => 'Combined software education and marketplace site.',
          'MelOn' => 'Korean music site.',
          'TechCrunch' => 'IT related news and research site.',
          'Improve Digital' => 'European sell side online ad service.',
          'PPTV' => 'Chinese file-streaming app.',
          'eBay' => 'An online auction and shopping website.',
          'Naverisk' => 'Cloud-based remote monitoring and management software.',
          'ICQ' => 'Internet chat client.',
          'Crittercism' => 'Mobile application monitor.',
          'Microsoft Store' => 'Online retailer for Microsoft products.',
          'Six Apart' => 'Advertisement site.',
          'RichRelevance' => 'Targeted advertising platform.',
          'Proclivity' => 'Advertisement site.',
          'TeacherTube' => 'Educational video streaming.',
          'Hopster' => 'A couponing site.',
          'LINE' => 'Instant Messaging.',
          'IKEA.com' => 'Online storefront for international furniture retailer.',
          'Telly' => 'Video sharing and streaming site.',
          'Quantcast' => 'Site for buying and selling target audiences.',
          'Motley Fool' => 'Financial and Investment community.',
          'Raging Bull' => 'Financial message board.'
        };

--]]

require "DetectorCommon"


local DC = DetectorCommon

DetectorPackageInfo = {
    name =  "payload_group_1ders",
    proto =  DC.ipproto.tcp,
    client = {
        init =  'DetectorInit',
        clean =  'DetectorClean',
        minimum_matches =  1
    }
}

gUrlPatternList = {
    -- Neustar Information Services
    { 0, 0, 0, 1491, 22, "neustar.biz", "/", "http:", "", 2537},
    { 0, 0, 0, 1491, 22, "neustar.com", "/", "http:", "", 2537},
    { 0, 0, 0, 1491, 22, "neustarlife.biz", "/", "http:", "", 2537},
    { 0, 0, 0, 1491, 22, "neustarsummit.biz", "/", "http:", "", 2537},
    { 0, 0, 0, 1491, 22, "neustarlocaleze.biz", "/", "http:", "", 2537},
    { 0, 0, 0, 1491, 22, "neustarlocaleze.com", "/", "http:", "", 2537},
    { 0, 0, 0, 1491, 22, "ultradns.com", "/", "http:", "", 2537},
    { 0, 0, 0, 1491, 22, "webmetrics.com", "/", "http:", "", 2537},
    { 0, 0, 0, 1491, 22, "tcpacompliance.us", "/", "http:", "", 2537},
    { 0, 0, 0, 1491, 22, "tcpacompliance.com", "/", "http:", "", 2537},
    { 0, 0, 0, 1491, 22, "npac.com", "/", "http:", "", 2537},
    -- Crittercism
    { 0, 0, 0, 1492, 15, "crittercism.com", "/", "http:", "", 3656},
    -- Delta Search
    { 0, 0, 0, 1493, 22, "delta-search.com", "/", "http:", "", 3657},
    { 0, 0, 0, 1493, 22, "royal-search.com", "/", "http:", "", 3657},
    -- MelOn
    { 0, 0, 0, 1494, 15, "melon.com", "/", "http:", "", 3659},
    -- Microsoft Store
    { 0, 0, 0, 1495, 15, "microsoftstore.com", "/", "http:", "", 3670},
    -- news.com.au
    { 0, 0, 0, 1496, 33, "news.com.au", "/", "http:", "", 3671},
    -- OpenCandy
    { 0, 0, 0, 1497, 22, "opencandy.com", "/", "http:", "", 3672},
    -- Soso
    { 0, 0, 0, 1498, 22, "soso.com", "/", "http:", "", 3673},
    -- Woolik
    { 0, 0, 0, 1499, 22, "woolik.com", "/", "http:", "", 3674},
    -- Last.fm
    { 0, 0, 0, 1500, 22, "last.fm", "/", "http:", "", 261},
    -- Hopster
    { 0, 0, 0, 1501, 22, "hopster.com", "/", "http:", "", 202},
    -- Hotspot Shield
    { 0, 0, 0, 1502, 22, "hotspotshield.com", "/", "http:", "", 1140},
    { 0, 0, 0, 1502, 22, "hsselite.com", "/", "http:", "", 1140},
    -- HowardForums
    { 0, 0, 0, 1503, 22, "howardforums.com", "/", "http:", "", 2598},
    -- HubPages
    { 0, 0, 0, 1504, 22, "hubpages.com", "/", "http:", "", 2485},
    -- Hupu
    { 0, 0, 0, 1505, 22, "hupu.com", "/", "http:", "", 2356},
    -- IBM
    { 0, 0, 0, 1506, 22, "ibm.com", "/", "http:", "", 1173},
    -- iCall
    { 0, 0, 0, 1507, 22, "icall.com", "/", "http:", "", 2401},
    -- ICQ
    { 0, 0, 0, 1508, 22, "icq.com", "/", "http:", "", 679},
    -- Ifeng.com
    { 0, 0, 0, 1509, 22, "ifeng.com", "/", "http:", "", 2856},
    -- IKEA.com
    { 0, 0, 0, 1510, 22, "ikea.com", "/", "http:", "", 2349},
    { 0, 0, 0, 1510, 22, "ikea.us", "/", "http:", "", 2349},
    { 0, 0, 0, 1510, 22, "ikea-usa.com", "/", "http:", "", 2349},
    { 0, 0, 0, 1510, 22, "ikea.is", "/", "http:", "", 2349},
    -- Image Venue
    { 0, 0, 0, 1511, 22, "imagevenue.com", "/", "http:", "", 1217},
    -- Improve Digital
    { 0, 0, 0, 1512, 22, "improvedigital.com", "/", "http:", "", 2451},
    { 0, 0, 0, 1512, 22, "360yield.com", "/", "http:", "", 2451},
    -- Infonline
    { 0, 0, 0, 1514, 22, "infonline.de", "/", "http:", "", 2461},
    -- InSkin Media
    { 0, 0, 0, 1515, 22, "inskinmedia.com", "/", "http:", "", 2527},
    { 0, 0, 0, 1515, 22, "inskinad.com", "/", "http:", "", 2527},
    -- Integral Ad Science
    { 0, 0, 0, 1516, 22, "integralads.com", "/", "http:", "", 2532},
    -- iPerceptions
    { 0, 0, 0, 1517, 22, "iperceptions.com", "/", "http:", "", 2455},
    -- iStock
    { 0, 0, 0, 1518, 22, "istockphoto.com", "/", "http:", "", 2858},
    -- it168
    { 0, 0, 0, 1519, 22, "it168.com", "/", "http:", "", 2373},
    -- Komli Media
    { 0, 0, 0, 1520, 22, "komli.com", "/", "http:", "", 2463},
    -- Kooora.com
    { 0, 0, 0, 1521, 22, "kooora.com", "/", "http:", "", 2859},
    -- Krux
    { 0, 0, 0, 1522, 22, "krux.com", "/", "http:", "", 2466},
    -- LA Times
    { 0, 0, 0, 1523, 22, "latimes.com", "/", "http:", "", 2609},
    -- LeadBolt
    { 0, 0, 0, 1524, 22, "leadbolt.com", "/", "http:", "", 2505},
    -- Leboncoin
    { 0, 0, 0, 1525, 22, "leboncoin.fr", "/", "http:", "", 1219},
    -- Alipay
    { 0, 0, 0, 1526, 39, "alipay.com", "/", "http:", "", 3655},
    -- Letitbit
    { 0, 0, 0, 1527, 9, "letitbit.net", "/", "http:", "", 2374},
    -- LINE
    { 0, 0, 0, 1528, 10, "line.me", "/", "http:", "", 1667},
    -- Line2
    { 0, 0, 0, 1529, 10, "line2.com", "/", "http:", "", 1149},
    -- ListProc
    { 0, 0, 0, 1530, 4, "listproc.sourceforge.net", "/", "http:", "", 481},
    -- LiveRail
    { 0, 0, 0, 1531, 22, "liverail.com", "/", "http:", "", 2520},
    -- LogMeIn
    { 0, 0, 0, 1532, 22, "logmein.com", "/", "http:", "", 270},
    -- Lotame
    { 0, 0, 0, 1533, 22, "lotame.com", "/", "http:", "", 2465},
    -- Luminate, Inc.
    { 0, 0, 0, 1534, 22, "luminate.com", "/", "http:", "", 2521},
    -- Marca
    { 0, 0, 0, 1535, 1, "marca.com", "/", "http:", "", 2486},
    { 0, 0, 0, 1535, 1, "marca.es", "/", "http:", "", 2486},
    -- Match.com
    { 0, 0, 0, 1536, 8, "match.com", "/", "http:", "", 2363},
    -- MaxPoint Interactive
    { 0, 0, 0, 1537, 22, "maxpoint.com", "/", "http:", "", 2561},
    { 0, 0, 0, 1537, 22, "maxpoint-express.com", "/", "http:", "", 2561},
    -- MdotM
    { 0, 0, 0, 1538, 22, "mdotm.com", "/", "http:", "", 2595},
    -- MediaMath
    { 0, 0, 0, 1539, 16, "mediamath.com", "/", "http:", "", 2416},
    -- DomainTools
    { 0, 0, 0, 1540, 22, "domaintools.com", "/", "http:", "", 1172},
    -- Doof
    { 0, 0, 0, 1541, 20, "doof.com", "/", "http:", "", 2359},
    -- Drawbridge
    { 0, 0, 0, 1542, 22, "drawbrid.ge", "/", "http:", "", 2509},
    -- Adenin / Dynamic Intranet
    { 0, 0, 0, 1543, 43, "dynamicintranet.com", "/", "http:", "", 2360},
    { 0, 0, 0, 1543, 43, "adenin.com", "/", "http:", "", 2360},
    -- East Money
    { 0, 0, 0, 1544, 33, "eastmoney.com", "/", "http:", "", 2481},
    -- Etao
    { 0, 0, 0, 1545, 22, "etao.com", "/", "http:", "", 2388},
    -- EQ Ads
    { 0, 0, 0, 1546, 22, "eqads.com", "/", "http:", "", 2539},
    { 0, 0, 0, 1546, 22, "eqworks.com", "/", "http:", "", 2539},
    -- Envato
    { 0, 0, 0, 1547, 23, "envato.com", "/", "http:", "", 1213},
    -- engage BDR
    { 0, 0, 0, 1548, 16, "engagebdr.com", "/", "http:", "", 2554},
    { 0, 0, 0, 1548, 16, "bnmla.com", "/", "http:", "", 2554},
    { 0, 0, 0, 1548, 16, "first-impression.com", "/", "http:", "", 2554},
    -- Enet
    { 0, 0, 0, 1549, 22, "enet.com.cn", "/", "http:", "", 1212},
    -- Effective Measure
    { 0, 0, 0, 1550, 45, "effectivemeasure.com", "/", "http:", "", 2516},
    -- eBay
    { 0, 0, 0, 1551, 45, "ebay.com", "/", "http:", "", 132},
    { 0, 0, 0, 1551, 45, "ebay.com.au", "/", "http:", "", 132},
    { 0, 0, 0, 1551, 45, "ebay.at", "/", "http:", "", 132},
    { 0, 0, 0, 1551, 45, "ebay.be", "/", "http:", "", 132},
    { 0, 0, 0, 1551, 45, "ebay.ca", "/", "http:", "", 132},
    { 0, 0, 0, 1551, 45, "ebay.com.cn", "/", "http:", "", 132},
    { 0, 0, 0, 1551, 45, "ebay.fr", "/", "http:", "", 132},
    { 0, 0, 0, 1551, 45, "ebay.de", "/", "http:", "", 132},
    { 0, 0, 0, 1551, 45, "ebay.com.hk", "/", "http:", "", 132},
    { 0, 0, 0, 1551, 45, "ebay.in", "/", "http:", "", 132},
    { 0, 0, 0, 1551, 45, "ebay.ie", "/", "http:", "", 132},
    { 0, 0, 0, 1551, 45, "ebay.it", "/", "http:", "", 132},
    { 0, 0, 0, 1551, 45, "ebay.com.ny", "/", "http:", "", 132},
    { 0, 0, 0, 1551, 45, "ebay.nl", "/", "http:", "", 132},
    { 0, 0, 0, 1551, 45, "ebay.ph", "/", "http:", "", 132},
    { 0, 0, 0, 1551, 45, "ebay.pl", "/", "http:", "", 132},
    { 0, 0, 0, 1551, 45, "ebay.com.sg", "/", "http:", "", 132},
    { 0, 0, 0, 1551, 45, "ebay.ch", "/", "http:", "", 132},
    { 0, 0, 0, 1551, 45, "ebay.es", "/", "http:", "", 132},
    { 0, 0, 0, 1551, 45, "tradera.com", "/", "http:", "", 132},
    { 0, 0, 0, 1551, 45, "ebay.cp.th", "/", "http:", "", 132},
    { 0, 0, 0, 1551, 45, "gittigidiyor.com", "/", "http:", "", 132},
    { 0, 0, 0, 1551, 45, "ebay.co.uk", "/", "http:", "", 132},
    { 0, 0, 0, 1551, 45, "ebay.vn", "/", "http:", "", 132},
    { 0, 0, 0, 1551, 45, "ruten.com.tw", "/", "http:", "", 132},
    { 0, 0, 0, 1551, 45, "gmarket.co.kr", "/", "http:", "", 132},
    -- comScore
    { 0, 0, 0, 1552, 22, "comscore.com", "/", "http:", "", 2462},
    -- MediaV
    { 0, 0, 0, 1553, 22, "mediav.com", "/", "http:", "", 2501},
    { 0, 0, 0, 1553, 22, "mediav.cn", "/", "http:", "", 2501},
    { 0, 0, 0, 1553, 22, "fenxi.com", "/", "http:", "", 2501},
    -- Meetup
    { 0, 0, 0, 1554, 22, "meetup.com", "/", "http:", "", 2364},
    -- Mercado Livre
    { 0, 0, 0, 1555, 30, "mercadolivre.com", "/", "http:", "", 2860},
    { 0, 0, 0, 1555, 30, "mercadolibre.com", "/", "http:", "", 2860},
    { 0, 0, 0, 1555, 30, "mercadolivre.com.br", "/", "http:", "", 2860},
    { 0, 0, 0, 1555, 30, "mercadolibre.com.ar", "/", "http:", "", 2860},
    { 0, 0, 0, 1555, 30, "mercadolibre.com.co", "/", "http:", "", 2860},
    { 0, 0, 0, 1555, 30, "mercadolibre.co.cr", "/", "http:", "", 2860},
    { 0, 0, 0, 1555, 30, "mercadolibre.cl", "/", "http:", "", 2860},
    { 0, 0, 0, 1555, 30, "mercadolibre.com.do", "/", "http:", "", 2860},
    { 0, 0, 0, 1555, 30, "mercadolibre.com.ec", "/", "http:", "", 2860},
    { 0, 0, 0, 1555, 30, "mercadolibre.com.mx", "/", "http:", "", 2860},
    { 0, 0, 0, 1555, 30, "mercadolibre.com.pa", "/", "http:", "", 2860},
    { 0, 0, 0, 1555, 30, "mercadolibre.com.pe", "/", "http:", "", 2860},
    { 0, 0, 0, 1555, 30, "mercadolivre.pt", "/", "http:", "", 2860},
    { 0, 0, 0, 1555, 30, "mercadolibre.com.uy", "/", "http:", "", 2860},
    { 0, 0, 0, 1555, 30, "mercadolibre.com.ve", "/", "http:", "", 2860},
    { 0, 0, 0, 1555, 30, "mercadopago.com", "/", "http:", "", 2860},
    { 0, 0, 0, 1555, 30, "mercadopago.com.br", "/", "http:", "", 2860},
    { 0, 0, 0, 1555, 30, "mercadoshops.com.br", "/", "http:", "", 2860},
    -- Meta5
    { 0, 0, 0, 1556, 30, "meta5.us", "/", "http:", "", 288},
    { 0, 0, 0, 1556, 30, "meta5.com", "/", "http:", "", 288},
    -- Mojiva
    { 0, 0, 0, 1557, 22, "mojiva.com", "/", "http:", "", 2507},
    -- Mixpanel
    { 0, 0, 0, 1558, 22, "mixpanel.com", "/", "http:", "", 2593},
    -- MLN Advertising
    { 0, 0, 0, 1559, 22, "mlnadvertising.com", "/", "http:", "", 2861},
    { 0, 0, 0, 1559, 22, "mediaglu.net", "/", "http:", "", 2861},
    -- Mobile Theory
    { 0, 0, 0, 1560, 22, "mobiletheory.com", "/", "http:", "", 2506},
    -- Monetate
    { 0, 0, 0, 1561, 22, "monetate.com", "/", "http:", "", 2496},
    -- Mop.com
    { 0, 0, 0, 1562, 22, "mop.com", "/", "http:", "", 2862},
    -- Motley Fool
    { 0, 0, 0, 1563, 39, "fool.com", "/", "http:", "", 2863},
    { 0, 0, 0, 1563, 39, "fool.ca", "/", "http:", "", 2863},
    { 0, 0, 0, 1563, 39, "fool.co.uk", "/", "http:", "", 2863},
    { 0, 0, 0, 1563, 39, "fool.com.au", "/", "http:", "", 2863},
    { 0, 0, 0, 1563, 39, "fool.sg", "/", "http:", "", 2863},
    -- Motrixi
    { 0, 0, 0, 1564, 22, "motrixi.com", "/", "http:", "", 2525},
    -- Mozilla
    { 0, 0, 0, 1565, 8, "mozilla.com", "/", "http:", "", 1261},
    { 0, 0, 0, 1565, 8, "mozilla.org", "/", "http:", "", 1261},
    -- MUZU TV
    { 0, 0, 0, 1566, 13, "muzu.tv", "/", "http:", "", 2375},
    -- MyBuys
    { 0, 0, 0, 1567, 22, "mybuys.com", "/", "http:", "", 2586},
    -- MyWebSearch
    { 0, 0, 0, 1568, 22, "mywebsearch.com", "/", "http:", "", 2365},
    -- Naverisk
    { 0, 0, 0, 1569, 8, "naverisk.com", "/", "http:", "", 2390},
    { 0, 0, 0, 1569, 8, "naveriskusa.com", "/", "http:", "", 2390},
    -- Netease
    { 0, 0, 0, 1570, 22, "netease.com", "/", "http:", "", 1222},
    { 0, 0, 0, 1570, 22, "163.com", "/", "http:", "", 1222},
    { 0, 0, 0, 1570, 22, "127.net", "/", "http:", "", 1222},
    -- NetSeer
    { 0, 0, 0, 1571, 22, "netseer.com", "/", "http:", "", 2551},
    -- Nexage
    { 0, 0, 0, 1572, 22, "nexage.com", "/", "http:", "", 2508},
    -- Nielsen
    { 0, 0, 0, 1573, 22, "nielsen.com", "/", "http:", "", 2468},
    -- NovaBACKUP
    { 0, 0, 0, 1574, 9, "novastor.com", "/", "http:", "", 336},
    -- Nugg
    { 0, 0, 0, 1576, 22, "nugg.ad", "/", "http:", "", 2544},
    { 0, 0, 0, 1576, 22, "nuggad.net", "/", "http:", "", 2544},
    -- Ohana
    { 0, 0, 0, 1577, 22, "ohana-media.com", "/", "http:", "", 2531},
    { 0, 0, 0, 1577, 22, "networkohana.com", "/", "http:", "", 2531},
    -- Olive Media
    { 0, 0, 0, 1578, 22, "olivemedia.ca", "/", "http:", "", 2592},
    -- Online File Folder
    { 0, 0, 0, 1579, 9, "onlinefilefolder.com", "/", "http:", "", 1223},
    { 0, 0, 0, 1579, 9, "login.secureserver.net", "/", "http:", "", 1223},
    -- Open Webmail
    { 0, 0, 0, 1580, 4, "openwebmail.org", "/", "http:", "", 1175},
    -- OpenX
    { 0, 0, 0, 1581, 22, "openx.com", "/", "http:", "", 2415},
    -- Optimizely
    { 0, 0, 0, 1582, 22, "optimizely.com", "/", "http:", "", 2530},
    -- Pchome
    { 0, 0, 0, 1583, 27, "pchome.net", "/", "http:", "", 2350},
    -- PDBox
    { 0, 0, 0, 1584, 27, "pdbox.co.kr", "/", "http:", "", 2471},
    -- Apple Update
    { 0, 0, 0, 1585, 6, "swcdn.apple.com", "/", "http:", "", 32},
    { 0, 0, 0, 1585, 6, "phobos.apple.com", "/", "http:", "", 32},
    -- Apple Maps
    { 0, 0, 0, 1586, 22, "ls.apple.com", "/", "http:", "", 2381},
    -- Netfolder.in
    { 0, 0, 0, 1590, 22, "netfolder.in", "/", "http:", "", 3814},
    -- MissLee
    { 0, 0, 0, 1591, 22, "misslee.net", "/", "http:", "", 3815},
    -- Mgoon
    { 0, 0, 0, 1592, 22, "mgoon.com", "/", "http:", "", 3816},
    -- QDown
    { 0, 0, 0, 1593, 22, "qdown.com", "/", "http:", "", 3817},
    -- SBS
    { 0, 0, 0, 1594, 22, "sbs.co.kr", "/", "http:", "", 3818},
    -- Google hangouts
    { 0, 0, 0, 1587, 10, "google.com", "/hangouts", "http:", "", 2960},
    -- Google helpouts
    { 0, 0, 0, 1588, 10, "helpouts.google.com", "/", "http:", "", 2961}, 
    -- Pinger
    { 0, 0, 0, 1595, 10, "pinger.com", "/", "http:", "", 1148}, 
    -- Plaxo
    { 0, 0, 0, 1596, 10, "plaxo.com", "/", "http:", "", 369}, 
    -- Polldaddy
    { 0, 0, 0, 1597, 22, "polldaddy.com", "/", "http:", "", 2582}, 
    -- PPStream
    { 0, 0, 0, 59, 13, "pps.tv", "/", "http:", "", 374}, 
    { 0, 0, 0, 59, 13, "ppstream.com", "/", "http:", "", 374}, 
    -- PPTV
    { 0, 0, 0, 1598, 13, "pptv.com", "/", "http:", "", 2380}, 
    -- Proclivity
    { 0, 0, 0, 1599, 22, "proclivitysystems.com", "/", "http:", "", 2533}, 
    -- QQ
    { 0, 0, 0, 1600, 10, "im.qq.com", "/", "http:", "", 386}, 
    { 0, 0, 0, 1600, 10, "imqq.com", "/", "http:", "", 386}, 
    -- Quake Live
    { 0, 0, 0, 1601, 20, "quakelive.com", "/", "http:", "", 2888}, 
    -- Quantcast
    { 0, 0, 0, 1602, 15, "quantcast.com", "/", "http:", "", 2405}, 
    -- Quote.com
    { 0, 0, 0, 1603, 39, "quote.com", "/", "http:", "", 2353}, 
    { 0, 0, 0, 1603, 39, "thestockmarketwatch.com", "/", "http:", "", 2353}, 
    -- RadiumOne
    { 0, 0, 0, 1604, 22, "radiumone.com", "/", "http:", "", 2564}, 
    -- Raging Bull
    { 0, 0, 0, 1605, 39, "ragingbull.com", "/", "http:", "", 1225}, 
    -- Rambler
    { 0, 0, 0, 1606, 22, "rambler.ru", "/", "http:", "", 2603}, 
    -- Rapleaf
    { 0, 0, 0, 1607, 22, "rapleaf.com", "/", "http:", "", 2540}, 
    { 0, 0, 0, 1607, 22, "towerdata.com", "/", "http:", "", 2540}, 
    -- Resonate Networks
    { 0, 0, 0, 1608, 22, "resonateinsights.com", "/", "http:", "", 2553}, 
    -- RichRelevance
    { 0, 0, 0, 1609, 22, "richrelevance.com", "/", "http:", "", 2404}, 
    -- Rocket Fuel
    { 0, 0, 0, 1610, 22, "rocketfuel.com", "/", "http:", "", 2563}, 
    -- Rubicon Project
    { 0, 0, 0, 1611, 22, "rubiconproject.com", "/", "http:", "", 2417}, 
    -- Scorecard Research
    { 0, 0, 0, 1612, 16, "scorecardresearch.com", "/", "http:", "", 2408}, 
    -- SendSpace
    { 0, 0, 0, 1613, 9, "sendspace.com", "/", "http:", "", 2382}, 
    -- ShareThis
    { 0, 0, 0, 1614, 9, "sharethis.com", "/", "http:", "", 2635}, 
    -- ShowMyPC
    { 0, 0, 0, 1615, 8, "showmypc.com", "/", "http:", "", 1630}, 
    -- Silverpop
    { 0, 0, 0, 1616, 4, "silverpop.com", "/", "http:", "", 2460}, 
    -- SiteScout
    { 0, 0, 0, 1617, 22, "sitescout.com", "/", "http:", "", 2864}, 
    -- Six Apart
    { 0, 0, 0, 1618, 22, "sixapart.com", "/", "http:", "", 2560}, 
    { 0, 0, 0, 1618, 22, "sixapart.jp", "/", "http:", "", 2560}, 
    { 0, 0, 0, 1618, 22, "movabletype.com", "/", "http:", "", 2560}, 
    -- Skimlinks
    { 0, 0, 0, 1619, 22, "skimlinks.com", "/", "http:", "", 2590}, 
    -- SLI Systems
    { 0, 0, 0, 1620, 22, "sli-systems.com", "/", "http:", "", 2494}, 
    { 0, 0, 0, 1620, 22, "sli-systems.co.uk", "/", "http:", "", 2494}, 
    { 0, 0, 0, 1620, 22, "sli-systems.com.au", "/", "http:", "", 2494}, 
    { 0, 0, 0, 1620, 22, "sli-systems.com.br", "/", "http:", "", 2494}, 
    { 0, 0, 0, 1620, 22, "sli-systems.co.jp", "/", "http:", "", 2494}, 
    -- SlideShare
    { 0, 0, 0, 1621, 9, "slideshare.com", "/", "http:", "", 1176}, 
    { 0, 0, 0, 1621, 9, "slideshare.net", "/", "http:", "", 1176}, 
    -- Smart AdServer
    { 0, 0, 0, 1622, 22, "smartadserver.com", "/", "http:", "", 2568}, 
    -- Softonic
    { 0, 0, 0, 1623, 22, "softonic.com", "/", "http:", "", 2599}, 
    { 0, 0, 0, 1623, 22, "softonic.fr", "/", "http:", "", 2599}, 
    { 0, 0, 0, 1623, 22, "softonic.de", "/", "http:", "", 2599}, 
    { 0, 0, 0, 1623, 22, "softonic.it", "/", "http:", "", 2599}, 
    { 0, 0, 0, 1623, 22, "softonic.com.br", "/", "http:", "", 2599}, 
    { 0, 0, 0, 1623, 22, "softonic.cn", "/", "http:", "", 2599}, 
    { 0, 0, 0, 1623, 22, "softonic.pl", "/", "http:", "", 2599}, 
    { 0, 0, 0, 1623, 22, "softonic.jp", "/", "http:", "", 2599}, 
    -- Softpedia
    { 0, 0, 0, 1624, 22, "softpedia.com", "/", "http:", "", 2606}, 
    -- Sogou
    { 0, 0, 0, 1625, 22, "sogou.com", "/", "http:", "", 2383}, 
    -- Soku
    { 0, 0, 0, 1626, 22, "soku.com", "/", "http:", "", 1226}, 
    -- SopCast
    { 0, 0, 0, 1627, 13, "sopcast.com", "/", "http:", "", 2628}, 
    -- Sourceforge
    { 0, 0, 0, 1628, 22, "sourceforge.net", "/", "http:", "", 1177}, 
    { 0, 0, 0, 1628, 22, "sf.net", "/", "http:", "", 1177}, 
    -- SPC Media
    { 0, 0, 0, 1629, 22, "spcmedia.co.uk", "/", "http:", "", 2411}, 
    -- SpotXchange
    { 0, 0, 0, 1630, 22, "spotxchange.com", "/", "http:", "", 2548}, 
    -- Squidoo
    { 0, 0, 0, 1631, 5, "squidoo.com", "/", "http:", "", 2377}, 
    { 0, 0, 0, 1631, 5, "squidoo.ca", "/", "http:", "", 2377}, 
    { 0, 0, 0, 1631, 5, "squidoohq.com", "/", "http:", "", 2377}, 
    -- SuperNews
    { 0, 0, 0, 1632, 33, "supernews.com", "/", "http:", "", 454}, 
    -- SurveyMonkey
    { 0, 0, 0, 1633, 23, "surveymonkey.com", "/", "http:", "", 1178}, 
    -- SVN
    { 0, 0, 0, 1634, 22, "visualsvn.com", "/", "http:", "", 2887}, 
    -- Tango
    { 0, 0, 0, 1635, 5, "tango.me", "/", "http:", "", 2379}, 
    -- TeacherTube
    { 0, 0, 0, 1636, 12, "teachertube.com", "/", "http:", "", 2602}, 
    -- TeamViewer
    { 0, 0, 0, 1637, 9, "teamviewer.com", "/", "http:", "", 958}, 
    -- TechCrunch
    { 0, 0, 0, 1638, 33, "techcrunch.com", "/", "http:", "", 2607}, 
    -- TechInline
    { 0, 0, 0, 1639, 8, "techinline.com", "/", "http:", "", 2351}, 
    { 0, 0, 0, 1639, 8, "fixme.it", "/", "http:", "", 2351}, 
    -- Telemetry
    { 0, 0, 0, 1640, 22, "telemetry.com", "/", "http:", "", 2596}, 
    -- Telly
    { 0, 0, 0, 1641, 1, "telly.com", "/", "http:", "", 2487}, 
    -- Bootstrap CDN
    { 0, 0, 0, 1642, 19, "bootstrapcdn.com", "/", "http:", "", 3822}, 

}

function DetectorInit(detectorInstance)

    gDetector = detectorInstance;

    -- Apple Maps
    gDetector:addHttpPattern(2, 5, 0, 468, 23, 0, 0, 'com.apple.Maps', 2381, 1);

    if gDetector.addAppUrl then
        for i,v in ipairs(gUrlPatternList) do
            gDetector:addAppUrl(v[1],v[2],v[3],v[4],v[5],v[6],v[7],v[8],v[9],v[10]);
        end
    end

    return gDetector;
end

function DetectorClean()
end

