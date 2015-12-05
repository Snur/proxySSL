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
detection_name: SSL Group "1ders"
version: 11
description: Group of SSL Host detectors.
bundle_description: $VAR1 = {
          'Pinger' => 'Allows SMS text messaging via a data connection.',
          'Nexage' => 'Advertisement site.',
          'ShowMyPC' => 'Cloud-based remote support and desktop sharing.',
          'Nielsen' => 'Global information and measurement company.',
          'imo.im' => 'Instant messenger service for various instant messaging protocols.',
          'Target' => 'Discount retailer.',
          'SpotXchange' => 'Advertisement site.',
          'DepositFiles' => 'International file hosting and sharing service.',
          'Dell' => 'Computer and related technologies retailer.',
          'Krux' => 'Cloud-based online marketing and monetization service.',
          'Mgoon' => 'Korean Entertainment web portal.',
          'IGN' => 'News/reviews website focused primarily on video games.',
          'Plaxo' => 'An online address book and social networking service that provides automatic updating of contact information.',
          'IBM' => 'Website for IBM.',
          'TeamViewer' => 'Remote desktop control and file transfer software.',
          'Sogou' => 'Chinese web portal.',
          'Newegg' => 'Computer hardware and software retailer.',
          'Olive Media' => 'Advertisement site.',
          'Motrixi' => 'Advertisement site.',
          'Meta5' => 'Business analytic software. Allows users to create reports that can access multiple corporate data sources. Registered with IANA on port 393 tcp/udp.',
          'HP Home & Home Office Store' => 'HP\'s online store for computers and related products.',
          'TechInline' => 'Website that offers remote desktop control.',
          'Sourceforge' => 'Site for sharing open source software projects.',
          'Infonline' => 'Malware-generated online advertisements.',
          'Tagged' => 'Social networking site based in California.',
          'Mafiawars' => 'A multiplayer browser game created by Zynga.  It is on several social networking sites and on the iPhone.',
          'Reduxmedia' => 'Advertisement site.',
          'Nugg' => 'Advertisement site.',
          'Rubicon Project' => 'Online advertising infrastructure company.',
          'Neustar Information Services' => 'Advertisement site.',
          'MyBuys' => 'Advertisement site.',
          'Rambler' => 'Russian search engine.',
          'Softonic' => 'Software download site.',
          'SBS' => 'Korean Online TV shows and Movies.',
          'MUZU TV' => 'Music video site.',
          'Doof' => 'Online gaming site.',
          'LA Times' => 'News site for the west coast newspaper.',
          'LinkedIn' => 'Career oriented social networking.',
          'Mercado Livre' => 'Brazil online auction and shopping website.',
          'Open Webmail' => 'Webmail service.',
          'PDBox' => 'Korean file-sharing site.',
          'Salesforce.com' => 'Enterprise cloud computing company.',
          'Marca' => 'Primarily Spanish video streaming site.',
          'Polldaddy' => 'Advertisement site.',
          'Playdom' => 'A web gaming company that produces facebook games.',
          'Quake Live' => 'Online video game by id Software.',
          'Hotspot Shield' => 'Anonymizer and tunnel that encrypts communications.',
          'Hushmail' => 'Web mail service providing encrypted and virus scanned e-mail.',
          'comScore' => 'Digital business analytics.',
          'SoundCloud' => 'Music platform for artists to upload and promote their music.',
          'engage BDR' => 'Advertisement site.',
          'NetSeer' => 'Advertisement site.',
          'Meetup' => 'Social networking website.',
          'Squidoo' => 'Social blogging site.',
          'Smart AdServer' => 'Advertisement site.',
          'Alipay' => 'Online payment service.',
          'iPerceptions' => 'Online marketing analysis provider.',
          'Luminate' => 'Advertisement site.',
          'StumbleUpon' => 'A web browser plugin that allows users to discover and rate webpages, photos, videos and news articles.',
          'Metacafe' => 'Online video entertainment website.',
          'Last.fm' => 'A social networking music streaming site.',
          'Leboncoin' => 'Auction and classified seller website.',
          'Reddit' => 'Social news link site.',
          'Samsung' => 'Electronics retail site.',
          'SlideShare' => 'A web-based slide show service.',
          'MLN Advertising' => 'Managing/Organising advertisements and its content delivery.',
          'TowerData' => 'Formerly RapLeaf, an advertisement site.',
          'Mixpanel' => 'Advertisement site.',
          'Telemetry' => 'Advertisement site.',
          'Resonate Networks' => 'Advertisement site.',
          'NovaBACKUP' => 'NovaStor develops and markets data protection and availability software. NovaBACKUP offers support for multi-OS environments and is capable of handling thousands of servers and petabytes of information.',
          'Sears' => 'Department store retailer.',
          'Rocket Fuel' => 'Advertisement site.',
          'Drawbridge' => 'Advertisement site.',
          'SVN' => 'Managing Subversion servers.',
          'Effective Measure' => 'Advertisement site.',
          'Hideman Login' => 'Logging into Hideman internet anonymizer.',
          'Scorecard Research' => 'Online marketing research community.',
          'Line2' => 'Mobile VoIP application with support for text messaging.',
          'Brilig' => 'Advertisement site.',
          'LeadBolt' => 'Advertisement site.',
          'iStock' => 'Online royalty-free stock images.',
          'LiveRail' => 'Advertisement site.',
          'Photobucket' => 'An image hosting, video hosting, slideshow creation and photo sharing website.',
          'SendSpace' => 'File sharing and hosting.',
          'SuperNews' => 'A Usenet/newsgroup service provider.',
          'Microsoft Ads' => 'Web advertisement services.',
          'MediaV' => 'Advertisement site.',
          'Mozilla' => 'Website for many open source software projects, including the Firefox browser.',
          'RadiumOne' => 'Advertisement site.',
          'Tango' => 'Mobile social networking app that provides voice, chat, and gaming services.',
          'MediaMath' => 'Advertising and business analytics.',
          'Lotame' => 'Online advertising and marketing research platform.',
          'Chinaren' => 'Chinese social networking site.',
          'LogMeIn' => 'Remote access and PC desktop control.',
          'OpenX' => 'Closed advertising platform.',
          'Optimizely' => 'Advertisement site.',
          'Letitbit' => 'File hosting and sharing website.',
          'SPC Media' => 'New media production company.',
          'Mojiva' => 'Advertisement site.',
          'Mop.com' => 'Chinese webportal acting as bulletin board for pop culture, games and other entertainments.',
          'OpenCandy' => 'Advertising and marketing.',
          'DomainTools' => 'A domain name registrar.',
          'Adenin' => 'A web portal.',
          'Kaixin001' => 'Chinese based social networking service.',
          'EQ Ads' => 'Advertisement site.',
          'Apple Store' => 'Official online retailer of Apple products.',
          'Limelight' => 'Content delivery network.',
          'ShareThis' => 'Social advertising widgets.',
          'iCall' => 'Free voice, video chat, and text messaging app.',
          'SurveyMonkey' => 'A site for distributing surveys.',
          'Jango' => 'Internet radio and social networking service.',
          'SiteScout' => 'Company targetting powerful and easy-to-use tech for real-time ads.',
          'Delicious' => 'Social bookmarking website for storing, sharing, and finding web bookmarks.',
          'SLI Systems' => 'Advertisement site.',
          'Netease' => 'Chinese web portal.',
          'HubPages' => 'Social blogging site.',
          'Ado Tube' => 'Video advertising solution.',
          'Netfolder.in' => 'Free online file sharing.',
          'Imgur' => 'Image hosting website.',
          'Match.com' => 'Dating website.',
          'Pandora' => 'Audio streaming.',
          'Kooora.com' => 'Webportal for Sports related news.',
          'StatCounter' => 'Web traffic analyser.',
          'Picasa' => 'Google picasa is an image organizer and image viewer for organizing and editing digital photos, plus an integrated photo-sharing website.',
          'iCloud' => 'Apple cloud storage service.',
          'Skimlinks' => 'Advertisement site.',
          'CBS' => 'CBS news website.',
          'Silverpop' => 'Email marketing service.',
          'Monetate' => 'Advertisement site.',
          'Online File Folder' => 'Cloud-based file storage.',
          'MaxPoint Interactive' => 'Advertisement site.',
          'Envato' => 'Combined software education and marketplace site.',
          'Docstoc' => 'Electronic business document repository and online store.',
          'Lokalisten' => 'German social network site focused on local events.',
          'MelOn' => 'Korean music site.',
          'DeNA websites' => 'Traffic generated by browsing DeNA Comm website and some other sites that belong to DeNA.',
          'TechCrunch' => 'IT related news and research site.',
          'NBA' => 'Official website for the National Basketball League, an American sports organization.',
          'Improve Digital' => 'European sell side online ad service.',
          'RapidShare' => 'Site for sharing and transferring files.',
          'eBay' => 'An online auction and shopping website.',
          'Naverisk' => 'Cloud-based remote monitoring and management software.',
          'Suresome' => 'Web based encrypted proxy service.',
          'ImageShack' => 'Image hosting website.',
          'SHOUTCast Radio' => 'Streaming media software.',
          'ICQ' => 'Internet chat client.',
          'MediaFire' => 'File and image hosting site.',
          'Crittercism' => 'Mobile application monitor.',
          'Microsoft Store' => 'Online retailer for Microsoft products.',
          'Six Apart' => 'Advertisement site.',
          'RichRelevance' => 'Targeted advertising platform.',
          'Adtech' => 'Advertisement site.',
          'TeacherTube' => 'Educational video streaming.',
          'Hopster' => 'A couponing site.',
          'contnet' => 'Advertisement site.',
          'LINE' => 'Instant Messaging.',
          'IKEA.com' => 'Online storefront for international furniture retailer.',
          'Telly' => 'Video sharing and streaming site.',
          'Quantcast' => 'Site for buying and selling target audiences.',
          'Motley Fool' => 'Financial and Investment community.',
          'Admasters' => 'Advertisement site.'
        };

--]]

require "DetectorCommon"


local DC = DetectorCommon

DetectorPackageInfo = {
    name =  "ssl_host_group_1ders",
    proto =  DC.ipproto.tcp,
    client = {
        init =  'DetectorInit',
        clean =  'DetectorClean',
        minimum_matches =  1
    }
}

--detectorType(0-> Web, 1->Client),  AppId, SSLPattern
gSSLHostPatternList = {

    -- Alipay
    { 0, 3655, 'alipay.com' },
    -- Crittercism
    { 0, 3656, 'crittercism.com' },
    -- MelOn
    { 0, 3659, 'melon.com' },
    -- Microsoft Store
    { 0, 3670, 'microsoftstore.com' },
    -- OpenCandy
    { 0, 3672, 'opencandy.com' },
    -- Last.fm
    { 0, 261, 'last.fm' },
    -- Microsoft Ads
    { 0, 1336, 'adcenter.microsoft.com' },
    { 0, 1336, 'bingads.microsoft.com' },
    -- Hopster
    { 0, 202, 'hopster.com' },
    -- Hotspot Shield
    { 0, 1140, 'esellerate.net' },
    { 0, 1140, 'hsselite.com' },
    { 0, 1140, 'hsselite.zendesk.com' },
    { 0, 1140, 'hotspotshield.com' },
    -- HP Home & Home Office Store
    { 0, 827, 'shopping.hp.com' },
    { 0, 827, 'store.hp.com' },
    -- HubPages
    { 0, 2485, 'hubpages.com' },
    -- Hushmail
    { 0, 981, 'hushmail.com' },
    -- IBM
    { 0, 1173, 'ibm.com' },
    -- iCall
    { 0, 2401, 'icall.com' },
    { 0, 2401, 'siftscience.com' },
    -- iCloud
    { 0, 1187, 'icloud.com' },
    { 0, 1187, 'me.com' },
    -- ICQ
    { 0, 679, 'icq.com' },
    -- IGN
    { 0, 680, 'ign.com' },
    -- IKEA.com
    { 0, 2349, 'ikea.com' },
    -- ImageShack
    { 0, 682, 'imageshack.com' },
    { 0, 682, 'imageshack.us' },
    -- Imgur
    { 0, 684, 'imgur.com' },
    -- imo.im
    { 0, 685, 'imo.im' },
    -- Improve Digital
    { 0, 2451, 'improvedigital.com' },
    { 0, 2451, '360yield.com' },
    -- Infonline
    { 0, 2461, 'infonline.de' },
    -- iPerceptions
    { 0, 2455, 'iperceptions.com' },
    -- iStock
    { 0, 2858, 'istockphoto.com' },
    -- Jango
    { 0, 987, 'jango.com' },
    -- Kaixin001
    { 0, 989, 'kaixin001.com' },
    -- Krux
    { 0, 2466, 'krux.com' },
    { 0, 2466, 'kruxdigital.com' },
    -- LA Times
    { 0, 2609, 'latimes.com' },
    -- LeadBolt
    { 0, 2505, 'leadbolt.com' },
    -- Leboncoin
    { 0, 1219, 'leboncoin.fr' },
    -- Letitbit
    { 0, 2374, 'letitbit.net' },
    -- Limelight
    { 0, 711, 'llnw.com' },
    { 0, 711, 'kiptronic.com' },
    { 0, 711, 'limelight.com' },
    -- LINE
    { 0, 1667, 'line.me' },
    -- Line2
    { 0, 1149, 'line2.com' },
    -- LinkedIn
    { 0, 713, 'linkedin.com' },
    -- LiveRail
    { 0, 2520, 'liverail.com' },
    -- LogMeIn
    { 0, 270, 'logmein.com' },
    { 0, 270, 'logme.in' },
    -- Lokalisten
    { 0, 718, 'lokalisten.de' },
    { 0, 718, 'lokalisten.at' },
    -- Lotame
    { 0, 2465, 'lotame.com' },
    -- Luminate, Inc.
    { 0, 2521, 'luminate.com' },
    -- Mafiawars
    { 0, 272, 'mafiawars.com' },
    { 0, 272, 'mafiawars.zynga.com' },
    { 0, 272, 'apps.facebook.com/inthemafia' },
    -- Marca
    { 0, 2486, 'marca.com' },
    { 0, 2486, 'marca.es' },
    -- Match.com
    { 0, 2363, 'match.com' },
    -- MaxPoint Interactive
    { 0, 2561, 'maxpoint.com' },
    { 0, 2561, 'maxpointexpress.com' },
    -- MediaFire
    { 0, 285, 'mediafire.com' },
    -- MediaMath
    { 0, 2416, 'mediamath.com' },
    -- Delicious
    { 0, 605, 'delicious.com' },
    -- Dell
    { 0, 606, 'dell.com' },
    -- DepositFiles
    { 0, 1054, 'depositfiles.com' },
    -- Docstoc
    { 0, 940, 'docstoc.com' },
    -- DomainTools
    { 0, 1172, 'domaintools.com' },
    -- Doof
    { 0, 2359, 'doof.com' },
    -- Drawbridge
    { 0, 2509, 'drawbrid.ge' },
    -- Adenin / Dynamic Intranet
    { 0, 2360, 'dynamicintranet.com' },
    { 0, 2360, 'adenin.com' },
    -- EQ Ads
    { 0, 2539, 'eqads.com' },
    { 0, 2539, 'eqworks.com' },
    -- Envato
    { 0, 1213, 'envato.com' },
    -- engage BDR
    { 0, 2554, 'bnmla.com' },
    { 0, 2554, 'first-impression.com' },
    -- Effective Measure
    { 0, 2516, 'effectivemeasure.com' },
    -- eBay
    { 0, 132, 'ebay.com' },
    { 0, 132, 'ebay.com.au' },
    { 0, 132, 'ebay.at' },
    { 0, 132, 'ebay.be' },
    { 0, 132, 'ebay.ca' },
    { 0, 132, 'ebay.com.cn' },
    { 0, 132, 'ebay.fr' },
    { 0, 132, 'ebay.de' },
    { 0, 132, 'ebay.com.hk' },
    { 0, 132, 'ebay.in' },
    { 0, 132, 'ebay.ie' },
    { 0, 132, 'ebay.it' },
    { 0, 132, 'ebay.com.ny' },
    { 0, 132, 'ebay.nl' },
    { 0, 132, 'ebay.ph' },
    { 0, 132, 'ebay.pl' },
    { 0, 132, 'ebay.com.sg' },
    { 0, 132, 'ebay.ch' },
    { 0, 132, 'ebay.es' },
    { 0, 132, 'tradera.com' },
    { 0, 132, 'ebay.cp.th' },
    { 0, 132, 'gittigidiyor.com' },
    { 0, 132, 'ebay.co.uk' },
    { 0, 132, 'ebay.vn' },
    { 0, 132, 'ruten.com.tw' },
    { 0, 132, 'gmarket.co.kr' },
    -- Neustar Information Services
    { 0, 2537, 'neustar.biz' },
    { 0, 2537, 'neustar.com' },
    { 0, 2537, 'neustarlife.com' },
    { 0, 2537, 'targusinfo.com' },
    { 0, 2537, 'neustarlocaleze.biz' },
    { 0, 2537, 'neustarlocaleze.com' },
    { 0, 2537, 'ultradns.com' },
    { 0, 2537, 'webmetrics.com' },
    { 0, 2537, 'tcpacompliance.us' },
    { 0, 2537, 'npac.com' },
    -- comScore
    { 0, 2462, 'comscore.com' },
    -- MediaV
    { 0, 2501, 'mediav.com' },
    { 0, 2501, 'mediav.cn' },
    { 0, 2501, 'fenxi.com' },
    -- Meetup
    { 0, 2364, 'meetup.com' },
    -- Mercado Livre
    { 0, 2860, 'mercadolivre.com' },
    { 0, 2860, 'mercadolibre.com' },
    { 0, 2860, 'mercadolivre.com.br' },
    { 0, 2860, 'mercadolibre.com.ar' },
    { 0, 2860, 'mercadolibre.com.co' },
    { 0, 2860, 'mercadolibre.co.cr' },
    { 0, 2860, 'mercadolibre.cl' },
    { 0, 2860, 'mercadolibre.com.do' },
    { 0, 2860, 'mercadolibre.com.ec' },
    { 0, 2860, 'mercadolibre.com.mx' },
    { 0, 2860, 'mercadolibre.com.pa' },
    { 0, 2860, 'mercadolibre.com.pe' },
    { 0, 2860, 'mercadolivre.pt' },
    { 0, 2860, 'mercadolibre.com.uy' },
    { 0, 2860, 'mercadolibre.com.ve' },
    { 0, 2860, 'mercadopago.com' },
    { 0, 2860, 'mercadopago.com.br' },
    { 0, 2860, 'mercadoshops.com.br' },
    -- Meta5
    { 0, 288, 'meta5.us' },
    { 0, 288, 'meta5.com' },
    -- Metacafe
    { 0, 728, 'metacafe.com' },
    -- Mojiva
    { 0, 2507, 'mojiva.com' },
    -- Mixpanel
    { 0, 2593, 'mixpanel.com' },
    -- MLN Advertising
    { 0, 2861, 'mlnadvertising.com' },
    { 0, 2861, 'mediaglu.net' },
    -- Monetate
    { 0, 2496, 'monetate.net' },
    -- Mop.com
    { 0, 2862, 'mop.com' },
    -- Motley Fool
    { 0, 2863, 'fool.com' },
    { 0, 2863, 'fool.ca' },
    { 0, 2863, 'fool.co.uk' },
    { 0, 2863, 'fool.com.au' },
    { 0, 2863, 'fool.sg' },
    -- Mozilla
    { 0, 1261, 'mozilla.com' },
    { 0, 1261, 'mozilla.org' },
    -- MUZU TV
    { 0, 2375, 'muzu.tv' },
    -- MyBuys
    { 0, 2586, 'mybuys.com' },
    -- Naverisk
    { 0, 2390, 'naverisk.com' },
    { 0, 2390, 'naveriskusa.com' },
    -- NBA
    { 0, 1939, 'nba.com' },
    { 0, 1939, 'nba.co.in' },
    { 0, 1939, 'nba.ca' },
    -- Netease
    { 0, 1222, '163.com' },
    -- NetSeer
    { 0, 2551, 'netseer.com' },
    -- Newegg
    { 0, 759, 'newegg.com' },
    -- Nexage
    { 0, 2508, 'nexage.com' },
    -- Nielsen
    { 0, 2468, 'nielsen.com' },
    -- NovaBACKUP
    { 0, 336, 'novastor.com' },
    -- Nugg
    { 0, 2544, 'nuggad.net' },
    -- Olive Media
    { 0, 2592, 'olivemedia.ca' },
    -- Online File Folder
    { 0, 1223, 'onlinefilefolder.com' },
    { 0, 1223, 'login.secureserver.net' },
    -- Open Webmail
    { 0, 1175, 'openwebmail.org' },
    -- OpenX
    { 0, 2415, 'openx.com' },
    -- Optimizely
    { 0, 2530, 'optimizely.com' },
    -- Pandora
    { 0, 779, 'pandora.com' },
    -- PDBox
    { 0, 2471, 'pdbox.co.kr' },
    -- Kooora.com
    { 0, 2859, 'kooora.com' },
    -- Motrixi
    { 0, 2525, 'motrixi.com' },
    -- Netfolder.in
    { 0, 3814, 'netfolder.in' },
    -- Mgoon
    { 0, 3816, 'mgoon.com' },
    -- SBS
    { 0, 3818, 'sbs.co.kr' },
    -- Photobucket
    { 0, 784, 'photobucket.com' },
    -- Picasa
    { 0, 785, 'picasa.com' },
    -- Pinger
    { 0, 1148, 'pinger.com' },
    -- Plaxo
    { 0, 369, 'plaxo.com' },
    -- Polldaddy
    { 0, 2582, 'polldaddy.com' },
    -- Quantcast
    { 0, 2405, 'quantcast.com' },
    -- RadiumOne
    { 0, 2564, 'radiumone.com' },
    -- Rambler
    { 0, 2603, 'rambler.ru' },
    -- RapidShare
    { 0, 802, 'rapidshare.com' },
    -- Rapleaf
    { 0, 2540, 'rapleaf.com' },
    { 0, 2540, 'towerdata.com' },
    -- Reddit
    { 0, 804, 'reddit.com' },
    -- Resonate Networks
    { 0, 2553, 'resonateinsights.com' },
    -- RichRelevance
    { 0, 2404, 'richrelevance.com' },
    -- Rocket Fuel
    { 0, 2563, 'rocketfuel.com' },
    -- Rubicon Project
    { 0, 2417, 'rubiconproject.com' },
    -- Salesforce.com
    { 0, 950, 'salesforce.com' },
    -- Samsung
    { 0, 1357, 'samsung.com' },
    { 0, 1357, 'samsungapps.com' },
    -- Scorecard Research
    { 0, 2408, 'scorecardresearch.com' },
    -- Sears
    { 0, 821, 'sears.com' },
    { 0, 821, 'sears.ca' },
    { 0, 821, 'searspartsdirect.com' },
    { 0, 821, 'searshomeservices.com' },
    { 0, 821, 'searsoutlet.com' },
    { 0, 821, 'searscommerceservices.com' },
    { 0, 821, 'searsflowers.com' },
    { 0, 821, 'searshomepro.com' },
    { 0, 821, 'searsoptical.com' },
    { 0, 821, 'searsoutlet.com' },
    { 0, 821, 'searsdrivingschools.com' },
    { 0, 821, 'searsvacations.com' },
    { 0, 821, 'searscommercial.com' },
    -- SendSpace
    { 0, 2382, 'sendspace.com' },
    -- ShareThis
    { 0, 2635, 'sharethis.com' },
    -- SHOUTCast Radio
    { 0, 829, 'shoutcast.com' },
    -- ShowMyPC
    { 0, 1630, 'showmypc.com' },
    -- Silverpop
    { 0, 2460, 'silverpop.com' },
    -- SiteScout
    { 0, 2864, 'sitescout.com' },
    -- Six Apart
    { 0, 2560, 'sixapart.com' },
    { 0, 2560, 'sixapart.jp' },
    { 0, 2560, 'movabletype.com' },
    -- Skimlinks
    { 0, 2590, 'skimlinks.com' },
    -- SLI Systems
    { 0, 2494, 'sli-systems.com' },
    -- SlideShare
    { 0, 1176, 'slideshare.com' },
    { 0, 1176, 'slideshare.net' },
    -- Smart AdServer
    { 0, 2568, 'smartadserver.com' },
    -- Softonic
    { 0, 2599, 'softonic.com' },
    -- Sogou
    { 0, 2383, 'sogou.com' },
    -- SoundCloud
    { 0, 1007, 'soundcloud.com' },
    -- Sourceforge
    { 0, 1177, 'sourceforge.net' },
    { 0, 1177, 'sf.net' },
    -- SPC Media
    { 0, 2411, 'spcmedia.co.uk' },
    -- SpotXchange
    { 0, 2548, 'spotxchange.com' },
    -- Squidoo
    { 0, 2377, 'squidoo.com' },
    { 0, 2377, 'squidoohq.com' },
    -- StatCounter
    { 0, 1521, 'statcounter.com' },
    -- StumbleUpon
    { 0, 852, 'stumbleupon.com' },
    -- SuperNews
    { 0, 454, 'supernews.com' },
    -- Suresome
    { 0, 1010, 'suresome.com' },
    -- SurveyMonkey
    { 0, 1178, 'surveymonkey.com' },
    -- SVN
    { 0, 2887, 'visualsvn.com' },
    -- Tagged
    { 0, 1065, 'tagged.com' },
    -- Tango
    { 0, 2379, 'tango.me' },
    -- Target
    { 0, 858, 'target.com' },
    -- TeacherTube
    { 0, 2602, 'teachertube.com' },
    -- TeamViewer
    { 0, 958, 'teamviewer.com' },
    -- TechCrunch
    { 0, 2607, 'techcrunch.com' },
    -- TechInline
    { 0, 2351, 'techinline.com' },
    { 0, 2351, 'fixme.it' },
    -- Telemetry
    { 0, 2596, 'telemetry.com' },
    -- Telly
    { 0, 2487, 'telly.com' },
    -- Reduxmedia
    { 0, 1955, 'reduxmedia.com' },
    { 0, 1955, 'reduxmediagroup.com' },
    -- Apple Store
    { 0, 551, 'store.apple.com' },
    -- Brilig
    { 0, 2511, 'brilig.com' },
    -- contnet
    { 0, 2566, 'contnet.de' },
    { 0, 2566, 'contnet.com' },
    -- Ado Tube
    { 0, 2847, 'adotube.com' },
    -- Adtech
    { 0, 2503, 'adtechaustralia.com' },
    { 0, 2503, 'adtech-kyushu.com' },
    { 0, 2503, 'ad-techlondon.co.uk' },
    { 0, 2503, 'ad-tech.sg' },
    { 0, 2503, 'adtechasean.com' },
    -- Chinaren
    { 0, 2384, 'chinaren.com' },
    -- Ad Master
    { 0, 2565, 'admasters.com' },
    -- Quake Live
    { 0, 2888, 'quakelive.com' },
    -- DeNA websites
    { 0, 2946, 'dena.com' },
    { 0, 2946, 'yahoo-mbga.jp' },
    { 0, 2946, 'mobage.cn' },
    { 0, 2946, 'mbga.jp' },
    { 0, 2946, 'daum-mobage.kr' },
    { 0, 2946, 'dena.jp' },
    { 0, 2946, 'dena-ec.com' },
    { 0, 2946, 'aumall.jp' },
    { 0, 2946, 'mbok.jp' },
    { 0, 2946, 'netsea.jp' },
    { 0, 2946, 'estar.jp' },
    { 0, 2946, 'paygent.co.jp' },
    { 0, 2946, 'mangabox.me' },
    { 0, 2946, 'showroom-live.com' },
    { 0, 2946, 'applizemi.com' },
    { 0, 2946, 'chirashiru.jp' },
    { 0, 2946, 'ssl.co-mm.com' },
    { 0, 2946, 'smcb.jp' },
    { 0, 2946, 'skygate.co.jp' },
    { 0, 2946, 'arukikata.com' },
    { 0, 2946, 'sougouhoken.jp' },
    { 0, 2946, 'gbooks.jp' },
    { 0, 2946, 'mycode.jp' },
    -- CBS
    { 0, 1332, 'cbslocal.com' },
    -- Hideman 
    { 0, 2681, 'hideman.net' },
    { 0, 2681, 'hideman.com' },
    -- Playdom
    { 0, 1237, 'playdom.com' }, 
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

