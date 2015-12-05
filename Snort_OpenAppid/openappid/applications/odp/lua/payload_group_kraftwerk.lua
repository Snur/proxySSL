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
detection_name: Payload Group "Kraftwerk"
version: 26
description: Group of payload detectors.
bundle_description: $VAR1 = {
          'AOL' => 'American company develops, grows and invests in brands and web sites.',
          'CometBird' => 'A web browser.',
          'Planetarium' => 'Planetarium for the Chrome browser.',
          'GoDaddy' => 'Domain registrar.',
          'Weather.gov' => 'Weather web portal.',
          'Pandora Audio' => 'Online Audio streaming.',
          'RoadRunner' => 'Web Portal for entertainment and sports news update.',
          'The Huffington Post' => 'Online news website.',
          'Verizon Wireless' => 'Telecom and Internet provider.',
          'Searchnu' => 'Search engine.',
          'Aweber' => 'Email marketing Service.',
          'OptMD' => 'Web advertisement services.',
          'Kuaibo' => 'Chinese website for the Client application QVOD.',
          'Ubuntu Update Manager' => 'Update manager.',
          'Wall Street Journal' => 'Web Portal for news update.',
          'Browzar' => 'A web browser.',
          'ZEDO' => 'Web advertisement services.',
          'PaleMoon' => 'A web browser.',
          'Indeed' => 'The job search engine.',
          'NATO' => 'Web portal for NATO.',
          'AT&T' => 'Telecom and Internet provider.',
          'Comcast' => 'Web Portal.',
          'Flurry Analytics' => 'Mobile application analytics.',
          'Etsy' => 'E-commerce website for homemade or vintage items.',
          'Comodo Dragon' => 'A web browser.',
          'FC2' => 'Web server, sites and Blog provider.',
          'Google Adsense' => 'AdSense for Google.',
          'CanvasRider' => 'Online game website.',
          'Taobao' => 'Chinese online auction and shopping website.',
          'NOAA' => 'Ocean and Atmospheric research agency.',
          'TweetDeck' => 'Dashboard application to manage both Twitter and Facebook.',
          'Eclipse Marketplace' => 'Marketplace for Eclipse application.',
          'CloudFront' => 'Content Delivery for AWS.',
          'Wyzo' => 'A web browser.',
          'Arora' => 'A web browser.',
          'Publishers Clearing House' => 'Online marketing company.',
          'ABC' => 'Web Portal for television network.',
          'Microsoft' => 'Official Microsoft website.',
          'SymantecUpdates' => 'Software updates for Symantec.',
          'Crazy Browser' => 'A web browser.',
          'Eclipse Updates' => 'Software Updates for Eclipse.',
          'Conduit' => 'Online website to create community toolbar.',
          'BBC' => 'Web Portal for news update.',
          'Daily Mail' => 'Web Portal for news update.',
          'AdNetwork.net' => 'Ad Portal.',
          'Ask.com' => 'Search engine.',
          'Amazon Web Services' => 'Online cloud computing service.',
          'Official Major League Baseball' => 'Web Portal for Sports news update.',
          'Sourcefire.com' => 'Company website for Network security and Intrusion Detection engine.',
          'NASA' => 'Web portal for NASA.',
          'eHow' => 'Website featuring tutorials on a wide variety of subjects.',
          'ESPN' => 'Online Sports news and show.',
          'Fox Sports' => 'Web Portal for Sports news update.',
          'Outbrain' => 'Online help for publishers and bloggers.',
          'GreenBrowser' => 'A web browser.',
          'Nokia Maps' => 'Nokia mapping and directions service.',
          'Localytics' => 'Mobile application analytics.',
          'Search-Result.com' => 'Search engine.',
          'Fox News' => 'Web Portal for news update.',
          'Drudge Report' => 'News aggregator.',
          'Apple Mobile Yahoo API' => 'Yahoos Mobile Applications for Apple product.',
          'Ubuntu Software Center' => 'Ubuntu software updates.'
        };

--]]

require "DetectorCommon"


local DC = DetectorCommon

DetectorPackageInfo = {
    name =  "payload_group_kraftwerk",
    proto =  DC.ipproto.tcp,
    client = {
        init =  'DetectorInit',
        clean =  'DetectorClean',
        minimum_matches =  1
    }
}

--serviceId, clientId, ClientType, PayloadId, PayloadType, hostPattern, pathPattern, schemePattern, queryPattern
gUrlPatternList = {

    --TweetDeck Dashboard app to manage Twitter and Facebook 
    { 0, 0, 0, 522,22, "tweetdeck.com", "/", "http:", "", 1360},
    --CanvasRider Online game 
    { 0, 0, 0, 523,20, "canvasrider.com", "/", "http:", "", 1361},
    --ZEDO Web Advertising Service 
    { 0, 0, 0, 524,16, "zedo.com", "/", "http:", "", 1362},
    --eHow Web Portal 
    { 0, 0, 0, 525,22, "ehow.com", "/", "http:", "", 1363},
    --ESPN Online sports update 
    { 0, 0, 0, 526,22, "espn.go.com", "/", "http:", "", 1364},
    { 0, 0, 0, 526,22, "espncdn.com", "/", "http:", "", 1364},
    { 0, 0, 0, 526,22, "espnfc", "/", "http:", "", 1364},
    --Comcast Web portal  
    { 0, 0, 0, 527,22, "comcast.com", "/", "http:", "", 1365},
    { 0, 0, 0, 527,22, "comcast.net", "/", "http:", "", 1365},
    --Foxnews Web portal for news update  
    { 0, 0, 0, 528,22, "foxnews.com", "/", "http:", "", 1366},
    { 0, 0, 0, 528,22, "foxnews.demdex.net", "/", "http:", "", 1366},
    { 0, 0, 0, 528,22, "foxnews.mobi", "/", "http:", "", 1366},
    { 0, 0, 0, 528,22, "fncstatic.com", "/", "http:", "", 1366},
    { 0, 0, 0, 528,22, "foxnews-f.akamaihd.net", "/", "http:", "", 1366},
    --Weather.com Weather Web portal  
   -- { 0, 0, 0, 529,22, "weather.com", "/", "http:", "", 1367},
    --Weather.gov Weather Web portal  
    { 0, 0, 0, 530,22, "weather.gov", "/", "http:", "", 1368},
    --Outbrain Online help for bloggers and publishers  
    { 0, 0, 0, 531,22, "outbrain.com", "/", "http:", "", 1369},
    --The Huffington post Online news website  
    { 0, 0, 0, 532,33, "huffingtonpost.com", "/", "http:", "", 1370},
    { 0, 0, 0, 532,33, "huffingtonpost.co.uk", "/", "http:", "", 1370},
    { 0, 0, 0, 532,33, "huffpost.com", "/", "http:", "", 1370},
    --Ask.com Search engine  
    { 0, 0, 0, 533,22, "ask.com", "/", "http:", "", 1371},
    --OptMD Web Advertising Service  
    { 0, 0, 0, 534,22, "optmd.com", "/", "http:", "", 1372},
    --GoDaddy Internet Domain registrar  
    { 0, 0, 0, 535,22, "godaddy.com", "/", "http:", "", 1373},
    --Etsy E-commerce for homemade items  
    { 0, 0, 0, 536,15, "etsy.com", "/", "http:", "", 1374},
    --Conduit Web portal to create community portal 
    { 0, 0, 0, 537,22, "conduit.com", "/", "http:", "", 1375},
    { 0, 0, 0, 537,22, "como.com", "/", "http:", "", 1375},
    { 0, 0, 0, 537,22, "getu.com", "/", "http:", "", 1375},
    --BBC Web portal for news update 
    { 0, 0, 0, 538,33, "bbc.co.uk", "/", "http:", "", 1376},
    { 0, 0, 0, 538,33, "bbci.co.uk", "/", "http:", "", 1376},
    { 0, 0, 0, 538,33, "bbc.com", "/", "http:", "", 1376},
    { 0, 0, 0, 538,33, "bbcamerica.com", "/", "http:", "", 1376},
    { 0, 0, 0, 538,33, "bbccanada.com", "/", "http:", "", 1376},
    { 0, 0, 0, 538,33, "cbeebies.com", "/", "http:", "", 1376},
    { 0, 0, 0, 538,33, "feeds.bbci.co.uk", "/", "http:", "", 1376},
    --Indeed Job Search Engine 
    { 0, 0, 0, 540,22, "indeed.com", "/", "http:", "", 1378},
    --Publishers Clearing House 
    { 0, 0, 0, 541,22, "pch.com", "/", "http:", "", 1379},
    --ATT  
    { 0, 0, 0, 542,22, "att.com", "/", "http:", "", 1380},
    { 0, 0, 0, 542,22, "att.net", "/", "http:", "", 1380},
    --Aweber  
    { 0, 0, 0, 543,22, "aweber.com", "/", "http:", "", 1381},
    -- FoxSports  
    { 0, 0, 0, 544,22, "foxsports.com", "/", "http:", "", 1382},
    --Searchnu 
    { 0, 0, 0, 545,22, "searchnu.com", "/", "http:", "", 1383},
    --Search-Result 
    { 0, 0, 0, 546,22, "search-result.com", "/", "http:", "", 1384},
    --Official Major League Baseball 
    { 0, 0, 0, 547,22, "mlb.com", "/", "http:", "", 1385},
    --RoadRunner
    { 0, 0, 0, 548,22, "rr.com", "/", "http:", "", 1386},
    --Drudge Report
    { 0, 0, 0, 549,33, "drudgereport.com", "/", "http:", "", 1387},
    -- Verizon Wireless
    { 0, 0, 0, 550,22, "verizonwireless.com", "/", "http:", "", 1388},
    { 0, 0, 0, 550,22, "vzw.com", "/", "http:", "", 1388},
    { 0, 0, 0, 550,22, "myvzw.com", "/", "http:", "", 1388},
    -- ABC Television network
    -- { 0, 0, 0, 551,33, "abcnews.go.com", "/", "http:", "", 1389},
    -- { 0, 0, 0, 551,33, "abcnews.com", "/", "http:", "", 1389},
    --{ 0, 0, 0, 551,33, "abc.go.com", "/", "http:", "", 1389},
    --{ 0, 0, 0, 551,33, "abc.com", "/", "http:", "", 1389},
    -- Wall Street Journal
    { 0, 0, 0, 552,33, "wsj.com", "/", "http:", "", 1390},
    { 0, 0, 0, 552,33, "wsj.net", "/", "http:", "", 1390},
    { 0, 0, 0, 552,33, "marketwatch.com", "/", "http:", "", 1390},
    { 0, 0, 0, 552,33, "barrons.com", "/", "http:", "", 1390},
    { 0, 0, 0, 552,33, "smartmoney.com", "/", "http:", "", 1390},
    { 0, 0, 0, 552,33, "allthingsd.com", "/", "http:", "", 1390},
    { 0, 0, 0, 552,33, "fins.com", "/", "http:", "", 1390},
    { 0, 0, 0, 552,33, "wsjradio.com", "/", "http:", "", 1390},
    --Daily Mail
    { 0, 0, 0, 553,33, "dailymail.co.uk", "/", "http:", "", 1391},
    --Amazon Web Services
    { 0, 0, 0, 554,22, "amazonaws.com", "/", "http:", "", 1392},
    { 0, 0, 0, 554,22, "aws.amazon.com", "/", "http:", "", 1392},
    --CloudFront  Content delivery to Amazon Web Services
    { 0, 0, 0, 555,22, "cloudfront.net", "/", "http:", "", 1393},
    --Me.com 
    --{ 0, 0, 0, 556,22, "me.com", "/", "http:", "", 1394},
    --Pandora Audio 
    { 0, 0, 0, 559,22, "pandora.com%&%audio", "/", "http:", "", 1711},
    --Sourcefire  
    { 0, 0, 0, 560,22, "sourcefire.com", "/", "http:", "", 1398},
    --Taobao
    { 0, 0, 0, 561,22, "taobao.com", "/", "http:", "", 1399},
    --Planetarium
    { 0, 0, 0, 562,22, "neave.com", "/planetarium/app/", "http:", "", 1400},
    --Engadget
    { 0, 0, 0, 563,22, "engadget.com", "/", "http:", "", 1401},
    { 0, 0, 0, 563,22, "engadget.com", "/", "http:", "", 1401},
    --Flipboard
    { 0, 0, 0, 564,33, "flipboard.com", "/", "http:", "", 1402},
    --TED
    { 0, 0, 0, 565,33, "ted.com", "/", "http:", "", 1403},
    { 0, 0, 0, 565,33, "tedhls-vod.hls.adaptive.level3.net", "/", "http:", "", 1403},
    --Flurry Analystics
    { 0, 0, 0, 566,22, "flurry.com", "/", "http:", "", 1406},
    --Ubuntu Software Center
    { 0, 0, 0, 567,22, "software-center.ubuntu.com", "/", "http:", "", 1408},
    --Ubuntu Update Manager
    { 0, 0, 0, 568,22, "us.archive.ubuntu.com", "/", "http:", "", 1409},
    { 0, 0, 0, 569,22, "download.eclipse.org", "/", "http:", "", 1412},
    { 0, 0, 0, 570,22, "marketplace.eclipse.org", "/", "http:", "", 1414},
    --Yahoo Mobile Apple API
    { 0, 0, 0, 571,22, "apple-mobile.query.yahooapis.com", "/", "http:", "", 1415},
    --NASA
    { 0, 0, 0, 572,22, "nasa.gov", "/", "http:", "", 1417},
    --NATO
    { 0, 0, 0, 573,22, "nato.int", "/", "http:", "", 1418},
    --AOL
    { 0, 0, 0, 574,22, "aol.com", "/", "http:", "", 1419},
    { 0, 0, 0, 574,22, "aol.co.uk", "/", "http:", "", 1419},
    { 0, 0, 0, 574,22, "aolcdn.com", "/", "http:", "", 1419},
    --NOAA
    { 0, 0, 0, 576,22, "noaa.gov", "/", "http:", "", 1420},
    --WeatherBug
    { 0, 0, 0, 577,22, "weatherbug.com", "/", "http:", "", 1421},
    { 0, 0, 0, 577,22, "wxbug.com", "/", "http:", "", 1421},
    --FC2
    { 0, 0, 0, 578,22, "fc2.com", "/", "http:", "", 1422},
    --Microsoft
    { 0, 0, 0, 579,22, "microsoft.com", "/", "http:", "", 1423},
    { 0, 0, 0, 579,22, "msftncsi.com", "/", "http:", "", 1423},
    --Google Adsense
    { 0, 0, 0, 580,22, "googlesyndication.com", "/", "http:", "", 1424},
    --AdNetwork.net
    { 0, 0, 0, 581,22, "adnetwork.net", "/", "http:", "", 1425},
    --Localytics
    { 0, 0, 0, 582,22, "localytics.com", "/", "http:", "", 1426},
    --Ovi
    { 0, 0, 0, 583,22, "ovi.com", "/", "http:", "", 1427},
    { 0, 0, 0, 583,22, "maps.nokia.com", "/", "http:", "", 1427},
    { 0, 0, 0, 583,22, "here.com", "/", "http:", "", 1427},
    { 0, 0, 0, 583,22, "here.sc", "/", "http:", "", 1427},
    { 0, 0, 0, 583,22, "maps.nlp.nokia.com", "/", "http:", "", 1427},
    --SymantecUpdates
    { 0, 0, 0, 584,22, "symantecliveupdate.com", "/", "http:", "", 1428},
    --Wolfram Alpha
    { 0, 0, 0, 585,22, "wolframalpha.com", "/", "http:", "", 1429},
    { 0, 0, 0, 585,22, "wolframcdn.com", "/", "http:", "", 1429},
    --Kuaibo 
    { 0, 0, 0, 586,22, "kuaibo.com", "/", "http:", "", 1449},
    { 0, 0, 0, 586,22, "searchstat.kuaibo.com", "/", "http:", "", 1449},

}

function DetectorInit(detectorInstance)

    gDetector = detectorInstance;

    gDetector:addHttpPattern(2, 5, 0, 200, 1, 0, 0, 'Arora/0.10.0', 3766, 1);
    gDetector:addHttpPattern(2, 5, 0, 201, 1, 0, 0, 'Browzar', 3777, 1);
    gDetector:addHttpPattern(2, 5, 0, 202, 1, 0, 0, 'CometBird', 3764, 1);
    gDetector:addHttpPattern(2, 5, 0, 203, 1, 0, 0, 'Comodo_Dragon', 1589, 1);
    gDetector:addHttpPattern(2, 5, 0, 204, 1, 0, 0, 'Crazy Browser', 3762, 1);
    gDetector:addHttpPattern(2, 5, 0, 205, 1, 0, 0, 'GreenBrowser', 3763, 1);
    gDetector:addHttpPattern(2, 5, 0, 206, 1, 0, 0, 'PaleMoon', 1592, 1);
    gDetector:addHttpPattern(2, 5, 0, 207, 1, 0, 0, 'Wyzo', 1593, 1);
    gDetector:addHttpPattern(2, 5, 0, 293, 1, 0, 0, 'LiveUpdate', 1428, 1);

    if gDetector.addAppUrl then
        for i,v in ipairs(gUrlPatternList) do
            gDetector:addAppUrl(v[1],v[2],v[3],v[4],v[5],v[6],v[7],v[8],v[9],v[10]);
        end
    end
    return gDetector;
end

function DetectorClean()
end

