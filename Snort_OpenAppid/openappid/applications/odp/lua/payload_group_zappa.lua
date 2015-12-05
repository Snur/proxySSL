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
detection_name: Payload Group "Zappp"
version: 8
description: Group of payload detectors.
bundle_description: $VAR1 = {
          'Brilig' => 'Advertisement site.',
          'AOL Ads' => 'AOL advertisement site.',
          'Datei.to' => 'German file sharing service.',
          'AD-X Tracking' => 'Data analysis and monitor ad related traffic tarfette for mobile application.',
          'Chango' => 'Advertisement site.',
          '12306.cn' => 'China Railway online customer service.',
          'Yesky' => 'Chinese IT portal.',
          'Connexity' => 'Advertisement site.',
          'CloudFlare' => 'Advertisement site.',
          'AdRoll' => 'Online advertising and Retargetting website vistor.',
          'Android.com' => 'Android web site.',
          'Commvault' => 'Enterprise data backup and storage management software.',
          'Brothersoft' => 'Free software download site.',
          'Aggregate Knowledge' => 'Advertisement site.',
          '100ye.com' => 'Chinese search portal.',
          'Shareman' => 'Traffic generated from chat and file transfer service by Shareman client.',
          '33Across' => 'Social ad delivery service.',
          'Clip2Net Upload' => 'Copying a local file to Clip2Net.',
          'Bazaarvoice' => 'Online service that provides data and analystics to brands/customer.',
          'TISTORY' => 'Korean Blog publishing service.',
          'DataLogicx' => 'Advertisement site.',
          'Clip2Net' => 'Yandex cloud storage that acts like a clipboard.',
          'Blokus' => 'Online spatial strategy board game.',
          '24/7 Media' => 'Advertisement site.',
          '126.com' => 'Free webmail system.',
          'Chinaren' => 'Chinese social networking site.',
          'MapleStory' => 'Online game portal.',
          'Aliyun' => 'Chinese web portal.',
          'Allegro.pl' => 'Polish auction website.',
          'Classmates' => 'Social networking site that allows schoolmates to connect via yearbook photograph.',
          'Mendeley' => 'A tool for sharing, storing, and organizing reference material such as PDFs.',
          'LogMeIn Rescue' => 'A remote desktop support tool.',
          'China News' => 'Chinese news site.',
          'eFax' => 'Internet fax service.',
          'ClickBooth' => 'Advertisement site.',
          'Admeld' => 'Ad delivery company servicing online publishers.',
          'Compuware' => 'Advertisement site.',
          'Adtegrity' => 'Advertisement site.',
          'Concur' => 'Business travel site.',
          'Astraweb' => 'A Usenet/newsgroup service provider.',
          'Alibaba' => 'International trade site.',
          'Criteo' => 'Advertisement site.',
          'ADMETA' => 'Advertisement site.',
          'Admin5' => 'Chinese directory of web admins.',
          'cXense' => 'Advertisement site.',
          '39.net' => 'Chinese health information web portal.',
          'AdF.ly' => 'URL shortening service.',
          'Adometry' => 'Advertisement site.',
          'Amobee' => 'Advertisement site.',
          'AdXpose' => 'Advertisement site.',
          'AdReady' => 'Advertisement site.',
          'Ado Tube' => 'Video advertising solution.',
          'Compete' => 'Data-driven marketing and advertising platform.',
          'Autohome.com.cn' => 'Chinese website targetted for automotive related information.',
          'ZumoDrive' => 'Cloud storage and file synchronization service provider.',
          'AudienceScience' => 'Online marketing.',
          '247 Inc.' => 'Advertisement site.',
          'About.com' => 'A site that provides original information on various subjects.',
          'ADNStream' => 'Spanish video streaming site.',
          'AdGear' => 'Advertisement site.',
          'ClickTale' => 'Advertisement site.',
          'Bizo' => 'Advertisement site.',
          'AppNexus' => 'Real-time advertising services.',
          'Brightroll' => 'Advertisement site.',
          'DeNA websites' => 'Traffic generated by browsing DeNA Comm website and some other sites that belong to DeNA.',
          'Caraytech' => 'Advertisement site.',
          'Lineage' => 'Online game for multiplayer.',
          'adSage' => 'Advertisement site.',
          'Egloos' => 'Korean blog host.',
          'CBS Interactive' => 'Division of CBS Corporation which coordinates ad sales and television programs together.',
          'Casale' => 'Advertisement site.',
          'Sina Video' => 'Video streaming from Chinese news/social website Sina.',
          'China.com' => 'Chinese social networking site.',
          'Atlas Advertiser Suite' => 'Tools for online advertising.',
          'Aptean' => 'Enterprise software company.',
          'CNZZ' => 'Advertisement site.',
          'ezhelp' => 'Allows remote access.',
          'Adtech' => 'Advertisement site.',
          'BlueKai' => 'Data-driven online marketing.',
          'contnet' => 'Advertisement site.',
          'AdSame' => 'Chinese digital marketting platform.',
          'Brighttalk' => 'Online webinar and video provider.',
          '2345.com' => 'Web portal.',
          'AdJuggler' => 'Advertisement site.',
          'Adconion Media Group' => 'Multi-channel ad delivery company.',
          'Booking.com' => 'Online travel reservation site.',
          'Aizhan' => 'Chinese web portal.',
          'DioDeo' => 'Korean Entertainment news.',
          'Answers.com' => 'A site that provides original answers to questions.',
          'Bloomberg' => 'Financial news and research.',
          'Crowd Science' => 'Advertisement site.',
          'Chinauma' => 'Advertisement site.',
          'Bet365' => 'Online gambling website.',
          'Connextra' => 'Advertisement site.',
          'Boxcar.io' => 'Social media and RSS aggregator. Different site than boxcar.com.',
          '4399.com' => 'Chinese gaming website.',
          'Admasters' => 'Advertisement site.',
          '17173.com' => 'Chinese social networking site.',
          'Cognitive Match' => 'Advertisement site.'
        };

--]]

require "DetectorCommon"


local DC = DetectorCommon

DetectorPackageInfo = {
    name =  "payload_group_zappa",
    proto =  DC.ipproto.tcp,
    client = {
        init =  'DetectorInit',
        clean =  'DetectorClean',
        minimum_matches =  1
    }
}

gUrlPatternList = {
     -- Clip2Net
    { 0, 0, 0, 1387, 9, "clip2net.com", "/", "http:", "", 3782},
    -- Clip2Net Upload
    { 0, 0, 0, 1388, 9, "clip2net.com", "/upload", "http:", "", 3783},
    -- LogMeIn Rescue
    { 0, 0, 0, 1389, 8, "secure.logmeinrescue.com", "/", "http:", "", 3784},
    -- Mendeley
    { 0, 0, 0, 1390, 12, "mendeley.com", "/", "http:", "", 3785},
     -- Blokus
    { 0, 0, 0, 1391, 20, "blokus.com", "/", "http:", "", 2482},
    { 0, 0, 0, 1391, 20, "blokus.refreshed.be", "/", "http:", "", 2482},
     -- Bloomberg
    { 0, 0, 0, 1392, 33, "bloomberg.com", "/", "http:", "", 1259},
    { 0, 0, 0, 1392, 33, "bloombergview.com", "/", "http:", "", 1259},
    { 0, 0, 0, 1392, 33, "bloomberg.net", "/", "http:", "", 1259},
    { 0, 0, 0, 1392, 33, "businessweek.com", "/", "http:", "", 1259},
    { 0, 0, 0, 1392, 33, "bloombergtradebook.com", "/", "http:", "", 1259},
    { 0, 0, 0, 1392, 33, "bloombergbriefs.com", "/", "http:", "", 1259},
    { 0, 0, 0, 1392, 33, "bloombergindexes.com", "/", "http:", "", 1259},
    { 0, 0, 0, 1392, 33, "bloombergsef.com", "/", "http:", "", 1259},
    { 0, 0, 0, 1392, 33, "bna.com", "/", "http:", "", 1259},
    { 0, 0, 0, 1392, 33, "bgov.com", "/", "http:", "", 1259},
    { 0, 0, 0, 1392, 33, "bloomberglaw.com", "/", "http:", "", 1259},
    { 0, 0, 0, 1392, 33, "bloomberglink.com", "/", "http:", "", 1259},
    { 0, 0, 0, 1392, 33, "bloombergsports.com", "/", "http:", "", 1259},
     -- BlueKai
    { 0, 0, 0, 1393, 30, "bluekai.com", "/", "http:", "", 2452},
     -- Booking.com
    { 0, 0, 0, 1394, 37, "booking.com", "/", "http:", "", 2600},
    { 0, 0, 0, 1394, 37, "workingatbooking.com", "/", "http:", "", 2600},
     -- Bazaarvoice
    { 0, 0, 0, 1395, 16, "bazaarvoice.com", "/", "http:", "", 2938},
     -- DeNA websites
    { 0, 0, 0, 1396, 22, "dena.com", "/", "http:", "", 2946},
    { 0, 0, 0, 1396, 22, "mbga.jp", "/", "http:", "", 2946},
    { 0, 0, 0, 1396, 22, "gr-oo-vy.com", "/", "http:", "", 2946},
    { 0, 0, 0, 1396, 22, "ssl.co-mm.com", "/", "http:", "", 2946},
    { 0, 0, 0, 1396, 22, "dena-ec.com", "/", "http:", "", 2946},
    { 0, 0, 0, 1396, 22, "aumall.jp", "/", "http:", "", 2946},
    { 0, 0, 0, 1396, 22, "mbok.jp", "/", "http:", "", 2946},
    { 0, 0, 0, 1396, 22, "netsea.jp", "/", "http:", "", 2946},
    { 0, 0, 0, 1396, 22, "paygent.co.jp", "/", "http:", "", 2946},
    { 0, 0, 0, 1396, 22, "estar.jp", "/", "http:", "", 2946},
    { 0, 0, 0, 1396, 22, "smcb.jp", "/", "http:", "", 2946},
    { 0, 0, 0, 1396, 22, "skygate.co.jp", "/", "http:", "", 2946},
    { 0, 0, 0, 1396, 22, "arukikata.com", "/", "http:", "", 2946},
    { 0, 0, 0, 1396, 22, "sougouhoken.jp", "/", "http:", "", 2946},
    { 0, 0, 0, 1396, 22, "mobage.com", "/", "http:", "", 2946},
    { 0, 0, 0, 1396, 22, "mobage.cn", "/", "http:", "", 2946},
    { 0, 0, 0, 1396, 22, "mobage.kr", "/", "http:", "", 2946},
    { 0, 0, 0, 1396, 22, "dena.jp", "/", "http:", "", 2946},
    { 0, 0, 0, 1396, 22, "daum-mobage.kr", "/", "http:", "", 2946},
    { 0, 0, 0, 1396, 22, "mangabox.me", "/", "http:", "", 2946},
    { 0, 0, 0, 1396, 22, "showroom-live.com", "/", "http:", "", 2946},
    { 0, 0, 0, 1396, 22, "applizemi.com", "/", "http:", "", 2946},
    { 0, 0, 0, 1396, 22, "chirashiru.jp", "/", "http:", "", 2946},
    { 0, 0, 0, 1396, 22, "gbooks.jp", "/", "http:", "", 2946},
    { 0, 0, 0, 1396, 22, "mycode.jp", "/", "http:", "", 2946},
     -- Sina Video
    { 0, 0, 0, 1397, 13, "video.sina.com", "/", "http:", "", 2948},
     -- 12306.cn
    { 0, 0, 0, 1399, 37, "12306.cn", "/", "http:", "", 1205},
     -- 126.com
    { 0, 0, 0, 1400, 4, "126.com", "/", "http:", "", 1206},
     -- 17173.com
    { 0, 0, 0, 1401, 5, "17173.com", "/", "http:", "", 2385},
     -- 2345.com
    { 0, 0, 0, 1402, 22, "2345.com", "/", "http:", "", 2346},
    { 0, 0, 0, 1402, 22, "2345.cn", "/", "http:", "", 2346},
     -- 24/7 Media
    { 0, 0, 0, 1403, 15, "247media.fr", "/", "http:", "", 2493},
    { 0, 0, 0, 1403, 15, "247media.com", "/", "http:", "", 2493},
     -- 247 Inc.
    { 0, 0, 0, 1404, 15, "247-inc.com", "/", "http:", "", 2492},
     -- 33Across
    { 0, 0, 0, 1405, 15, "33across.com", "/", "http:", "", 2419},
    { 0, 0, 0, 1405, 15, "tynt.com", "/", "http:", "", 2419},
     -- 39.net
    { 0, 0, 0, 1406, 22, "39.net", "/", "http:", "", 1207},
     -- 4399.com
    { 0, 0, 0, 1407, 20, "4399.com", "/", "http:", "", 1256},
    { 0, 0, 0, 1407, 20, "4399.cn", "/", "http:", "", 1256},
     -- About.com
    { 0, 0, 0, 1408, 22, "about.com", "/", "http:", "", 1167},
     -- Ad Master
    { 0, 0, 0, 1409, 22, "admasters.com", "/", "http:", "", 2565},
     -- AD-X Tracking
    { 0, 0, 0, 1410, 22, "adxtracking.com", "/", "http:", "", 2850},
     -- Adconion Media Group
    { 0, 0, 0, 1411, 22, "adconion.com", "/", "http:", "", 2414},
     -- AdF.ly
    { 0, 0, 0, 1412, 15, "adf.ly", "/", "http:", "", 1257},
     -- AdGear
    { 0, 0, 0, 1413, 22, "adgear.com", "/", "http:", "", 2500},
     -- AdJuggler
    { 0, 0, 0, 1414, 22, "adjuggler.com", "/", "http:", "", 2575},
     -- Admeld
    { 0, 0, 0, 1415, 22, "admeld.com", "/", "http:", "", 2454},
    { 0, 0, 0, 1415, 22, "google.com", "/doubleclick", "http:", "", 2454},
    -- ADMETA
    { 0, 0, 0, 1416, 22, "admeta.com", "/", "http:", "", 2569},
     -- Admin5
    { 0, 0, 0, 1417, 22, "admin5.com", "/", "http:", "", 1258},
    { 0, 0, 0, 1417, 22, "admin5.net", "/", "http:", "", 1258},
    { 0, 0, 0, 1417, 22, "admin5.cn", "/", "http:", "", 1258},
     -- ADNStream
    { 0, 0, 0, 1418, 19, "adnstream.com", "/", "http:", "", 2370},
     -- Ado Tube
    { 0, 0, 0, 1419, 22, "adotube.com", "/", "http:", "", 2847},
     -- Adometry
    { 0, 0, 0, 1420, 22, "adometry.com", "/", "http:", "", 2556},
    { 0, 0, 0, 1420, 22, "clickforensics.com", "/", "http:", "", 2556},
     -- AdReady
    { 0, 0, 0, 1421, 22, "adready.com", "/", "http:", "", 2497},
     -- AdRoll
    { 0, 0, 0, 1422, 22, "adroll.com", "/", "http:", "", 2848},
     -- adSage
    { 0, 0, 0, 1423, 22, "adsage.com", "/", "http:", "", 2491},
    { 0, 0, 0, 1423, 22, "adsage.cn", "/", "http:", "", 2491},
     -- AdSame
    { 0, 0, 0, 1424, 22, "adsame.com", "/", "http:", "", 2849},
     -- Adtech
    { 0, 0, 0, 1425, 22, "ad-tech.com", "/", "http:", "", 2503},
    { 0, 0, 0, 1425, 22, "adtechchina.com", "/", "http:", "", 2503},
    { 0, 0, 0, 1425, 22, "adtechaustralia.com", "/", "http:", "", 2503},
    { 0, 0, 0, 1425, 22, "adtech-kyushu.com", "/", "http:", "", 2503},
    { 0, 0, 0, 1425, 22, "ad-techlondon.co.uk", "/", "http:", "", 2503},
    { 0, 0, 0, 1425, 22, "ad-tech.sg", "/", "http:", "", 2503},
    { 0, 0, 0, 1425, 22, "adtechasean.com", "/", "http:", "", 2503},
     -- AdXpose
    { 0, 0, 0, 1426, 22, "adxpose.com", "/", "http:", "", 2538},
     -- Amobee
    { 0, 0, 0, 1427, 15, "amobee.com", "/", "http:", "", 2504},
     -- Aggregate Knowledge
    { 0, 0, 0, 1428, 22, "aggregateknowledge.com", "/", "http:", "", 2547},
     -- Alibaba
    { 0, 0, 0, 1429, 15, "alibaba.com", "/", "http:", "", 2386},
    { 0, 0, 0, 1429, 15, "alibabagroup.com", "/", "http:", "", 2386},
     -- Aliyun
    { 0, 0, 0, 1430, 22, "aliyun.com", "/", "http:", "", 2389},
     -- Allegro.pl
    { 0, 0, 0, 1431, 15, "allegro.pl", "/", "http:", "", 2851},
     -- Aizhan
    { 0, 0, 0, 1432, 22, "aizhan.com", "/", "http:", "", 1208},
     -- Android.com
    { 0, 0, 0, 1433, 15, "android.com", "/", "http:", "", 2470},
     -- Answers.com
    { 0, 0, 0, 1434, 22, "answers.com", "/", "http:", "", 1168},
     -- AOL Ads
    { 0, 0, 0, 1435, 22, "advertising.aol.com", "/", "http:", "", 2578},
     -- Bizo
    { 0, 0, 0, 1436, 22, "bizo.com", "/", "http:", "", 2557},
    { 0, 0, 0, 1436, 22, "bizographics.com", "/", "http:", "", 2557},
     -- Shareman
    { 0, 0, 0, 1437, 9, "shareman.tv", "/", "http:", "", 2918},
    -- -- Sparrow
    -- { 0, 0, 0, 1438, 12, "sparrowmailapp.com", "/", "http:", "", 3788},
    -- eFax 
    { 0, 0, 0, 1439, 12, "efax.com", "/", "http:", "", 3789},
    -- Yesky
    { 0, 0, 0, 1440, 12, "yesky.com", "/", "http:", "", 3790},
    -- 100ye.com
    { 0, 0, 0, 1441, 12, "100ye.com", "/", "http:", "", 3791},
    -- AppNexus
    { 0, 0, 0, 1443, 22, "appnexus.com", "/", "http:", "", 2413},
    { 0, 0, 0, 1443, 22, "appnexus.net", "/", "http:", "", 2413},
    { 0, 0, 0, 1443, 22, "alenty.com", "/", "http:", "", 2413},
    -- Aptean
    { 0, 0, 0, 1444, 22, "aptean.com", "/", "http:", "", 2581},
    -- Astraweb
    { 0, 0, 0, 1445, 33, "astraweb.com", "/", "http:", "", 38},
    -- Atlas Advertiser Suite
    { 0, 0, 0, 1446, 22, "atlassolutions.com", "/", "http:", "", 2456},
    -- AudienceScience
    { 0, 0, 0, 1447, 22, "audiencescience.com", "/", "http:", "", 2467},
    -- Autohome.com.cn
    { 0, 0, 0, 1448, 36, "autohome.com.cn", "/", "http:", "", 2852},
    -- Bet365
    { 0, 0, 0, 1451, 22, "bet365.com", "/", "http:", "", 1209},
    -- Adtegrity
    { 0, 0, 0, 1452, 22, "adtegrity.com", "/", "http:", "", 2577},
    -- Boxcar.io
    { 0, 0, 0, 1453, 6, "boxcar.io", "/", "http:", "", 2605},
    -- Brightroll
    { 0, 0, 0, 1454, 22, "brightroll.com", "/", "http:", "", 2558},
    -- Brighttalk
    { 0, 0, 0, 1455, 8, "brighttalk.com", "/", "http:", "", 1211},
    -- Brilig
    { 0, 0, 0, 1456, 22, "brilig.com", "/", "http:", "", 2511},
    -- Brothersoft
    { 0, 0, 0, 1457, 22, "brothersoft.com", "/", "http:", "", 1210},
    -- Caraytech
    { 0, 0, 0, 1458, 22, "caraytech.com", "/", "http:", "", 2573},
    -- Casale
    { 0, 0, 0, 1459, 22, "casalemedia.com", "/", "http:", "", 2512},
    { 0, 0, 0, 1459, 22, "indexexchange.com", "/", "http:", "", 2512},
    { 0, 0, 0, 1459, 22, "medianet.com", "/", "http:", "", 2512},
    -- CBS Interactive
    { 0, 0, 0, 1460, 33, "cbsinteractive.com", "/", "http:", "", 2354},
    { 0, 0, 0, 1460, 33, "cbspressexpress.com", "/", "http:", "", 2354},
    -- Chango
    { 0, 0, 0, 1461, 22, "chango.com", "/", "http:", "", 2513},
    -- China News
    { 0, 0, 0, 1462, 33, "chinanews.com", "/", "http:", "", 2610},
    { 0, 0, 0, 1462, 33, "ecns.cn", "/", "http:", "", 2610},
    { 0, 0, 0, 1462, 33, "chinanews.com.cn", "/", "http:", "", 2610},
    -- China.com
    { 0, 0, 0, 1463, 22, "china.com", "/", "http:", "", 2371},
    -- Chinaren
    { 0, 0, 0, 1464, 5, "chinaren.com", "/", "http:", "", 2384},
    -- Chinauma
    { 0, 0, 0, 1465, 22, "chinauma.com", "/", "http:", "", 2490},
    -- Classmates
    { 0, 0, 0, 1466, 5, "classmates.com", "/", "http:", "", 1169},
    -- ClickBooth
    { 0, 0, 0, 1467, 22, "clickbooth.com", "/", "http:", "", 2585},
    -- ClickTale
    { 0, 0, 0, 1468, 22, "clicktale.com", "/", "http:", "", 2502},
    -- CloudFlare
    { 0, 0, 0, 1469, 22, "cloudflare.com", "/", "http:", "", 2535},
    -- CNZZ
    { 0, 0, 0, 1470, 22, "cnzz.com", "/", "http:", "", 2597},
    -- Cognitive Match
    { 0, 0, 0, 1471, 22, "cognitivematch.com", "/", "http:", "", 2528},
    -- Compete
    { 0, 0, 0, 1472, 22, "compete.com", "/", "http:", "", 2458},
    -- Compuware
    { 0, 0, 0, 1473, 22, "compuware.com", "/", "http:", "", 2579},
    -- Commvault
    { 0, 0, 0, 1474, 9, "commvault.com", "/", "http:", "", 96},
    { 0, 0, 0, 1474, 9, "commvault.be", "/", "http:", "", 96},
    { 0, 0, 0, 1474, 9, "commvault.ca", "/", "http:", "", 96},
    { 0, 0, 0, 1474, 9, "commvault.cl", "/", "http:", "", 96},
    { 0, 0, 0, 1474, 9, "commvault.fr", "/", "http:", "", 96},
    { 0, 0, 0, 1474, 9, "commvault.de", "/", "http:", "", 96},
    { 0, 0, 0, 1474, 9, "commvault.in", "/", "http:", "", 96},
    { 0, 0, 0, 1474, 9, "commvault.it", "/", "http:", "", 96},
    { 0, 0, 0, 1474, 9, "commvault.jp", "/", "http:", "", 96},
    { 0, 0, 0, 1474, 9, "commvault.nl", "/", "http:", "", 96},
    { 0, 0, 0, 1474, 9, "commvault.ru", "/", "http:", "", 96},
    { 0, 0, 0, 1474, 9, "commvault.co.za", "/", "http:", "", 96},
    { 0, 0, 0, 1474, 9, "commvault.se", "/", "http:", "", 96},
    { 0, 0, 0, 1474, 9, "commvault.ch", "/", "http:", "", 96},
    { 0, 0, 0, 1474, 9, "commvault.co.uk", "/", "http:", "", 96},
    -- Concur
    { 0, 0, 0, 1476, 15, "concur.com", "/", "http:", "", 2601},
    { 0, 0, 0, 1476, 15, "concur.ca", "/", "http:", "", 2601},
    { 0, 0, 0, 1476, 15, "concur.de", "/", "http:", "", 2601},
    { 0, 0, 0, 1476, 15, "concur.nl", "/", "http:", "", 2601},
    { 0, 0, 0, 1476, 15, "concur.fr", "/", "http:", "", 2601},
    { 0, 0, 0, 1476, 15, "concur.co.uk", "/", "http:", "", 2601},
    { 0, 0, 0, 1476, 15, "concur.co.in", "/", "http:", "", 2601},
    { 0, 0, 0, 1476, 15, "concur.co.jp", "/", "http:", "", 2601},
    -- Connexity
    { 0, 0, 0, 1477, 22, "connexity.com", "/", "http:", "", 2555},
    -- Connextra
    { 0, 0, 0, 1478, 22, "connextra.com", "/", "http:", "", 2529},
    { 0, 0, 0, 1478, 22, "connextra.net", "/", "http:", "", 2529},
    { 0, 0, 0, 1478, 22, "betgenius.com", "/", "http:", "", 2529},
    -- contnet
    { 0, 0, 0, 1479, 22, "contnet.de", "/", "http:", "", 2566},
    { 0, 0, 0, 1479, 22, "contnet.com", "/", "http:", "", 2566},
    -- Criteo
    { 0, 0, 0, 1480, 22, "criteo.com", "/", "http:", "", 2514},
    -- Crowd Science
    { 0, 0, 0, 1481, 22, "crowdscience.com", "/", "http:", "", 2591},
    { 0, 0, 0, 1481, 22, "yume.com", "/", "http:", "", 2591},
    -- cXense
    { 0, 0, 0, 1482, 22, "cxense.com", "/", "http:", "", 2572},
    -- DataLogicx
    { 0, 0, 0, 1483, 22, "datalogix.com", "/", "http:", "", 2542},
    -- Datei.to
    { 0, 0, 0, 1484, 9, "datei.to", "/", "http:", "", 1260},
    -- TISTORY
    { 0, 0, 0, 1485, 22, "tistory.com", "/", "http:", "", 3798},
    -- DioDeo
    { 0, 0, 0, 1486, 22, "diodeo.jp", "/", "http:", "", 3799},
    { 0, 0, 0, 1486, 22, "diodeo.com", "/", "http:", "", 3799},
    -- Egloos
    { 0, 0, 0, 1487, 22, "egloos.com", "/", "http:", "", 3800},
    -- Lineage
    { 0, 0, 0, 1488, 22, "lineage2.com", "/", "http:", "", 3801},
    { 0, 0, 0, 1488, 22, "lineage.com", "/", "http:", "", 3801},
    { 0, 0, 0, 1488, 22, "lineage.plaync.com", "/", "http:", "", 3801},
    -- MapleStory
    { 0, 0, 0, 1489, 22, "maplestory.nexon.net", "/", "http:", "", 3802},
    { 0, 0, 0, 1489, 22, "maplestory.nexoneu.com", "/", "http:", "", 3802},
    -- ezhelp
    { 0, 0, 0, 1490, 22, "ezhelp.co.kr", "/", "http:", "", 3803},
}

function DetectorInit(detectorInstance)

    gDetector = detectorInstance;

    -- Clip2net
    gDetector:addHttpPattern(2, 5, 0, 461, 21, 0, 0, 'Clit2NetUTF', 3782, 1);
    -- LogMeInRescue
    gDetector:addHttpPattern(2, 5, 0, 462, 8, 0, 0, 'LogMeIn Rescue', 3784, 1);
    -- Mendeley
    gDetector:addHttpPattern(2, 5, 0, 463, 21, 0, 0, 'Mendeley Desktop', 3785, 1);
    -- ZumoDrive
    gDetector:addHttpPattern(2, 5, 0, 464, 21, 0, 0, 'ZumoDrive', 3787, 1);
    -- -- Sparrow  
    -- gDetector:addHttpPattern(2, 5, 0, 465, 2, 0, 0, 'Sparrow', 3788, 1);
    -- eFax  
    gDetector:addHttpPattern(2, 5, 0, 466, 2, 0, 0, 'eFax Messenger', 3789, 1);

    if gDetector.addAppUrl then
        for i,v in ipairs(gUrlPatternList) do
            gDetector:addAppUrl(v[1],v[2],v[3],v[4],v[5],v[6],v[7],v[8],v[9],v[10]);
        end
    end

    return gDetector;
end

function DetectorClean()
end

