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
detection_name: Payload Group "BITTERS"
version: 3
description: Group of payload detectors.
bundle_description: $VAR1 = {
          'Integromedb Crawler' => 'Medical data web crawler.',
          'Nexon' => 'Online video games.',
          'Remote Ctrl from iPhone/iPad' => 'Mobile app for iPhone/iPad to control other devices like Apple TV.',
          'EarthCam' => 'Network of live cameras in public places around the world.',
          'PHP-SOAP' => 'SOAP client written in PHP.',
          'Dropcam' => 'Cloud-based remote Wifi video with voice chat from either side.',
          'GTA Online' => 'Grand Theft Auto V, Video game series created by Rockstar Games.',
          'msnbot' => 'Microsoft bot meant to scan the web for documents. Precursor to Bingbot.',
          'BesTV' => 'Shangai Media Group television station, pioneer in China\'s IPTV and Internet TV.',
          'SimplePie' => 'RSS Feed.',
          'OpenDNS' => 'DNS service for reliability and security for internet surfers.',
          'Zippyshare' => 'File hosting site.',
          'RealNetworks' => 'Websites for RealNetworks, the streaming media company.',
          'MixBit' => 'Create and edit videos from mobile.',
          'Last.fm' => 'A social networking music streaming site.',
          'SHOWTIME ANYTIME' => 'On-Demand access for Showtime series, movies and other entertainments.',
          'Gizmodo' => 'Blogs about design and technology.',
          'Safari' => 'Apple\'s web browser.',
          'blinkx' => 'Video search engine.',
          'Arizona Public Media' => 'Web portal by University of Arizona to connect people.',
          'iBooks' => 'Mobile app for download and read e-books.',
          'iTunes Store' => 'An Apple store for music and movies on iOS devices. Different than Mac App Store and Apple App Store.',
          'Sky.com' => 'Web portal for news.',
          'Pingdom' => 'A website monitoring crawler.',
          'EA Games' => 'Web portal for Electronics Arts, a video games distributor.',
          'Android Asynchronous Http Client' => 'Asynchronous callback-based HTTP client for Android.',
          'Rockstar Games' => 'Developer and Publisher of video games.',
          'Twitter4J' => 'A Java library for the Twitter API.',
          'PointRoll' => 'Advertising company.',
          'Copy' => 'Cloud storage for sharing files.',
          'Sophos Live Protection' => 'Anti-Malware software.',
          'RealPlayer Cloud' => 'RealNetworks cloud player.',
          'SecurityKiss' => 'Security Kiss anonymizer proxy.',
          'Drupal' => 'Open source to content management service.',
          'Garmin' => 'Offcial website for Garmin, GPS manufacturer.',
          'Fuyin.TV' => 'Chinese website for Christians.',
          'TomTom' => 'Gadget which provides traffic related details.',
          'TVonline.cc' => 'Web portal agregating most TV shows/series.'
        };

--]]

require "DetectorCommon"


local DC = DetectorCommon

DetectorPackageInfo = {
    name =  "payload_group_bitters",
    proto =  DC.ipproto.tcp,
    client = {
        init =  'DetectorInit',
        clean =  'DetectorClean',
        minimum_matches =  1
    }
}

--serviceId, clientId, ClientType, PayloadId, PayloadType, hostPattern, pathPattern, schemePattern, queryPattern
gUrlPatternList = {

    -- MixBit
    { 0, 0, 0, 1228, 22, "mixbit.com", "/", "http:", "", 2710},
    -- Fuyin.TV
    { 0, 0, 0, 1216, 22, "fuyin.tv", "/", "http:", "", 2696},
    -- SHOWTIME ANYTIME
    { 0, 0, 0, 1217, 22, "sho.com", "/", "http:", "", 2697},
    { 0, 0, 0, 1217, 22, "showtimeanytime.com", "/", "http:", "", 2697},
    -- Drupal 
    { 0, 0, 0, 1218, 22, "drupal.org", "/", "http:", "", 2698},
    -- Sky.com
    { 0, 0, 0, 1219, 22, "sky.com", "/", "http:", "", 2699},
    { 0, 0, 0, 1219, 22, "news.sky.com", "/", "http:", "", 2699},
    { 0, 0, 0, 1219, 22, "skynews.com", "/", "http:", "", 2699},
    { 0, 0, 0, 1219, 22, "skysports.com", "/", "http:", "", 2699},
    -- Arizona Public Media
    { 0, 0, 0, 1220, 22, "azpm.org", "/", "http:", "", 2700},
    -- EA Games
    { 0, 0, 0, 1221, 22, "ea.com", "/", "http:", "", 2701},
    { 0, 0, 0, 1221, 22, "eamobile.com", "/", "http:", "", 2701},
    { 0, 0, 0, 1221, 22, "easports.com", "/", "http:", "", 2701},
    { 0, 0, 0, 1221, 22, "maxis.com", "/", "http:", "", 2701},
    { 0, 0, 0, 1221, 22, "thesims.com", "/", "http:", "", 2701},
    { 0, 0, 0, 1221, 22, "simcity.com", "/", "http:", "", 2701},
    -- Copy
    { 0, 0, 0, 1222, 22, "copy.com", "/", "http:", "", 2702},
    -- TomTom
    { 0, 0, 0, 1223, 22, "tomtom.com", "/", "http:", "", 2703},
    -- OpenDNS
    { 0, 0, 0, 1224, 22, "opendns.com", "/", "http:", "", 2704},
    -- Gizmodo
    { 0, 0, 0, 1225, 22, "gizmodo.com", "/", "http:", "", 2705},
    -- SimplePie
    { 0, 0, 0, 1226, 22, "simplepie.org", "/", "http:", "", 2706},
    -- Sophos Live Protection
    { 0, 0, 0, 1227, 22, "sophosxl.net", "/", "http:", "", 2707},
    { 0, 0, 0, 1227, 22, "sophos.com", "/", "http:", "", 2707},
    -- RealNetworks
    { 0, 0, 0, 1232, 13, "real.com", "/", "http:", "", 2726},
    -- EarthCam
    { 0, 0, 0, 1233, 22, "earthcam.com", "/", "http:", "", 2604},
    -- iBooks
    { 0, 0, 0, 1234, 22, "ibook.info", "/", "http:", "", 2724},
    -- blinkx
    { 0, 0, 0, 1235, 22, "blinkx.com", "/", "http:", "", 2728},
    -- Garmin
    { 0, 0, 0, 1236, 22, "garmin.com", "/", "http:", "", 2729},
    { 0, 0, 0, 1236, 22, "garmincdn.com", "/", "http:", "", 2729},
    --  Ink File Picker
    -- { 0, 0, 0, 1237, 9, "inkfilepicker.com", "/", "http:", "", 2730},
    --  MuchShare
    -- { 0, 0, 0, 1238, 9, "muchshare.net", "/", "http:", "", 2731},
    --  Nexon
    { 0, 0, 0, 1239, 20, "nexon.net", "/", "http:", "", 2732},
    --  PointRoll
    { 0, 0, 0, 1240, 22, "pointroll.com", "/", "http:", "", 2733},
    --  TVonline.cc
    { 0, 0, 0, 1241, 22, "tvonline.cc", "/", "http:", "", 2735},
    { 0, 0, 0, 1241, 22, "tvdb.cc", "/", "http:", "", 2735},
    --  BesTV
    { 0, 0, 0, 1242, 22, "bestv.com.cn", "/", "http:", "", 2737},
    --  Zippyshare
    { 0, 0, 0, 1243, 22, "zippyshare.com", "/", "http:", "", 2738},
    --  Dropcam
    { 0, 0, 0, 1244, 22, "dropcam.com", "/", "http:", "", 2739},
    --  Grand Theft Auto
    { 0, 0, 0, 1245, 22, "rockstargames.com", "/gta5/", "http:", "", 2740},
    -- Rockstar games
    { 0, 0, 0, 1246, 22, "rockstargames.com", "/", "http:", "", 2747},
    { 0, 0, 0, 1246, 22, "rockstartoronto.com", "/", "http:", "", 2747},
    { 0, 0, 0, 1246, 22, "rockstartoronto.com", "/", "http:", "", 2747},
    { 0, 0, 0, 1246, 22, "rockstarsandiego.com", "/", "http:", "", 2747},
    { 0, 0, 0, 1246, 22, "rockstarnorth.com", "/", "http:", "", 2747},
    { 0, 0, 0, 1246, 22, "rockstarnewengland.com", "/", "http:", "", 2747},
    { 0, 0, 0, 1246, 22, "rockstarlincoln.com", "/", "http:", "", 2747},
    { 0, 0, 0, 1246, 22, "rockstarleeds.co.uk", "/", "http:", "", 2747},
}


gHostPortAppList = {
    -- type, AppId, IP Address, Port, Protocol
    { 0, 2695, "109.75.167.42",     123, DC.ipproto.udp},
    { 0, 2695, "109.75.167.42",     443, DC.ipproto.tcp},
    { 0, 2695, "109.75.167.42",    1723, DC.ipproto.tcp},
    { 0, 2695, "109.75.167.42",    5000, DC.ipproto.udp},
    { 0, 2695, "109.75.167.42",    5353, DC.ipproto.udp},
    { 0, 2695, "184.154.116.157",   123, DC.ipproto.udp},
    { 0, 2695, "184.154.116.157",   443, DC.ipproto.tcp},
    { 0, 2695, "184.154.116.157",  1723, DC.ipproto.tcp},
    { 0, 2695, "184.154.116.157",  5000, DC.ipproto.udp},
    { 0, 2695, "184.154.116.157",  5353, DC.ipproto.udp},
    { 0, 2695, "217.147.94.149",    123, DC.ipproto.udp},
    { 0, 2695, "217.147.94.149",    443, DC.ipproto.tcp},
    { 0, 2695, "217.147.94.149",   1723, DC.ipproto.tcp},
    { 0, 2695, "217.147.94.149",   5000, DC.ipproto.udp},
    { 0, 2695, "217.147.94.149",   5353, DC.ipproto.udp},
    { 0, 2695, "31.24.33.221",      123, DC.ipproto.udp},
    { 0, 2695, "31.24.33.221",      443, DC.ipproto.tcp},
    { 0, 2695, "31.24.33.221",     1723, DC.ipproto.tcp},
    { 0, 2695, "31.24.33.221",     5000, DC.ipproto.udp},
    { 0, 2695, "31.24.33.221",     5353, DC.ipproto.udp},
    { 0, 2695, "46.165.197.1",      123, DC.ipproto.udp},
    { 0, 2695, "46.165.197.1",      443, DC.ipproto.tcp},
    { 0, 2695, "46.165.197.1",     1723, DC.ipproto.tcp},
    { 0, 2695, "46.165.197.1",     5000, DC.ipproto.udp},
    { 0, 2695, "46.165.197.1",     5353, DC.ipproto.udp},
    { 0, 2695, "46.165.221.230",    123, DC.ipproto.udp},
    { 0, 2695, "46.165.221.230",    443, DC.ipproto.tcp},
    { 0, 2695, "46.165.221.230",   1723, DC.ipproto.tcp},
    { 0, 2695, "46.165.221.230",   5000, DC.ipproto.udp},
    { 0, 2695, "46.165.221.230",   5353, DC.ipproto.udp},
    { 0, 2695, "62.75.181.139",     123, DC.ipproto.udp},
    { 0, 2695, "62.75.181.139",     443, DC.ipproto.tcp},
    { 0, 2695, "62.75.181.139",    1723, DC.ipproto.tcp},
    { 0, 2695, "62.75.181.139",    5000, DC.ipproto.udp},
    { 0, 2695, "62.75.181.139",    5353, DC.ipproto.udp},
    { 0, 2695, "64.251.22.13",      123, DC.ipproto.udp},
    { 0, 2695, "64.251.22.13",      443, DC.ipproto.tcp},
    { 0, 2695, "64.251.22.13",     1723, DC.ipproto.tcp},
    { 0, 2695, "64.251.22.13",     5000, DC.ipproto.udp},
    { 0, 2695, "64.251.22.13",     5353, DC.ipproto.udp},
    { 0, 2695, "91.121.166.108",    123, DC.ipproto.udp},
    { 0, 2695, "91.121.166.108",    443, DC.ipproto.tcp},
    { 0, 2695, "91.121.166.108",   1723, DC.ipproto.tcp},
    { 0, 2695, "91.121.166.108",   5000, DC.ipproto.udp},
    { 0, 2695, "91.121.166.108",   5353, DC.ipproto.udp},
}


function DetectorInit(detectorInstance)
-- ClientType, DHPSequence,  serviceId, clientId, PayloadId,  hostPattern, pathPattern, schemePattern, queryPattern
    gDetector = detectorInstance;

    -- iBook 
    gDetector:addHttpPattern(2, 5, 0, 421, 19, 0, 0, 'iBooks/', 2724);
    -- SimplePie
    gDetector:addHttpPattern(2, 5, 0, 422, 19, 0, 0, 'SimplePie/', 2706);
    -- Sophos Live Protection
    gDetector:addHttpPattern(2, 5, 0, 423, 25, 0, 0, 'SXL/', 2707);
    -- Android Asynchronous Http Client
    gDetector:addHttpPattern(2, 5, 0, 410, 23, 0, 0, 'android-async-http/', 2708);
    -- Last.fm
    gDetector:addHttpPattern(2, 5, 0, 411, 19, 0, 0, 'Last.fm Client', 261);
    -- iTunes Store
    gDetector:addHttpPattern(2, 5, 0, 424, 19, 0, 0, 'MobileStore/', 2725);    
    -- Integromedb Crawler
    gDetector:addHttpPattern(2, 5, 0, 415, 1, 0, 0, 'www.integromedb.org/Crawler', 2712);
    -- Twitter4J
    gDetector:addHttpPattern(2, 5, 0, 416, 1, 0, 0, 'twitter4j http://twitter4j.org/ /', 2713);
    -- msnbot
    gDetector:addHttpPattern(2, 5, 0, 417, 1, 0, 0, 'msnbot/', 2714);
    -- Pingdom
    gDetector:addHttpPattern(2, 5, 0, 418, 1, 0, 0, 'Pingdom', 2715);
    -- PHP-SOAP
    gDetector:addHttpPattern(2, 5, 0, 419, 1, 0, 0, 'PHP-SOAP/', 2716);
    -- RealPlayer Cloud
    gDetector:addHttpPattern(2, 5, 0, 420, 19, 0, 0, 'nucleus', 2718);
    -- Remote Ctrl for iPhone/iPad
    gDetector:addHttpPattern(2, 5, 0, 425, 19, 0, 0, 'Remote/', 2746);
    -- Rockstar Games
    gDetector:addHttpPattern(2, 5, 0, 426, 19, 0, 0, 'ros ', 2747);
 
    if gDetector.addAppUrl then
        for i,v in ipairs(gUrlPatternList) do
            gDetector:addAppUrl(v[1],v[2],v[3],v[4],v[5],v[6],v[7],v[8],v[9],v[10]);
        end
    end

    if gDetector.addHostPortApp then
        for i,v in ipairs(gHostPortAppList) do
            gDetector:addHostPortApp(v[1],v[2],v[3],v[4],v[5]);
        end
    end

    return gDetector;
end

function DetectorClean()
end

