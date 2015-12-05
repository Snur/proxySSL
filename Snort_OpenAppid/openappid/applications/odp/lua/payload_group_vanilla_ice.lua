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
detection_name: Payload Group "Vanilla Ice"
version: 4
description: Group of payload detectors.
bundle_description: $VAR1 = {
          'eRoom' => 'Collaborative software site.',
          'LeapFILE' => 'Managed file transfer site.',
          'Megaproxy' => 'Web VPN services through SSL traffic.',
          'Shopkick' => 'Mobile app for shopping.',
          'DuckDuckGo' => 'Search engine.',
          'Fetion' => 'Chinese instant messaging client.',
          'KProxy' => 'Anonymous proxy service.',
          'Camo Proxy' => 'Online free proxy server.',
          'Yahoo! Mobage' => 'Mobile gaming platform popular in Japan.',
          'Fotki' => 'Photo sharing site.',
          'GREE' => 'Japanese mobile social game developer.',
          'SugarCRM' => 'Customer relationship management software company.',
          'RayFile' => 'Free file hosting site.',
          'Pogoplug' => 'Cloud storage for mobile devices.',
          'Eyejot' => 'Video mail web application.',
          'Wii' => 'Video games console by Nintendo.',
          'Tencent' => 'Chinese portal for Internet service.',
          'Glide' => 'Cross-platform web desktop that allows for file sharing between different computers and mobile devices.',
          'Hangame' => 'Korean online game portal.',
          'FlyProxy' => 'Anonymous proxy service.',
          'Guardster' => 'Anonymous proxy service.',
          'Twiddla' => 'Web based collaboration tool.',
          'Quora' => 'Online discussion forums on a wide variety of topics.',
          'Picsearch' => 'Image search engine.',
          'Dogpile' => 'Search engine aggregator.',
          'Bloglovin' => 'Blog portal.',
          'Okurin' => 'Japanese file upload site.',
          'Netload' => 'File hosting site.',
          'CrossLoop' => 'Desktop sharing / remote access site.',
          'Zhihu.com' => 'Chinese Q&A website.',
          'Coral CDN' => 'Content distribution network.',
          'Pastebin.com' => 'Online whiteboard application.',
          'Fluxiom' => 'Cloud storage, collaboration, and file management.'
        };

--]]

require "DetectorCommon"


local DC = DetectorCommon

DetectorPackageInfo = {
    name =  "payload_group_vanilla_ice",
    proto =  DC.ipproto.tcp,
    client = {
        init =  'DetectorInit',
        clean =  'DetectorClean',
        minimum_matches =  1
    }
}

--serviceId, clientId, ClientType, PayloadId, PayloadType, hostPattern, pathPattern, schemePattern, queryPattern
gUrlPatternList = {

    -- Eyejot
    { 0, 0, 0, 1298, 4, "eyejot.com", "/", "http:", "", 2803},
    -- Dogpile
    { 0, 0, 0, 1299, 22, "dogpile.com", "/", "http:", "", 2804},
    -- DuckDuckGo
    { 0, 0, 0, 1300, 22, "duckduckgo.com", "/", "http:", "", 2805},
    -- Picsearch
    { 0, 0, 0, 1311, 22, "picsearch.com", "/", "http:", "", 2816},
    -- Fetion
    { 0, 0, 0, 1312, 10, "fetionpic.com", "/", "http:", "", 2817},
    { 0, 0, 0, 1312, 10, "fexion.com", "/", "http:", "", 2817},
    { 0, 0, 0, 1312, 10, "fexion.10086.cn", "/", "http:", "", 2817},
    -- Fluxiom
    { 0, 0, 0, 1313, 9, "fluxiom.com", "/", "http:", "", 2818},
    -- GigaUP
    --{ 0, 0, 0, 1314, 9, "gigaup.fr", "/", "http:", "", 2819},
    -- LeapFILE
    { 0, 0, 0, 1315, 9, "leapfile.com", "/", "http:", "", 2820},
    -- Netload
    { 0, 0, 0, 1316, 9, "netload.in", "/", "http:", "", 2821},
    -- Okurin
    { 0, 0, 0, 1317, 9, "okurin.bitpark.co.jp", "/", "http:", "", 2822},
    -- RayFile
    { 0, 0, 0, 1318, 9, "rayfile.com", "/", "http:", "", 2823},
    -- Fotki
    { 0, 0, 0, 1319, 9, "fotki.com", "/", "http:", "", 2824},
    -- Crossloop
    { 0, 0, 0, 1320, 8, "crossloop.com", "/", "http:", "", 2825},
    -- eroom
    { 0, 0, 0, 1321, 8, "eroom.net", "/", "http:", "", 2826},
    -- Glide
    { 0, 0, 0, 1322, 9, "glideconnect.com", "/", "http:", "", 2827},
    { 0, 0, 0, 1322, 9, "glideos.com", "/", "http:", "", 2827},
    -- GREE
    { 0, 0, 0, 1323, 20, "gree.net", "/", "http:", "", 2828},
    { 0, 0, 0, 1323, 20, "gree.net.s3.amazonaws.com", "/", "http:", "", 2828},
    -- Camo Proxy 
    { 0, 0, 0, 1301, 22, "camoproxy.zoomshare.com", "/", "http:", "", 2814},
    -- Tencent
    { 0, 0, 0, 1302, 22, "tencent.com", "/", "http:", "", 2815},
    { 0, 0, 0, 1302, 22, "weiyun.com", "/", "http:", "", 2815},
    -- Wii
    { 0, 0, 0, 1303, 22, "wii.com", "/", "http:", "", 2826},
    { 0, 0, 0, 1303, 22, "nintendo.com", "/wii/", "http:", "", 2830},
    -- Shopkick
    { 0, 0, 0, 1304, 22, "shopkick.com", "/", "http:", "", 2831},
    -- Hangame
    { 0, 0, 0, 1305, 22, "hangame.co.kr", "/", "http:", "", 2832},
    { 0, 0, 0, 1305, 22, "hangame.com", "/", "http:", "", 2832},
    { 0, 0, 0, 1305, 22, "hangame.co.jp", "/", "http:", "", 2832},
    -- SugarCRM 
    { 0, 0, 0, 1306, 22, "sugarcrm.com", "/", "http:", "", 2833},
    -- Megaproxy
    { 0, 0, 0, 1307, 22, "megaproxy.com", "/", "http:", "", 2834},
    -- KProxy
    { 0, 0, 0, 1308, 22, "kproxy.com", "/", "http:", "", 2835},
    -- Guardster
    { 0, 0, 0, 1309, 22, "guardster.com", "/", "http:", "", 2836},
    -- FlyProxy
    { 0, 0, 0, 1310, 22, "flyproxy.com", "/", "http:", "", 2837},
    -- Coral CDN
    { 0, 0, 0, 1325, 22, "coralcdn.org", "/", "http:", "", 2838},
    -- Pastebin.com 
    { 0, 0, 0, 1326, 22, "pastebin.com", "/", "http:", "", 2839},
    -- Zhihu.com 
    { 0, 0, 0, 1327, 22, "zhihu.com", "/", "http:", "", 2840},
    { 0, 0, 0, 1327, 22, "zhimg.com", "/", "http:", "", 2840},
    -- Twiddla
    { 0, 0, 0, 1328, 8, "twiddla.com", "/", "http:", "", 2841},
    -- -- Aereo
    -- { 0, 0, 0, 1329, 13, "aereo.com", "/", "http:", "", 2842},
    -- Quora
    { 0, 0, 0, 1330, 5, "quora.com", "/", "http:", "", 2843},
    -- Yahoo! mobage
    { 0, 0, 0, 1331, 20, "yahoo-mbga.jp", "/", "http:", "", 2844},
    -- Pogoplug
    { 0, 0, 0, 1332, 20, "pogoplug.com", "/", "http:", "", 2845},
    -- Bloglovin
    { 0, 0, 0, 1333, 20, "bloglovin.com", "/", "http:", "", 2867},
}


function DetectorInit(detectorInstance)
-- ClientType, DHPSequence,  serviceId, clientId, PayloadId,  hostPattern, pathPattern, schemePattern, queryPattern
    gDetector = detectorInstance;

    -- Shopkick
     gDetector:addHttpPattern(2, 5, 0, 436, 19, 0, 0, 'shopkick/', 2831);
    -- Pogoplug 
     gDetector:addHttpPattern(2, 5, 0, 437, 19, 0, 0, 'PogoplugAndroid/', 2845);
 
    if gDetector.addAppUrl then
        for i,v in ipairs(gUrlPatternList) do
            gDetector:addAppUrl(v[1],v[2],v[3],v[4],v[5],v[6],v[7],v[8],v[9],v[10]);
        end
    end

    return gDetector;
end

function DetectorClean()
end

