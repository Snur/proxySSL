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
detection_name: Payload Group "6pencenonethericher"
version: 8
description: Group of payload detectors.
bundle_description: $VAR1 = {
          'MetaFilter' => 'Community weblog for link sharing.',
          'Webcrawler' => 'A search engine.',
          'PPStream' => 'Chinese video streaming software.',
          'Java Update' => 'Java update software service.',
          'eBuddy' => 'Web chat client.',
          'LiveJournal' => 'Social blogging site.',
          'Dailymotion' => 'A video sharing service website.',
          'Twitter' => 'Social networking and microblogging site.',
          'Ustream.tv' => 'Video streaming and sharing.',
          'Google Analytics' => 'Google service that tracks and generates detailed web statistics.',
          'Digg' => 'News discussion site.',
          'Napster' => 'Audio streaming and MP3 store.',
          'Hulu' => 'Video streaming.',
          'Friendster' => 'Social networking site.',
          'SoulSeek' => 'Peer-to-peer network.',
          'YY' => 'Chinese Chat application.',
          'YouTube' => 'A video-sharing website on which users can upload, share, and view videos.',
          'Wow' => 'A search engine.',
          'WebEx' => 'Cisco\'s online meeting and web conferencing application.',
          'Netflix stream' => 'Video streams from Netflix service.',
          'Hulu Video' => 'Hulu Video streaming.',
          'XM Radio Online' => 'Streaming audio.',
          'StumbleUpon' => 'A web browser plugin that allows users to discover and rate webpages, photos, videos and news articles.',
          'Live365' => 'Internet radio.'
        };

--]]

require "DetectorCommon"


local DC = DetectorCommon

DetectorPackageInfo = {
    name =  "payload_group_6pencenonethericher",
    proto =  DC.ipproto.tcp,
    client = {
        init =  'DetectorInit',
        clean =  'DetectorClean',
        minimum_matches =  1
    }
}

gUrlPatternList = {

    -- Wow
    { 0, 0, 0, 1658, 22, "wow.com", "/", "http:", "", 3910 },

    -- Webcrawler
    { 0, 0, 0, 1659, 22, "webcrawler.com", "/", "http:", "", 3911 },

    -- Hulu Video
    { 0, 0, 0, 1671, 1, "hulu.com", "/site-player", "http:", "", 3946},

    -- Netflix Stream
    { 0, 0, 0, 1672, 1, "netflix.com", "/WiPlayer", "http:", "", 939}, 
    { 0, 0, 0, 1672, 1, "nflxvideo.net", "/", "http:", "", 939},

    -- Hulu
    { 0, 0, 0, 41, 13, "hulu.com", "/", "http:", "", 677},

    -- Youtube
    { 0, 0, 0, 74, 13, "youtube.com", "/", "http:", "", 929},
    { 0, 0, 0, 74, 13, "ytimg.com", "/", "http:", "", 929},

    -- XM Radio
    { 0, 0, 0, 71, 13, "xmradio.com", "/", "http:", "", 923},  
    
    -- WebEx
    { 0, 0, 0, 70, 21, "webex.com", "/", "http:", "", 905},

    -- Twitter
    { 0, 0, 0, 67, 5, "twitter.com", "/", "http:", "", 882},

    -- Ustream
    { 0, 0, 0, 68, 13, "ustream.tv", "/", "http:", "", 884}, 

    -- Stumbleupon
    { 0, 0, 0, 66, 14, "stumbleupon.com", "/", "http:", "", 852},
    { 0, 0, 0, 66, 14, "stumble-upon.com", "/", "http:", "", 852},

    -- PPStream
    { 0, 0, 0, 59, 13, "ppstream.com", "/", "http:", "", 374},
    { 0, 0, 0, 59, 13, "pps.tv", "/", "http:", "", 374},

    -- Pandora
    { 0, 0, 0, 56, 13, "pandora.com", "/", "http:", "", 779},

    -- Napster
    { 0, 0, 0, 54, 13, "napster.com", "/", "http:", "", 319},
    { 0, 0, 0, 54, 13, "napster.co.uk", "/", "http:", "", 319},

    -- Metafilter
    { 0, 0, 0, 79, 14, "metafilter.com", "/", "http:", "", 729},
    { 0, 0, 0, 79, 14, "metafilter.net", "/", "http:", "", 729},

    -- Livejournal
    { 0, 0, 0, 46, 5, "livejournal.com", "/", "http:", "", 716},
 
    -- live365
    { 0, 0, 0, 45, 13, "live365.com", "/", "http:", "", 264},

    -- Samsung Wallet
    --{ 0, 0, 0, 404, 1, "wallet.samsung.com", "/", "http:", "", 2649},

    -- Friendster
    { 0, 0, 0, 37, 5, "friendster.com", "/", "http:", "", 642},
    
    -- ebuddy
    { 0, 0, 0, 35, 10, "ebuddy.com", "/", "http:", "", 1697},

    -- google analytics
    { 0, 0, 0, 38, 16, "google.com", "/analytics", "http:", "", 660},
    { 0, 0, 0, 38, 16, "google-analytics.com", "/", "http:", "", 660},     

    -- Digg
    { 0, 0, 0, 31, 14, "digg.com", "/", "http:", "", 117},

    -- Dailymotion
    { 0, 0, 0, 30, 13, "dailymotion.com", "/", "http:", "", 600},

    -- YY
    { 0, 0, 0, 1693, 1, "yy.com", "/", "http:", "", 1663},
    { 0, 0, 0, 1693, 1, "duowan.com", "/", "http:", "", 1663},
    { 0, 0, 0, 1693, 1, "hiido.com", "/", "http:", "", 1663},
    { 0, 0, 0, 1693, 1, "hiido.cn", "/", "http:", "", 1663},

    -- Soulseek
    { 0, 0, 0, 61, 15, "soulseekqt.net", "/", "http:", "", 442},

    -- Java update
    { 0, 0, 0, 187, 1, "javadl.sun.com", "/", "http:", "", 1676},
    { 0, 0, 0, 187, 1, "javadl-esd.sun.com", "/", "http:", "", 1676},
    
}



function DetectorInit(detectorInstance)

    gDetector = detectorInstance;

    if gDetector.addAppUrl then
        for i,v in ipairs(gUrlPatternList) do
            gDetector:addAppUrl(v[1],v[2],v[3],v[4],v[5],v[6],v[7],v[8],v[9],v[10]);
        end
    end

    return gDetector;
end

function DetectorClean()
end

