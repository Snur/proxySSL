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
detection_name: Payload Group "Wu Tang"
description: Group of payload detectors.
bundle_description: $VAR1 = {
          'Google Groups' => 'Platform for discussion groups provided by Google.',
          'Baidu Movies' => 'Video search engine by Baidu.',
          'Myspace Videos' => 'Videos sharing service by Myspace.',
          'Google+ Photos' => 'Photo sharing among Google+ community.',
          'Dropbox Upload' => 'File upload action of Dropbox.',
          'Glype' => 'Web-based proxy.',
          'Xunlei Kankan' => 'Chinese webportal for video-on-demand service.',
          'Dropbox Share' => 'File sharing option from Dropbox.',
          'Sanook.com' => 'Web portal for Entertainment purpose like games, lotery, news and music.',
          'BitTorrent' => 'A peer-to-peer file sharing protocol used for transferring large amounts of data.',
          'Google+ Videos' => 'Video sharing among Google+ community.',
          'Dropbox Download' => 'File download action of Dropbox.',
          'ExtraTorrent' => 'A BitTorrent network.',
          'FileHost.ro' => 'Romanian File sharing service.',
          'Sophos Update' => 'Software update for the Anti-Malware Sophos Live protection.',
          'Gyao' => 'Video streaming website by Yahoo! Japan.',
          'Gbridge' => 'Google extension to access other computer remotely.',
          'Mikogo' => 'Desktop sharing application.',
          'Core Audience' => 'Advertisement site.',
          'Tritone Hosting' => 'Advertisement and analytics site.',
          'Myspace Photos' => 'Photos sharing service by Myspace.',
          'GMX' => 'Free webmail and email service provider.'
        };

--]]

require "DetectorCommon"


local DC = DetectorCommon

DetectorPackageInfo = {
    name =  "payload_group_wu_tang",
    proto =  DC.ipproto.tcp,
    client = {
        init =  'DetectorInit',
        clean =  'DetectorClean',
        minimum_matches =  1
    }
}

--serviceId, clientId, ClientType, PayloadId, PayloadType, hostPattern, pathPattern, schemePattern, queryPattern
gUrlPatternList = {

    -- Baidu Video
    { 0, 0, 0, 1334, 22, "v.baidu.com", "/", "http:", "", 2869},
    { 0, 0, 0, 1334, 22, "video.baidu.com", "/", "http:", "", 2869},
    { 0, 0, 0, 1334, 22, "movie.baidu.com", "/", "http:", "", 2869},
    -- Gbridge
    { 0, 0, 0, 1335, 22, "gbridge.com", "/", "http:", "", 2874},
    -- Mikogo
    { 0, 0, 0, 1336, 22, "mikogo.com", "/", "http:", "", 2875},
    { 0, 0, 0, 1336, 22, "mikogo1.com", "/", "http:", "", 2875},
    { 0, 0, 0, 1336, 22, "mikogo2.com", "/", "http:", "", 2875},
    { 0, 0, 0, 1336, 22, "mikogo3.com", "/", "http:", "", 2875},
    { 0, 0, 0, 1336, 22, "mikogo4.com", "/", "http:", "", 2875},
    { 0, 0, 0, 1336, 22, "mikogo5.com", "/", "http:", "", 2875},
    { 0, 0, 0, 1336, 22, "mikogo6.com", "/", "http:", "", 2875},
    { 0, 0, 0, 1336, 22, "mikogo7.com", "/", "http:", "", 2875},
    { 0, 0, 0, 1336, 22, "mikogo8.com", "/", "http:", "", 2875},
    { 0, 0, 0, 1336, 22, "mikogo9.com", "/", "http:", "", 2875},
    -- Xunlei Kankan
    { 0, 0, 0, 1338, 1, "kankan.com", "/", "http:", "", 2878},
    { 0, 0, 0, 1338, 1, "kanimg.com", "/", "http:", "", 2878},
    { 0, 0, 0, 1338, 1, "phone.xunlei.com", "/", "http:", "", 2878},
    { 0, 0, 0, 1338, 1, "pad.xunlei.com", "/", "http:", "", 2878},
    { 0, 0, 0, 1338, 1, "phone.xlisp.net", "/", "http:", "", 2878},
    { 0, 0, 0, 1338, 1, "pad.xlisp.net", "/", "http:", "", 2878},
    { 0, 0, 0, 1338, 1, "kkpgv0.xunlei.com", "/", "http:", "", 2878},
    { 0, 0, 0, 1338, 1, "kkpgv0.xlisp.net", "/", "http:", "", 2878},
    { 0, 0, 0, 1338, 1, "xmp.xunlei.com", "/", "http:", "", 2878},
    { 0, 0, 0, 1338, 1, "xmp.xlisp.net", "/", "http:", "", 2878},
    { 0, 0, 0, 1338, 1, "kankan.xunlei.com", "/", "http:", "", 2878},
    { 0, 0, 0, 1338, 1, "kankan.xlisp.net", "/", "http:", "", 2878},
    { 0, 0, 0, 1338, 1, "kkpgv1.xunlei.com", "/", "http:", "", 2878},
    { 0, 0, 0, 1338, 1, "kkpgv1.xlisp.net", "/", "http:", "", 2878},
    { 0, 0, 0, 1338, 1, "kkpgv2.xunlei.com", "/", "http:", "", 2878},
    { 0, 0, 0, 1338, 1, "kkpgv2.xlisp.net", "/", "http:", "", 2878},
    { 0, 0, 0, 1338, 1, "kkpgv3.xunlei.com", "/", "http:", "", 2878},
    { 0, 0, 0, 1338, 1, "kkpgv3.xlisp.net", "/", "http:", "", 2878},
    { 0, 0, 0, 1338, 1, "kkpgv4.xunlei.com", "/", "http:", "", 2878},
    { 0, 0, 0, 1338, 1, "kkpgv4.xlisp.net", "/", "http:", "", 2878},
    { 0, 0, 0, 1338, 1, "kkpgv5.xunlei.com", "/", "http:", "", 2878},
    { 0, 0, 0, 1338, 1, "kkpgv5.xlisp.net", "/", "http:", "", 2878},
    { 0, 0, 0, 1338, 1, "kkpgv6.xunlei.com", "/", "http:", "", 2878},
    { 0, 0, 0, 1338, 1, "kkpgv6.xlisp.net", "/", "http:", "", 2878},
    { 0, 0, 0, 1338, 1, "kkpgv7.xunlei.com", "/", "http:", "", 2878},
    { 0, 0, 0, 1338, 1, "kkpgv7.xlisp.net", "/", "http:", "", 2878},
    { 0, 0, 0, 1338, 1, "kkpgv8.xunlei.com", "/", "http:", "", 2878},
    { 0, 0, 0, 1338, 1, "kkpgv8.xlisp.net", "/", "http:", "", 2878},
    { 0, 0, 0, 1338, 1, "kkpgv9.xunlei.com", "/", "http:", "", 2878},
    { 0, 0, 0, 1338, 1, "kkpgv9.xlisp.net", "/", "http:", "", 2878},
    { 0, 0, 0, 1338, 1, "kankan.xunlei.com", "/", "http:", "", 2878},
    { 0, 0, 0, 1338, 1, "xlpan.com", "/", "http:", "", 2878},
    { 0, 0, 0, 1338, 1, "xunlei.com", "/", "http:", "", 2878},
    { 0, 0, 0, 1338, 1, "sandai.net", "/", "http:", "", 2878},
    --  Google Groups
    { 0, 0, 0, 1339, 1, "groups.google.com", "/", "http:", "", 2879},
    --  Google+ Photos
    { 0, 0, 0, 1340, 1, "plus.google.com", "/_/photos", "http:", "", 2880},
    { 0, 0, 0, 1340, 1, "plus.google.com", "/u/0/_/photos", "http:", "", 2880},
    { 0, 0, 0, 1340, 1, "plus.google.com", "/c/photos", "http:", "", 2880},
    { 0, 0, 0, 1340, 1, "plus.google.com", "/photos", "http:", "", 2880},
    { 0, 0, 0, 1340, 1, "plus.google.com", "/upload/photos", "http:", "", 2880},
    { 0, 0, 0, 1340, 1, "plus.google.com", "/sharebox/medialayout", "http:", "", 2880},
    { 0, 0, 0, 1340, 1, "plus.google.com", "/picker/fetch", "http:", "", 2880},
    --  Google+ Videos
    { 0, 0, 0, 1341, 1, "plus.google.com", "/_/photos/videosbyuser", "http:", "", 2881},
    { 0, 0, 0, 1341, 1, "plus.google.com", "/_/photos/getvideosettings", "http:", "", 2881},
    --  Myspace Photos
    { 0, 0, 0, 1342, 1, "myspace.com", "/my/photos/", "http:", "", 2882},
    { 0, 0, 0, 1342, 1, "myspace.com", "/modules/photos/", "http:", "", 2882},
    { 0, 0, 0, 1342, 1, "myspace.com", "/Modules/Photos/", "http:", "", 2882},
    { 0, 0, 0, 1342, 1, "images.myspacecdn.com", "/", "http:", "", 2882},
    { 0, 0, 0, 1342, 1, "myspacecdn.com", "/_/photos/videosbyuser", "http:", "", 2882},
    --  Myspace Videos
    { 0, 0, 0, 1343, 1, "myspace.com", "/ajax/manage/video", "http:", "", 2883},
    { 0, 0, 0, 1343, 1, "myspace.com", "/ajax/videos", "http:", "", 2883},
    { 0, 0, 0, 1343, 1, "myspace.com", "/manage/videos", "http:", "", 2883},
    { 0, 0, 0, 1343, 1, "myspace.com", "/upload/video", "http:", "", 2883},
    { 0, 0, 0, 1343, 1, "myspace.com", "/modules/video", "http:", "", 2883},
    { 0, 0, 0, 1343, 1, "myspace.com", "/modules/videos", "http:", "", 2883},
    { 0, 0, 0, 1343, 1, "myspace.com", "/modules/Video", "http:", "", 2883},
    { 0, 0, 0, 1343, 1, "myspace.com", "/modules/Videos", "http:", "", 2883},
    { 0, 0, 0, 1343, 1, "myspace.com", "/my/video", "http:", "", 2883},
    { 0, 0, 0, 1343, 1, "myspace.com", "/my/videos", "http:", "", 2883},
    { 0, 0, 0, 1343, 1, "myspace.com", "/my/Video", "http:", "", 2883},
    { 0, 0, 0, 1343, 1, "myspace.com", "/my/Videos", "http:", "", 2883},
    { 0, 0, 0, 1343, 1, "videos.myspacecdn.com", "/", "http:", "", 2883},
    --  FileHost.ro
    { 0, 0, 0, 1344, 1, "filehost.ro", "/", "http:", "", 2884},
    --  Gyao
    { 0, 0, 0, 1345, 1, "gyao.yahoo.co.jp", "/", "http:", "", 2885},
    { 0, 0, 0, 1345, 1, "yahoo-streaming.co.jp", "/gyao", "http:", "", 2885},
    { 0, 0, 0, 1345, 1, "yahooapis.jp", "/gyao", "http:", "", 2885},
    { 0, 0, 0, 1345, 1, "gyao.c.yimg.jp", "/", "http:", "", 2885},
    --  Sophos Update
    { 0, 0, 0, 1346, 1, "sophosupd.com", "/", "http:", "", 2890},
    { 0, 0, 0, 1346, 1, "sophosupd.net", "/", "http:", "", 2890},
    { 0, 0, 0, 1346, 1, "sophos.net", "/update", "http:", "", 2890},
    { 0, 0, 0, 1346, 1, "sophos.com", "/update", "http:", "", 2890},
    --  Glype
    { 0, 0, 0, 1347, 1, "glype.com", "/", "http:", "", 2891},
    --  GMX
    { 0, 0, 0, 1348, 1, "gmx.com", "/", "http:", "", 2892},
    { 0, 0, 0, 1348, 1, "gmx.co.uk", "/", "http:", "", 2892},
    { 0, 0, 0, 1348, 1, "gmx.net", "/", "http:", "", 2892},
    { 0, 0, 0, 1348, 1, "gmx.at", "/", "http:", "", 2892},
    { 0, 0, 0, 1348, 1, "gmx.ch", "/", "http:", "", 2892},
    { 0, 0, 0, 1348, 1, "gmx.net", "/", "http:", "", 2892},
    { 0, 0, 0, 1348, 1, "ui-portal.de", "/", "http:", "", 2892},
    --  BitTorrent
    { 0, 0, 0, 1349, 1, "bittorrent.com", "/", "http:", "", 61},
    --  Sanook.com
    { 0, 0, 0, 1350, 1, "sanook.com", "/", "http:", "", 2893 },
    { 0, 0, 0, 1350, 1, "fsanook.com", "/", "http:", "", 2893 },
    { 0, 0, 0, 1350, 1, "isanook.com", "/", "http:", "", 2893 },
    --  ExtraTorrent
    { 0, 0, 0, 1352, 1, "extratorrent.cc", "/", "http:", "", 1214 },
    --  Tritone Hosting 
    { 0, 0, 0, 1353, 1, "tritonehosting.net", "/", "http:", "", 2594 },
    --  Core Audience 
    { 0, 0, 0, 1354, 1, "coreaudience.com", "/", "http:", "", 2552 },
    --  Dropbox Upload 
    { 0, 0, 0, 1355, 1, "dropbox.com", "/static/swf/swfupload.swf", "http:", "", 2895 },
    { 0, 0, 0, 1355, 1, "dropbox.com", "/upload", "http:", "", 2895 },
    { 0, 0, 0, 1355, 1, "dropbox.com", "/chunked_upload", "http:", "", 2895 },
    --  Dropbox download
    { 0, 0, 0, 1356, 1, "dropbox.com", "/get", "http:", "", 2896 },
    { 0, 0, 0, 1356, 1, "dropbox.com", "/zip_batch", "http:", "", 2896 },
    { 0, 0, 0, 1356, 1, "dropbox.com", "/zip_batch", "http:", "", 2896 },
    { 0, 0, 0, 1356, 1, "dropbox.com", "/static/images/client-downloadload.png", "http:", "", 2896 },
    --  Dropbox Share 
    { 0, 0, 0, 1357, 1, "dropbox.com", "/share", "http:", "", 2897 },
    { 0, 0, 0, 1357, 1, "dropbox.com", "/sm/share", "http:", "", 2897 },

}


function DetectorInit(detectorInstance)
    gDetector = detectorInstance;

    gDetector:addHttpPattern(2, 5, 0, 442, 20, 0, 0, 'BaiduMovieP2P', 2869, 1); 
    gDetector:addHttpPattern(2, 5, 0, 442, 20, 0, 0, 'BaiduP2P', 2869, 1); 
    if gDetector.addAppUrl then
        for i,v in ipairs(gUrlPatternList) do
            gDetector:addAppUrl(v[1],v[2],v[3],v[4],v[5],v[6],v[7],v[8],v[9],v[10]);
        end
    end

    return gDetector;
end

function DetectorClean()
end

