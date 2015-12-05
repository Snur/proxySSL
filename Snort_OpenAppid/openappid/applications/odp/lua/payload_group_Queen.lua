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
detection_name: Payload Group "Queen"
version: 12
description: Group of payload detectors.
bundle_description: $VAR1 = {
          'LiteCoin' => 'A cryptopgraphic currency similar to BitCoin which requires lighter-weight resources to mine.',
          'NCAA' => 'National Collegiate Athletic Association - non-profit association for athletic programs.',
          'Chosun' => 'News aggregates from BBC in Korean.',
          'Yahoo!' => 'Yahoo! and it\'s online services.',
          'CBS' => 'CBS news website.',
          'Scribd Upload' => 'Sharing, publishing, discussing and discovering documents. This app can be detected from decrypted traffic only.',
          'Docstoc Upload' => 'Electronic repository for documents, video.',
          'OpenSUSE' => 'Official website for OpenSUSE, Linux based OS.',
          'Po.st' => 'Social sharing platform.',
          'Livefyre' => 'Real-Time tools for socializing the web-sites.',
          'GOLF.com' => 'News, instruction and courses about Golf.',
          'Youtube Upload' => 'Upload and share videos.',
          'FOX' => 'Official website for Fox entertainment.',
          'FriendFinder' => 'Online friend finder and dating site.',
          'Flickr Upload' => 'Online photo management and sharing.',
          'Intermarkets' => 'Sales management firm for Advertising.',
          'C-SPAN' => 'Cable-Satellite Public Affairs Network - Non-profit cable television.',
          'OpenBSD' => 'Open source code for security, enterprise and server.',
          'Windows Azure' => 'Cloud computing by Microsoft.',
          'NextBus' => 'Live updates on public transit system.',
          'CheapStuff' => 'Aggregates best deals.',
          'Washington Times' => 'Official web site for the Washington times news portal.',
          'Ooyala' => 'Solution providers for Video analytics.',
          'Clear Channel' => 'Aggregates online radio broadcasting.',
          'Associated Press' => 'Official web site for the Associated Press, non-profit news agency.',
          'Speedtest' => 'Test the download and upload speed of the internet.',
          'Adobe Software' => 'Adobe software and updates.',
          'BoldChat' => 'Live Chat software for website.',
          'OCLC' => 'Online Computer Library Center - Nonprofit collaboration for providing online public access catalog.',
          'Game Front' => 'Gaming news, reviews, cheats, and walkthroughs,',
          'Entertainment Weekly' => 'Entertainment new and video clips.',
          'DSW' => 'Designer Shoe Warehouse - branded footwear.',
          'Letterpress' => 'Word game for iOS.',
          'Glam' => 'News regarding recent trends in fashion and lifestyle.',
          'lynda.com' => 'Online education site focusing on aspects of web design.',
          'WTOP' => 'Official web site for WTOP FM.',
          'FreeStreams' => 'Online Movies, Radio and Games.',
          'Game Center' => 'Social gaming app for iOS.',
          'Boxnet Upload SSL' => 'Online repository for documents, spreadsheet and presentations.  This app can be detected from decrypted traffic only.',
          'Audible.com' => 'Digital audio version for books, magazines, information and other entertainments.',
          'ShareFile Upload SSL' => 'Securely send files. This app can be detected from decrypted traffic only.',
          'Woopra' => 'Real time customer service and solutions.',
          'BitCoin' => 'Application and website for mining and exchanging BitCoins, a cryptographic currency.',
          'Turner Broadcasting System' => 'Content provider for branded television network.',
          'Starbucks' => 'Mobile application for a ubiquitous chain of coffee shops.'
        };

--]]

require "DetectorCommon"


local DC = DetectorCommon

DetectorPackageInfo = {
    name =  "payload_group_Queen",
    proto =  DC.ipproto.tcp,
    client = {
        init =  'DetectorInit',
        clean =  'DetectorClean',
        minimum_matches =  1
    }
}

--serviceId, clientId, ClientType, PayloadId, PayloadType, hostPattern, pathPattern, schemePattern, queryPattern
gUrlPatternList = {

   --CBS   
    { 0, 0, 0, 980, 22, "cbsstatic.com", "/", "http:", "", 1332},
    { 0, 0, 0, 980, 22, "cbslocal.com", "/", "http:", "", 1332},
    { 0, 0, 0, 980, 22, "cbsnews.com", "/", "http:", "", 1332},
   --FOX   
    { 0, 0, 0, 981, 22, "fox.com", "/", "http:", "", 2050},
    { 0, 0, 0, 981, 22, "foxnetworks.tt.omtrdc.net", "/", "http:", "", 2050},
    { 0, 0, 0, 981, 22, "foxnet.demdex.net", "/", "http:", "", 2050},
    { 0, 0, 0, 981, 22, "fbchdvod-f.akamaihd.net", "/z/Fox.com", "http:", "", 2050},
   --Washington Times
    { 0, 0, 0, 982, 33, "washingtontimes.com", "/", "http:", "", 2051},
    { 0, 0, 0, 982, 33, "washtimes.com", "/", "http:", "", 2051},
    { 0, 0, 0, 982, 33, "washtimes.disqus.com", "/", "http:", "", 2051},
    { 0, 0, 0, 982, 33, "chartbeat.net", "/", "http:", "washingtontimes", 2051},
   --NextBus
    { 0, 0, 0, 983, 22, "nextbus.com", "/", "http:", "", 2052},
   --OpenBSD
    { 0, 0, 0, 984, 22, "openbsd.com", "/", "http:", "", 2053},
    { 0, 0, 0, 984, 22, "openbsd.org", "/", "http:", "", 2053},
   -- Associated Press
    { 0, 0, 0, 985, 33, "ap.org", "/", "http:", "", 2054},
   -- WTOP 
    { 0, 0, 0, 986, 22, "wtop.com", "/", "http:", "", 2055},
   -- OpenSUSE
    { 0, 0, 0, 987, 22, "opensuse.org", "/", "http:", "", 2056},
    { 0, 0, 0, 987, 22, "opensuse.com", "/", "http:", "", 2056},
   -- Turner Broadcasting System
    { 0, 0, 0, 988, 22, "turner.com", "/", "http:", "", 2057},
   -- NCAA
    { 0, 0, 0, 989, 22, "ncaa.com", "/", "http:", "", 2058},
    { 0, 0, 0, 989, 22, "ncaa.org", "/", "http:", "", 2058},
    { 0, 0, 0, 989, 22, "turner.com", "/NCAA/", "http:", "", 2058},
   -- Yahoo
    { 0, 0, 0, 990, 22, "yahoo.net", "/", "http:", "", 524},
    { 0, 0, 0, 990, 22, "yimg.com", "/", "http:", "", 524},
   -- DSW 
    { 0, 0, 0, 991, 22, "dsw.com", "/", "http:", "", 2059},
    { 0, 0, 0, 991, 22, "dsw.112.2o7.net", "/", "http:", "", 2059},
    { 0, 0, 0, 991, 22, "scene7.com", "/DSWShoes/", "http:", "", 2059},
   -- Po.st
    { 0, 0, 0, 992, 22, "po.st", "/", "http:", "", 2060},
   -- CheapStuff
    { 0, 0, 0, 993, 22, "cheapstuff.com", "/", "http:", "", 2061},
   -- Livefyre
    { 0, 0, 0, 994, 22, "livefyre.com", "/", "http:", "", 2062},
   -- FreeStreams
    { 0, 0, 0, 995, 22, "freestreams.com", "/", "http:", "", 2063},
   -- Clear Channel
    { 0, 0, 0, 996, 22, "clearchannel.com", "/", "http:", "", 2064},
    { 0, 0, 0, 996, 22, "clearchannelinternational.com", "/", "http:", "", 2064},
   -- GOLF.com
    { 0, 0, 0, 997, 22, "golf.com", "/", "http:", "", 2065},
    { 0, 0, 0, 997, 22, "cdn.turner.com", "/dr/golf", "http:", "", 2065},
   -- Glam 
    { 0, 0, 0, 998, 22, "glam.com", "/", "http:", "", 2066},
    { 0, 0, 0, 998, 22, "ning.com", "/", "http:", "", 2066},
    { 0, 0, 0, 998, 22, "glammedia.com", "/", "http:", "", 2066},
   -- BoldChat
    { 0, 0, 0, 999, 22, "boldchat.com", "/", "http:", "", 2067},
   -- Intermarkets
    { 0, 0, 0, 1000, 22, "intermarkets.net", "/", "http:", "", 2068},
   -- Woopra
    { 0, 0, 0, 1001, 22, "woopra.com", "/", "http:", "", 2069},
    { 0, 0, 0, 1001, 22, "disqus.com", "/woopra/", "http:", "", 2069},
   -- OCLC
    { 0, 0, 0, 1002, 22, "oclc.org", "/", "http:", "", 2070},
    { 0, 0, 0, 1002, 22, "oclc.com", "/", "http:", "", 2070},
   -- Chosun
    { 0, 0, 0, 1003, 22, "chosun.com", "/", "http:", "", 2071},
   -- Ooyala
    { 0, 0, 0, 1004, 22, "ooyala.com", "/", "http:", "", 2072},
   -- C-SPAN
    { 0, 0, 0, 1005, 22, "c-span.org", "/", "http:", "", 2074},
    { 0, 0, 0, 1005, 22, "c-spanvideo.org", "/", "http:", "", 2074},
    { 0, 0, 0, 1005, 22, "c-spanarchives.org", "/", "http:", "", 2074},
    -- Game Front
    { 0, 0, 0, 1006, 34, "gamefront.com", "/", "http:", "", 2082},
    -- BitCoin
    { 0, 0, 0, 1007, 41, "bitcoin.org", "/", "http:", "", 2083},
    -- LiteCoin
    { 0, 0, 0, 1008, 41, "litecoin.org", "/", "http:", "", 2084},
    { 0, 0, 0, 1008, 41, "give-me-ltc.com", "/", "http:", "", 2084},
    -- lynda.com
    { 0, 0, 0, 1010, 12, "lynda.com", "/", "http:", "", 2086},
    -- Letterpress
    { 0, 0, 0, 1011, 20, "atebits.com", "/letterpress", "http:", "", 2091},
    -- Game Center
    { 0, 0, 0, 1012, 20, "gc.apple.com", "/", "http:", "", 2092},
   -- FriendFinder
    { 0, 0, 0, 1013, 22, "friendfinder.com", "/", "http:", "", 2093},
    { 0, 0, 0, 1013, 22, "pop6.com", "/", "http:", "", 2093},
   -- Audible.com
    { 0, 0, 0, 1014, 22, "audible.com", "/", "http:", "", 2094},
    { 0, 0, 0, 1014, 22, "audible.tt.omtrdc.net", "/", "http:", "", 2094},
   -- Entertainment Weekly
    { 0, 0, 0, 1015, 22, "ew.com", "/", "http:", "", 2095},
    { 0, 0, 0, 1015, 22, "timeinc.net", "/ew/", "http:", "", 2095},
   -- Adobe
    { 0, 0, 0, 21, 22, "macromedia.com", "/", "http:", "", 541},
    { 0, 0, 0, 21, 22, "adobe.com", "/", "http:", "", 541},
   -- Docstoc
    { 0, 0, 0, 1016, 22, "docstoc.com", "/upload", "http:", "", 2102},
    { 0, 0, 0, 1016, 22, "docstoccdn.com", "/upload", "http:", "", 2102},
    { 0, 0, 0, 1016, 22, "docstoccdn.com", "/js/upload-edit", "http:", "", 2102},
   -- Speedtest 
    { 0, 0, 0, 1017, 22, "speedtest.net", "/", "http:", "", 2103},
    { 0, 0, 0, 1017, 22, "speedtest.consolidated.net", "/", "http:", "", 2103},
   -- Boxnet Upload
    { 0, 0, 0, 1018, 22, "upload.box.com", "/", "http:", "", 2104},
   -- Flickr Upload
    { 0, 0, 0, 1019, 22, "flickr.com", "/services/upload/", "http:", "", 2105},
    { 0, 0, 0, 1019, 22, "flickr.com", "/upload", "http:", "", 2105},
    { 0, 0, 0, 1019, 22, "flickr.com", "/beacon_uploadr_timings", "http:", "", 2105},
    { 0, 0, 0, 1019, 22, "up.flickr.com", "/services/upload/", "http:", "", 2105},
    { 0, 0, 0, 1019, 22, "flickr.com", "/photos/upload/", "http:", "", 2105},
   -- Scribd Upload
    { 0, 0, 0, 1020, 22, "scribd.com", "/newupload", "http:", "", 2106},
    { 0, 0, 0, 1020, 22, "scribd.com", "/newuploads", "http:", "", 2106},
    { 0, 0, 0, 1020, 22, "scribd.com", "/upload-document", "http:", "", 2106},
   -- Youtube Upload
    { 0, 0, 0, 1021, 22, "youtube.com", "/upload", "http:", "", 2107},
    { 0, 0, 0, 1021, 22, "ytimg.com", "/yts/img/upload", "http:", "", 2107},
    { 0, 0, 0, 1021, 22, "upload.youtube.com", "/", "http:", "", 2107},
   -- ShareFile Upload
    { 0, 0, 0, 1022, 22, "sharefile.com", "/upload-threaded-1.aspx", "http:", "", 3861},
   -- Windows Azure
    { 0, 0, 0, 1025, 22, "windowsazure.com", "/", "http:", "", 2111},
    { 0, 0, 0, 1025, 22, "thewindowsazureproductsite.disqus.com", "/", "http:", "", 2111},
    { 0, 0, 0, 1025, 22, "msecnd.net", "/", "http:", "", 2111},
    { 0, 0, 0, 1025, 22, "windows.net", "/", "http:", "", 2111},
    -- Starbucks
    { 0, 0, 0, 1026, 45, "starbucks.com", "/", "http:", "", 2112},
}


function DetectorInit(detectorInstance)

    gDetector = detectorInstance;

    gDetector:addHttpPattern(2, 5, 0, 276, 24, 0, 0, 'Starbucks', 2112);

    if gDetector.addAppUrl then
        for i,v in ipairs(gUrlPatternList) do
            gDetector:addAppUrl(v[1],v[2],v[3],v[4],v[5],v[6],v[7],v[8],v[9],v[10]);
        end
    end

    return gDetector;
end

function DetectorClean()
end

