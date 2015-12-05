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
detection_name: Payload Group "X"
version: 3
description: Group of payload detectors.
bundle_description: $VAR1 = {
          'iTunes iPhone' => 'iTunes for iPhone.',
          'Yahoo! Accounts' => 'Login session for Yahoo! Accounts.',
          'Facebook Utilities' => 'Utilities category in Facebook.',
          'R6 FeedFetcher' => 'Web crawler for Marketing companies.',
          'Facebook Notes' => 'Notes app in Facebook.',
          'Cisco Phone' => 'Cisco Phone using SIP traffic.',
          'Telepresence Control' => 'Cisco\'s protocol for Telepresence system.',
          'Facebook Applications Other' => 'Other Application categories in Facebook.',
          'iTunes iPad' => 'iTunes for iPad.',
          'Facebook Games' => 'Online games section of Facebook.',
          'iTunes iPod' => 'iTunes for iPod.',
          'LinkedIn Profile' => 'Profile page while browsing through LinkedIn.',
          'LinkedIn Inbox' => 'Inbox session of LinkedIn.',
          'Facebook Photos' => 'Photos traffic from Facebook.',
          'Facebook Sports' => 'Sports section of Facebook.'
        };

--]]

require "DetectorCommon"


local DC = DetectorCommon

DetectorPackageInfo = {
    name =  "payload_group_x",
    proto =  DC.ipproto.tcp,
    client = {
        init =  'DetectorInit',
        clean =  'DetectorClean',
        minimum_matches =  1
    }
}

--serviceId, clientId, ClientType, PayloadId, PayloadType, hostPattern, pathPattern, schemePattern, queryPattern
gUrlPatternList = {

    -- LinkedIn Profile
    { 0, 0, 0, 1358, 22, "linkedin.com", "/profile", "http:", "", 2903},
    -- LinkedIn Inbox
    { 0, 0, 0, 1359, 22, "linkedin.com", "/inbox", "http:", "", 2904},
    -- Facebook Notes
    { 0, 0, 0, 1360, 22, "facebook.com", "/notes", "http:", "", 3767},
    -- Facebook Utilities
    { 0, 0, 0, 1361, 22, "facebook.com", "/appcenter/category/utilities", "http:", "", 2909},
    -- Facebook Sports
    { 0, 0, 0, 1362, 22, "facebook.com", "/appcenter/category/sports", "http:", "", 2910},
    -- Facebook Games
    { 0, 0, 0, 1363, 22, "facebook.com", "/appcenter/category/games", "http:", "", 2911},
    -- Facebook Photos and Videos
    { 0, 0, 0, 1364, 22, "facebook.com", "/ajax/photo", "http:", "", 2925},
    { 0, 0, 0, 1364, 22, "facebook.com", "/hphotos", "http:", "", 2925},
    { 0, 0, 0, 1364, 22, "facebook.com", "/photos/clusters/", "http:", "", 2925},
    { 0, 0, 0, 1364, 22, "facebook.com", "/photo.php", "http:", "", 2925},
    { 0, 0, 0, 1364, 22, "facebook.com", "/photo_stream", "http:", "", 2925},
    { 0, 0, 0, 1364, 22, "facebook.com", "/photos", "http:", "", 2925},
    { 0, 0, 0, 1364, 22, "facebook.com", "/photos_albums", "http:", "", 2925},
    -- Yahoo! Account
    { 0, 0, 0, 1366, 22, "login.yahoo.com", "/", "http:", "", 2926},
    -- Faceboo Others
    { 0, 0, 0, 1367, 22, "facebook.com", "/appcenter/category/", "http:", "", 2935},

}
gSipUserAgentPatternList = {

    -- Entry Format is <clientAppId <int>, clientVersion (string), multipart pattern (string)> 
    -- from http://www.voip-info.org/wiki/view/SIP+user+agent+identification
   --Cisco Phone
    { 2902, "6", "CSCO"},
    { 2902, "6", "Cisc"},
    { 2902, "", "CSCO"},
    { 2902, "", "Cisc"},
    { 2942, "", "Cisco-Telepresence"},
}



function DetectorInit(detectorInstance)
    gDetector = detectorInstance;

    gDetector:addHttpPattern(2, 5, 0, 443, 20, 0, 0, 'R6_FeedFetcher', 2898, 1); 
    gDetector:addHttpPattern(2, 5, 0, 444, 18, 0, 0, 'iTunes-iPhone', 2905, 1); 
    gDetector:addHttpPattern(2, 5, 0, 445, 18, 0, 0, 'iTunes-iPod', 2906, 1); 
    gDetector:addHttpPattern(2, 5, 0, 446, 18, 0, 0, 'iTunes-iPad', 2907, 1); 
    if gDetector.addAppUrl then
        for i,v in ipairs(gUrlPatternList) do
            gDetector:addAppUrl(v[1],v[2],v[3],v[4],v[5],v[6],v[7],v[8],v[9],v[10]);
        end
    end

    if gDetector.addSipUserAgent then
        for i,v in ipairs(gSipUserAgentPatternList) do
            gDetector:addSipUserAgent(v[1],v[2],v[3]);
        end
    end


    return gDetector;
end

function DetectorClean()
end

