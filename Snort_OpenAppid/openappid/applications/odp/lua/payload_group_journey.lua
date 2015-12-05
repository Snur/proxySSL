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
detection_name: Payload Group "Journey"
version: 9
description: Group of payload detectors.
bundle_description: $VAR1 = {
          'Greystripe' => 'Web advertisement services.',
          'Weather Underground' => 'Weather web portal.',
          'Naver' => 'Web portal.',
          'Babylon' => 'Search engine, Translation and Dictionary toolbar.',
          'Kanoodle' => 'Web advertisement services.',
          'Doubleclick' => 'Web advertisement services.',
          'DCinside' => 'Internet forum for photography and Digital camera.',
          'iAd' => 'Web advertisement services.',
          'Burstly' => 'Web advertisement services.',
          'OnLive' => 'Online gaming portal.',
          'Yahoo! Finance' => 'Yahoo! Stock and finance website.',
          'Clubbox' => 'Korean online movie/channel/music.',
          'The New York Times' => 'Newspaper website.',
          'Pubmatic' => 'Web advertisement services.',
          'GO.com' => 'Web portal.',
          'Microsoft Ads' => 'Web advertisement services.',
          'Silverlight' => 'Microsoft rich internet application framework.',
          'Ad Advisor' => 'Web advertisement services.',
          'Isoball' => 'Web game where you must construct a track to lead a ball into a hole.',
          'Pulse360' => 'Web advertisement services.',
          'Nate' => 'Web portal and Search engine.',
          'Angry Birds' => 'Catapult game.',
          'Ad Nexus' => 'Web advertisement services.',
          'Kiwoom' => 'Investment firm.',
          'Twitter Link Service' => 't.co, Twitter\'s URL redirect service.',
          'Fileguri' => 'Korean file sharing web site.',
          'Advertising.com' => 'Web advertisement services.',
          'Baidu' => 'Chinese Search engine.',
          'Millennial Media' => 'Web advertisement services.',
          'Ad Mob' => 'Web advertisement services.',
          'Ad Marvel' => 'Web advertisement services.'
        };

--]]

require "DetectorCommon"


local DC = DetectorCommon

DetectorPackageInfo = {
    name =  "payload_group_journey",
    proto =  DC.ipproto.tcp,
    client = {
        init =  'DetectorInit',
        clean =  'DetectorClean',
        minimum_matches =  1
    }
}

--serviceId, clientId, ClientType, PayloadId, PayloadType, hostPattern, pathPattern, schemePattern, queryPattern
gUrlPatternList = {

    -- The New York Times
    { 0, 0, 0, 487, 33, "nytimes.com", "/", "http:", "", 1299 },
    { 0, 0, 0, 487, 33, "nyt.com", "/", "http:", "", 1299 },
    -- t.co
    { 0, 0, 0, 488, 14, "t.co", "/", "http:", "", 1300 },
    -- Yahoo! Finance
    { 0, 0, 0, 489, 39, "finance.yahoo.com", "/", "http:", "", 1301 },
    -- Silverlight
    { 0, 0, 0, 490, 1, "silverlight.net", "/", "http:", "", 1302 },
    -- Isoball
    { 0, 0, 0, 491, 20, "officewebgames.com", "/web-store/isoball.php", "http:", "", 1303 },
    -- GO.com
    { 0, 0, 0, 492, 22, "go.com", "/", "http:", "", 1304 },
    -- OnLive
    { 0, 0, 0, 493, 20, "onlive.com", "/", "http:", "", 1305 },
    -- Ad Advisor
    { 0, 0, 0, 494, 16, "adadvisor.net", "/", "http:", "", 1306 },
    -- Ad Mob
    { 0, 0, 0, 495, 16, "admob.com", "/", "http:", "", 1307 },
    -- Ad marvel
    { 0, 0, 0, 496, 16, "admarvel.com", "/", "http:", "", 1308 },
    -- Naver
    { 0, 0, 0, 497, 22, "naver.com", "/", "http:", "", 1309 },
    { 0, 0, 0, 497, 22, "naver.net", "/", "http:", "", 1309 },
    { 0, 0, 0, 497, 22, "naver.jp", "/", "http:", "", 1309 },
    -- Advertising.com
    { 0, 0, 0, 498, 16, "advertising.com", "/", "http:", "", 1310}, 	
    -- Ad Whirl
    --{ 0, 0, 0, 499, 16, "adwhirl.com", "/", "http:", "", 1311}, 	
    -- Burstly 
    { 0, 0, 0, 500, 16, "appads.com", "/", "http:", "", 1312}, 	
    { 0, 0, 0, 500, 16, "burstly.com", "/", "http:", "", 1312},
    -- DoubleClick 
    { 0, 0, 0, 501, 16, "doubleclick.net", "/", "http:", "", 1313}, 	
    { 0, 0, 0, 501, 16, "doubleclick.com", "/", "http:", "", 1313}, 	
    -- Ad Nexus 
    { 0, 0, 0, 502, 16, "ib.adnxs.com", "/", "http:", "", 1314}, 	
    -- Pubmatic 
    { 0, 0, 0, 503, 16, "pubmatic.com", "/", "http:", "", 1315}, 	
    -- Pulse 360
    { 0, 0, 0, 504, 16, "pulse360.com", "/", "http:", "", 1316}, 	
    -- Kanoodle
    { 0, 0, 0, 505, 16, "kanoodle.com", "/", "http:", "", 1317}, 	
    -- Greystripe
    { 0, 0, 0, 506, 16, "greystripe.com", "/", "http:", "", 1318}, 	
    -- iAd ad portal
    { 0, 0, 0, 507, 16, "advertising.apple.com", "/", "http:", "", 1319}, 	
    -- Microsoft Ads
    { 0, 0, 0, 508, 16, "adcenter.microsoft.com", "/", "http:", "", 1336}, 	
    { 0, 0, 0, 508, 16, "bingads.microsoft.com", "/", "http:", "", 1336}, 	
    -- Millennial Media
    { 0, 0, 0, 509, 16, "millennialmedia.com", "/", "http:", "", 1337}, 	
    { 0, 0, 0, 509, 16, "ads.mp.mydas.mobi", "/", "http:", "", 1337},
    --Angry Birds
    { 0, 0, 0, 443, 20, "chrome.angrybirds.com", "/", "http:", "", 1162},
    --Weather web portal 
    { 0, 0, 0, 510, 22, "wunderground.com", "/", "http:", "", 1338},
    { 0, 0, 0, 510, 22, "wxug.com", "/", "http:", "", 1338},
    --Korean Messenger BuddyBuddy
    -- { 0, 0, 0, 511,10, "buddybuddy.co.kr", "/", "http:", "", 1339},
    --Korean online movie/channel/music
    { 0, 0, 0, 512,10, "clubbox.co.kr", "/", "http:", "", 1340},
    --Korean investment firm 
    { 0, 0, 0, 513,22, "kiwoom.com", "/", "http:", "", 1341},
    --Korean Internet Forum for photography 
    { 0, 0, 0, 514,22, "dcinside.com", "/", "http:", "", 1342},
    --Korean web portal and search engine 
    { 0, 0, 0, 515,22, "nate.com", "/", "http:", "", 1343},
    --Korean file sharing web site 
    { 0, 0, 0, 516,9, "fileguri.com", "/", "http:", "", 1344},
    --Chinese Search engine  
    { 0, 0, 0, 517,22, "baidu.com", "/", "http:", "", 1345},
    { 0, 0, 0, 517,22, "bdstatic.com", "/", "http:", "", 1345},
    --Search engine, Dictionary and Translations 
    { 0, 0, 0, 518,22, "babylon.com", "/", "http:", "", 1346},

}

function DetectorInit(detectorInstance)

    gDetector = detectorInstance;

    -- Naver
    gDetector:addHttpPattern(2, 5, 0, 384, 19, 0, 0, 'NaverSearch', 1309); 

    if gDetector.addAppUrl then
        for i,v in ipairs(gUrlPatternList) do
            gDetector:addAppUrl(v[1],v[2],v[3],v[4],v[5],v[6],v[7],v[8],v[9],v[10]);
        end
    end
    return gDetector;
end

function DetectorClean()
end

