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
detection_name: Payload Group "HuskerDu"
version: 9
description: Group of payload detectors.
bundle_description: $VAR1 = {
          'Spotify' => 'Social Music Player.',
          'Diamond Dash' => 'Matching game for Facebook.',
          'Farmville' => 'A real-time farm simulation game developed by Zynga, available for Facebook and the iPhone.',
          'Tetris Battle' => 'Tetris for Facebook.',
          'Castleville' => 'Castle building game.',
          'Cityville' => 'Social city-building game.',
          'Angry Birds' => 'Catapult game.',
          'Bubble Witch Saga' => 'Witch-themed, bubble-bursting Facebook game.',
          'Words With Friends' => 'Word game.'
        };

--]]

require "DetectorCommon"


local DC = DetectorCommon

DetectorPackageInfo = {
    name =  "payload_group_huskerdu",
    proto =  DC.ipproto.tcp,
    client = {
        init =  'DetectorInit',
        clean =  'DetectorClean',
        minimum_matches =  1
    }
}

--serviceId, clientId, ClientType, PayloadId, PayloadType, hostPattern, pathPattern, schemePattern, queryPattern
gUrlPatternList = {

    -- Tetris Battle
    -- { 0, 0, 0, 438, 20, "apps.facebook.com", "/tetris_battle", "http:", "", 1157 },
    { 0, 0, 0, 438, 20, "tetrisfb.com", "/", "http:", "", 1157 },
    -- Spotify
    { 0, 123, 19, 575, 22, "spotify.com", "/", "http:", "", 1158 },
    { 0, 123, 19, 575, 22, "spotify.edgekey.net", "/", "http:", "", 1158},
    -- Bubblewitch
    -- { 0, 0, 0, 439, 20, "apps.facebook.com", "/bubblewitch", "http:", "", 1159 },
    { 0, 0, 0, 439, 20, "bubblewitch.king.com", "/", "http:", "", 1159 },
    -- Farmville
    -- { 0, 0, 0, 440, 20, "apps.facebook.com", "/onthefarm", "http:", "", 151 },
    { 0, 0, 0, 440, 20, "farmville.com", "/", "http:", "", 151 },
    -- Sims Social
    -- { 0, 0, 0, 441, 20, "simssoc.game.playfish.com", "/", "http:", "", 1160 },
    -- { 0, 0, 0, 441, 20, "static-cdn.playfish.com", "/", "http:", "", 1160 },
    -- Diamond Dash
    { 0, 0, 0, 442, 20, "dd.wooga.com", "/", "http:", "", 1161 },
    { 0, 0, 0, 442, 20, "dd.t.wooga.com", "/", "http:", "", 1161 },
    -- Angrybirds
    { 0, 0, 0, 443, 20, "apps.facebook.com", "/angrybirds", "http:", "", 1162 },
    { 0, 0, 0, 443, 20, "angrybirds-facebook.appspot.com", "/", "http:", "", 1162 },
    -- Words With Friends
    -- { 0, 0, 0, 444, 20, "apps.facebook.com", "/wordswithfriends", "http:", "", 1163 },
    { 0, 0, 0, 444, 20, "zyngawithfriends.com", "/", "http:", "", 1163 },
    -- Castleville
    -- { 0, 0, 0, 445, 20, "apps.facebook.com", "/castleville", "http:", "", 1164 },
    { 0, 0, 0, 445, 20, "castle.zynga.com", "/", "http:", "", 1164 },
    -- Hidden Chronicles
    -- { 0, 0, 0, 446, 20, "apps.facebook.com", "/hidden-chronicles", "http:", "", 1165 },
    -- { 0, 0, 0, 446, 20, "hidden.zynga.com", "/", "http:", "", 1165 },
    -- Cityville
    -- { 0, 0, 0, 448, 20, "apps.facebook.com", "/cityville", "http:", "", 1166 },
    { 0, 0, 0, 448, 20, "cityville.zynga.com", "/", "http:", "", 1166 },
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

