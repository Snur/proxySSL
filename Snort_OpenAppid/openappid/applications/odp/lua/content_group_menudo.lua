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
detection_name: Content Group "Menudo"
version: 3
description: Group of Content-Type detectors.
bundle_description: $VAR1 = {
          'Ogg' => 'Multimedia framework.',
          'WebM' => 'Free audio-video format.'
        };

--]]

require "DetectorCommon"

local DC = DetectorCommon

DetectorPackageInfo = {
    name = "content_group_menudo",
    proto =  DC.ipproto.tcp,
    client = {
        init =  'DetectorInit',
        clean =  'DetectorClean',
        minimum_matches =  1
    }
}

-- "header", "pattern", "data"
gContentTypePatternList = {
    -- Ogg
    { "application/ogg",      1672},
    { "video/ogg",            1672},
    { "audio/ogg",           1672},
    -- WebM
    { "video/webm",           1673},
    { "audio/webm",           1673},
    -- BitTorrent
    { "application/x-bittorrent", 61},
}

function DetectorInit(detectorInstance)

    gDetector = detectorInstance;

    if gDetector.addContentTypePattern then
        for i,v in ipairs(gContentTypePatternList) do
            gDetector:addContentTypePattern(v[1], v[2]);
        end
    end
    return gDetector;
end

function DetectorClean()
end
