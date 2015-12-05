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
detection_name: Content Group "Elvis"
version: 1
description: Group of Content-Type detectors.
bundle_description: $VAR1 = {
          'RealAudio' => 'RealNetworks\' proprietary audio format.',
          'ASF' => 'Microsoft\'s proprietary audio/video format.'
        };

--]]

require "DetectorCommon"

local DC = DetectorCommon

DetectorPackageInfo = {
    name = "content_group_elvis",
    proto =  DC.ipproto.tcp,
    client = {
        init =  'DetectorInit',
        clean =  'DetectorClean',
        minimum_matches =  1
    }
}

-- "header", "pattern", "data"
gContentTypePatternList = {
    { "application/vnd.ms-asf",      1110},
    { "video/x-ms-asf",              1110},
    { "audio/x-realaudio",           1089},
    { "audio/x-pn-realaudio",        1089},
    { "audio/vnd.rn-realaudio",      1089},
    { "audio/x-pn-realaudio-plugin", 1089},
    { "video/vnd.rn-realvideo",      1089},
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
