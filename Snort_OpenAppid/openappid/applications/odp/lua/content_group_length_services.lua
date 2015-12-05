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
detection_name: Content Group "Length Services"
version: 1
description: Group of Length Service detectors.
bundle_description: $VAR1 = {
          'keyholetv' => 'An online television portal that links to Japanese television channels, radio stations, and user-made channels.'
        };

--]]

require "DetectorCommon"

local DC = DetectorCommon

DetectorPackageInfo = {
    name = "content_group_length_services",
    proto =  DC.ipproto.udp,
    client = {
        init =  'DetectorInit',
        clean =  'DetectorClean',
        minimum_matches =  1
    }
}

-- "appId", "proto", "sequence_cnt", "sequence_str"
gLengthServiceList = {

    -- KeyHoleTV
    {3823, 17, 5, "I/8,R/512,I/512,R/1024,I/1024"},

}

function DetectorInit(detectorInstance)

    gDetector = detectorInstance;

    if gDetector.AddLengthBasedDetector then
        for i,v in ipairs(gLengthServiceList) do
            gDetector:AddLengthBasedDetector(v[1], v[2], v[3], v[4]);
        end
    end
    return gDetector;
end

function DetectorClean()
end

