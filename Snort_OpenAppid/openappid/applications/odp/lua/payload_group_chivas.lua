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
detection_name: Payload Group "Chivas"
version: 8
description: Group of payload detectors.
bundle_description: $VAR1 = {
          'LinkedIn Upload' => 'Uploading resumes and other data to LinkedIn.',
          'ESPN Video' => 'Video streaming on ESPN.',
          'Kik Messenger' => 'Instant messenger for Smartphones.',
          'Crackle Video' => 'Video streaming from Crackle.'
        };

--]]

require "DetectorCommon"


local DC = DetectorCommon

DetectorPackageInfo = {
    name =  "payload_group_chivas",
    proto =  DC.ipproto.tcp,
    client = {
        init =  'DetectorInit',
        clean =  'DetectorClean',
        minimum_matches =  1
    }
}

gUrlPatternList = {
    -- LinkedIn Upload
    { 0, 0, 0, 1369, 23, "linkedin.com", "/upload", "http:", "", 2963},
    { 0, 0, 0, 1369, 23, "slideshare.www.linkedin.com", "/upload", "http:", "", 2963},
    -- Kik Messenger
    { 0, 0, 0, 1370, 23, "kik.com", "/", "http:", "", 3648},
}

--serviceId, clientId, ClientType, PayloadId, PayloadType, hostPattern, pathPattern, schemePattern, queryPattern
gRTMPPatternList = {
    --ESPN Video
    { 0, 0, 0, 2933, 0, "espn.go.com", "/", "http:", "", 2933},
    --Crackle Video
    { 0, 0, 0, 2955, 0, "crackle.com", "/", "http:", "", 2955},
}

function DetectorInit(detectorInstance)

    gDetector = detectorInstance;

    if gDetector.addRTMPUrl then
        for i,v in ipairs(gRTMPPatternList) do
            gDetector:addRTMPUrl(v[1],v[2],v[3],v[4],v[5],v[6],v[7],v[8],v[9],v[10]);
        end
    end

    if gDetector.addAppUrl then
        for i,v in ipairs(gUrlPatternList) do
            gDetector:addAppUrl(v[1],v[2],v[3],v[4],v[5],v[6],v[7],v[8],v[9],v[10]);
        end
    end
    return gDetector;
end

function DetectorClean()
end

