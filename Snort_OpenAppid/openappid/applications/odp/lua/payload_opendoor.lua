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
detection_name: OpenDoor
version: 2
description: Web anonymizer for iOS.
bundle_description: $VAR1 = {
          'OpenDoor' => 'Web anonymizer for iOS.'
        };

--]]

require "DetectorCommon"


local DC = DetectorCommon

DetectorPackageInfo = {
    name =  "OpenDoor",
    proto =  DC.ipproto.tcp,
    client = {
        init =  'DetectorInit',
        clean =  'DetectorClean',
        validate =  'DetectorValidator',
        minimum_matches =  1
    }
}

gSSLHostPatternList = {
    { 0, 3733, '9956.com' },
    { 0, 3733, '7c3.com' },
    { 0, 3733, 'd55.com' },
    { 0, 3733, '1a8cf7.com' },
    { 0, 3733, '82adf.com' },
    { 0, 3733, 'fc0.com' },
    { 0, 3733, '68f1.com' },
    { 0, 3733, '698.com' },
    { 0, 3733, '90d.com' },
    { 0, 3733, '26d.com' },
    { 0, 3733, '2697.com' },
}

function DetectorClean()
end

function DetectorInit(detectorInstance)
    gDetector = detectorInstance;

    gDetector:addHttpPattern(2, 5, 0, 467, 1, 0, 0, 'OpenDoor', 3733, 1);

    if (gDetector.CHPCreateApp and gDetector.CHPAddAction) then
        gDetector:CHPCreateApp(3733, 6, 0);
        gDetector:CHPAddAction(3733, 1, 3, "com.backdoor", 0, "");
        gDetector:CHPAddAction(3733, 0, 3, "opendoor", 0, "");
    end 

    if gDetector.addSSLCertPattern then
        for i,v in ipairs(gSSLHostPatternList) do
            gDetector:addSSLCertPattern(v[1],v[2],v[3]);
        end
    end

    return gDetector
end

function DetectorValidator()
    local context = {}
    return serviceFail(context)
end

function DetectorFini()
end
