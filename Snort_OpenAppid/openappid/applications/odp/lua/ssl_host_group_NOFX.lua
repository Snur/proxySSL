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
detection_name: SSL Group "NOFX"
version: 4
description: Group of SSL Host detectors.
bundle_description: $VAR1 = {
          'Megaupload' => 'File transfer application.',
          'AIM Express' => 'Browser-based client for AIM.',
          'MySpace' => 'MySpace is a social networking service.',
          'Raptr' => 'Social Network for video game player.',
          'Google News' => 'Automated news aggregator.',
          'Google Calendar' => 'A free time-management web application offered by Google.'
        };

--]]

require "DetectorCommon"


local DC = DetectorCommon

DetectorPackageInfo = {
    name =  "ssl_host_group_NOFX",
    proto =  DC.ipproto.tcp,
    client = {
        init =  'DetectorInit',
        clean =  'DetectorClean',
        minimum_matches =  1
    }
}

--serviceId, clientId, ClientType, PayloadId, PayloadType, hostPattern, pathPattern, schemePattern, queryPattern
gSSLHostPatternList = {

    -- Raptr 
    { 0, 1757, 'raptr.com' },
    { 0, 949, 'mega.co.nz' },
    { 0, 1759, 'api.screenname.aol.com'},
    -- Google Calendar
    { 0, 661, 'calendar.google.com' },
    -- MySpace
    { 0, 317, 'myspacecdn.com' },
    { 0, 317, 'myspace.com' },
    -- Google News
    { 0, 663, 'news.google.com' },
}

function DetectorInit(detectorInstance)

    gDetector = detectorInstance;

    if gDetector.addSSLCertPattern then
        for i,v in ipairs(gSSLHostPatternList) do
            gDetector:addSSLCertPattern(v[1],v[2],v[3]);
        end
    end
    return gDetector;
end

function DetectorClean()
end

