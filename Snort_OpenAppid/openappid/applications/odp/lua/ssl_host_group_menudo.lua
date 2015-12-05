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
detection_name: SSL Group "Menudo"
version: 6
description: Group of SSL Host detectors.
bundle_description: $VAR1 = {
          'Ning' => 'Social Networking.',
          'QualysGuard' => 'Cloud security and compliance solutions.',
          'Trend Micro' => 'Security software company.',
          'MyLife' => 'Social Networking.',
          'GitHub' => 'Code management portal for open Source projects.',
          'Kickstarter' => 'Platform for creative projects with funding goal and deadline.',
          'Gravatar' => 'Profile picture management for comments and discussion forum.',
          'The Washington Post' => 'American daily newspaper.',
          'Fancy' => 'Social media to share and buy items.',
          'textPlus' => 'Application which support free text, group chat and calls.',
          'ChatON' => 'Mobile chat service provided.',
          'Webshots' => 'Service for uploading and sharing photos and videos.'
        };

--]]

require "DetectorCommon"


local DC = DetectorCommon

DetectorPackageInfo = {
    name =  "ssl_host_group_menudo",
    proto =  DC.ipproto.tcp,
    client = {
        init =  'DetectorInit',
        clean =  'DetectorClean',
        minimum_matches =  1
    }
}

--serviceId, clientId, ClientType, PayloadId, PayloadType, hostPattern, pathPattern, schemePattern, queryPattern
gSSLHostPatternList = {

    -- Fancy 
    { 0, 1668, 'thefancy.com' },
    { 0, 1668, 'www.thefancy.com' },
    -- ChatON
    { 1, 1669, 'us.contact.samsungchaton.com' },
    { 1, 1669, 'samsungchaton.com' },
    -- GitHub
    { 0, 1670, 'github.com' },
    { 0, 1670, 'github-central.s3.amazonaws.com' },
    { 0, 1670, 'github.s3.amazonaws.com' },
    { 0, 1670, 'github-image.s3.amazonaws.com' },
    { 0, 1670, 'github.global.ssl.fastly.net' },
    -- Trend Micro
    { 0, 1671, 'trendmicro.com' },
    -- WebShots
    { 0, 1021, 'www.webshots.com' },
    -- Qualys 
    { 0, 1675, 'qualys.com' },
    -- MyLife 
    { 0, 1702, 'mylife.com' },
    -- Ning 
    { 0, 1703, 'ning.com' },
    -- Gravatar
    { 0, 1704, 'gravatar.com' },
    -- Kickstarter
    { 0, 1705, 'kickstarter.com' },
    -- Google Publisher Tag
    --{ 0, 1706, 'googletagservices.com' },
    -- The Washington Post 
    { 0, 1709, 'washingtonpost.com' },
     -- textPlus
    { 1, 1611, 'gogii.com' },

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

