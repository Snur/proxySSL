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
detection_name: SSL Group "starsports"
version: 5
description: Group of SSL Host detectors.
bundle_description: $VAR1 = {
          'Starsports' => 'Live streaming sports from India.',
          'Periscope' => 'Mobile app for live video streaming.',
          'F-secure' => 'Antivirus software.',
          'SUPERAntiSpyware' => 'Antivirus / antimalware application.',
          'WhatsApp' => 'A cross-platform mobile messaging app which serves as a free alternative to SMS messages.',
          'ESPNcricinfo' => 'ESPN site focused on the game of Cricket.',
          'Meerkat' => 'Mobile app for live video streaming.',
          'Netflix' => 'Rental and on-demand internet television and movie streaming website.',
          'Malwarebytes' => 'Antimalware software.',
          'Amazon Instant Video' => 'Amazon video streaming site.'
        };

--]]

require "DetectorCommon"


local DC = DetectorCommon

DetectorPackageInfo = {
    name =  "ssl_host_group_drambuie",
    proto =  DC.ipproto.tcp,
    client = {
        init =  'DetectorInit',
        clean =  'DetectorClean',
        minimum_matches =  1
    }
}

gSSLHostPatternList = {

    -- Starsports
    { 0, 3977, 'starsports.com' },

    -- ESPNcricinfo
    { 0, 3978, 'espncricinfo.com' },

    -- F-secure
    { 0, 3989, 'F-Secure Corporation' },
    { 0, 3990, 'f-secure.com' },

    -- malwarebytes
    { 0, 3990, 'Malwarebytes Corporation' },
    { 0, 3990, 'mwbsys.com' },
    { 0, 3990, 'malwarebytes.org' },

    --WhatsApp
    { 1, 1143, 'whatsapp.net' },
    { 0, 1143, 'whatsapp.com' },
    --Amazon Instant Video
    { 0, 3793, 'atv-ext.amazon.com' },
    { 0, 3793, 'atv-ps.amazon.com' },
    --Meerkat
    { 1, 3993, 'meerkatapp.co' },
    --Periscope
    { 0, 3992, 'periscope.tv' },
    --NetFlix
    { 0, 756, 'netflix.com' },
    { 0, 756, 'nflxext.com' },
    { 0, 756, 'nflximg.net' },
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

