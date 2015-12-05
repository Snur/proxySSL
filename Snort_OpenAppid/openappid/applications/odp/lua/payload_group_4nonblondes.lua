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
detection_name: Payload Group "4nonblondes"
version: 2
description: Group of payload detectors.
bundle_description: $VAR1 = {
          'People\'s Daily' => 'Chinese news website.',
          'Neobux' => 'A site that pays users to view ads and recruit their friends.',
          'Kickass Torrents' => 'Torrent site.',
          '360 Safeguard' => 'Chinese anti-virus software.',
          'China Daily' => 'Chinese news site.',
          'Vube' => 'Video upload and sharing site.',
          'Guangming Online' => 'Chinese news site.',
          'RevenueHits' => 'Ad site.'
        };

--]]

require "DetectorCommon"


local DC = DetectorCommon

DetectorPackageInfo = {
    name =  "payload_group_4nonblondes",
    proto =  DC.ipproto.tcp,
    client = {
        init =  'DetectorInit',
        clean =  'DetectorClean',
        minimum_matches =  1
    }
}

gUrlPatternList = {

    -- 350 Safeguard
    { 0, 0, 0, 1648, 11, "360.cn", "/", "http:", "", 3866},

    -- neobux
    { 0, 0, 0, 1649, 15, "neobux.com", "/", "http:", "", 3867},

    -- People's Daily
    { 0, 0, 0, 1650, 33, "people.com.cn", "/", "http:", "", 3868},

    -- Vube
    { 0, 0, 0, 1651, 13, "vube.com", "/", "http:", "", 3869},

    -- Kickass Torrents
    { 0, 0, 0, 1652, 9, "kickass.to", "/", "http:", "", 3870},
    { 0, 0, 0, 1652, 9, "kickasstorrents.eu", "/", "http:", "", 3870},
    { 0, 0, 0, 1652, 9, "kickass.so", "/", "http:", "", 3870},

    -- China Daily
    { 0, 0, 0, 1653, 33, "chinadaily.com.cn", "/", "http:", "", 3871},

    -- Guangming Online
    { 0, 0, 0, 1654, 33, "gmw.cn", "/", "http:", "", 3872},

    -- RevenueHits
    { 0, 0, 0, 1655, 15, "revenuehits.com", "/", "http:", "", 3873},
    { 0, 0, 0, 1655, 15, "clkmon.com", "/", "http:", "", 3873},
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

