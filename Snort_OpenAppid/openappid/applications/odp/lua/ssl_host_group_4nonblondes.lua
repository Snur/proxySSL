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
detection_name: SSL Group "4nonblondes"
version: 2
description: Group of SSL Host detectors.
bundle_description: $VAR1 = {
          'Kickass Torrents' => 'Torrent site.',
          'RevenueHits' => 'Ad site.',
          'Vube' => 'Video upload and sharing site.',
          'Neobux' => 'A site that pays users to view ads and recruit their friends.'
        };

--]]

require "DetectorCommon"


local DC = DetectorCommon

DetectorPackageInfo = {
    name =  "ssl_host_group_4nonblondes",
    proto =  DC.ipproto.tcp,
    client = {
        init =  'DetectorInit',
        clean =  'DetectorClean',
        minimum_matches =  1
    }
}

gSSLHostPatternList = {

    -- Neobux
    { 0, 3867, 'neobux.com' },

    -- Vube
    { 0, 3869, 'vube.com' },
    
    -- Kickass Torrents
    { 0, 3870, 'kickass.to' },
    { 0, 3870, 'kickass.so' },

    -- RevenueHits
    { 0, 3873, 'revenuehits.com' },
    { 0, 3873, 'clkmon.com' },
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

