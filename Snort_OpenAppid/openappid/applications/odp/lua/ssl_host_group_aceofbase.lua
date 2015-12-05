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
detection_name: SSL Group "AceOfBase"
version: 2
description: Group of SSL Host detectors.
bundle_description: $VAR1 = {
          'JoinMe' => 'Video, Audio and Text Conferencing provider.',
          'Brewster' => 'Consolidated address book with sync\'d up contacts from Linked, Facebook, Gmail and other apps.',
          'EA Download Manager' => 'Electronic Arts Download manager is a digital distribution for EA games.',
          'Victoria\'s Secret' => 'Woman\'s wear, lingerie, and beauty product retailer.'
        };

--]]

require "DetectorCommon"


local DC = DetectorCommon

DetectorPackageInfo = {
    name =  "ssl_host_group_aceofbase",
    proto =  DC.ipproto.tcp,
    client = {
        init =  'DetectorInit',
        clean =  'DetectorClean',
        minimum_matches =  1
    }
}

gSSLHostPatternList = {
    --JoinMe
    { 1, 4019, 'join.me' },
    --Victoria's Secret
    { 0, 892 , 'victoriassecret.com' },
    --EA Download Manager
    { 1, 4016, 'dm.origin.com' },
    { 1, 4016, 'groups.gameservices.ea.com' },
    { 1, 4016, 'chat.dm.origin.com' },
    { 1, 4016, 'atom.dm.origin.com' },
    { 1, 4016, 'web.dm.origin.com' },
    { 1, 4016, 'avatar.dm.origin.com' },
    --Brewster
    { 1, 4014, 'brewster.com' },
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
