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
detection_name: SSL Group "X"
version: 1
description: Group of SSL Host detectors.
bundle_description: $VAR1 = {
          'Google Accounts Authentication' => 'Login process for Google sites.',
          'Yahoo! Accounts' => 'Login session for Yahoo! Accounts.',
          'Microsoft Windows Live Services Authentication' => 'Login process for Windows sites.',
          'VMware Horizon View' => 'Virtual desktop infrastructure for managing, providing desktop to users.'
        };

--]]

require "DetectorCommon"


local DC = DetectorCommon

DetectorPackageInfo = {
    name =  "ssl_host_group_x",
    proto =  DC.ipproto.tcp,
    client = {
        init =  'DetectorInit',
        clean =  'DetectorClean',
        minimum_matches =  1
    }
}

--detectorType(0-> Web, 1->Client),  AppId, SSLPattern
gSSLHostPatternList = {

    -- VMware Horizon View
    { 1, 2899, 'viewConnSrv.vmware.pl.cisco' },
    -- Microsoft Windows Live Services Authentication
    { 0, 2900, 'login.live.com' },
    { 0, 2900, 'profile.live.com' },
    { 0, 2900, 'signout.live.com' },
    { 0, 2900, 'signup.live.com' },
    { 0, 2900, 'accountservices.msn.com' },
    { 0, 2900, 'secure.wlxrs.com' },
    { 0, 2900, 'auth.gfx.ms.com' },
    { 0, 2900, 'account.live.com' },
    -- Google Account Authentication
    { 0, 2901, 'accounts.google.com' },
    { 0, 2901, 'youtube.google.com' },
    -- Yahoo! Accounts
    { 0, 2926, 'login.yahoo.com' },
    { 0, 2926, 'mobile.login.yahoo.com' },
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

