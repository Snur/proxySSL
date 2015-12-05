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
detection_name: SSL Group "TMBG"
version: 7
description: Group of SSL Host detectors.
bundle_description: $VAR1 = {
          'Stitcher' => 'Internet radio for news and talk shows.',
          'HBO GO' => 'Mobile app for HBO subscribers to watch HBO programming.',
          'Buffer' => 'App to share web pages with social media.',
          'Pocket' => 'App to save web pages.',
          'Panoramio' => 'Social network for sharing interesting places through photo.',
          'Ivacy Login' => 'Logging into Ivacy VPN, a firewall-bypassing service.',
          'Tunnelbear Login' => 'Logins to Tunnelbear, a web browsing anonymizer service.',
          'New Relic' => 'Web metrics site.',
          'Pinboard' => 'Social bookmarking portal.',
          'VyprVPN Login' => 'Logins to VyprVPN, a personal VPN service.',
          'iTunes Radio' => 'Internet radio by Apple.',
          'VMware vCenter client' => 'VMware vCenter client.',
          'Svpply' => 'Online shopping portal.',
          'GoodSync' => 'File transfer and synchronization service.',
          'Google URL Shortener' => 'Shortens URL for website.',
          'Dots' => 'Mobile game for connecting dots.',
          'Hotels.com' => 'Webportal for finding hotel deals and booking it online.',
          'ibVPN Login' => 'Logins to the ibVPN personal VPN service.',
          'Mathworks' => 'Producers of MATLAB and other tools for science and engineering.',
          'Hide My Ass!' => 'Web surfing anonymizer.',
          'WorldCat' => 'Library catalogue aggregator.',
          'VEVO.com' => 'Website for music videos.',
          'Cloudnymous Login' => 'Logins to Cloudynomous, a private VPN/anonymizer service.',
          'UpToDate' => 'Online clinical database for medical professionals.',
          'Pushover' => 'Push notification services.',
          'Instapaper' => 'App to save wb pages for later use.',
          'Break.com' => 'Web portal for sharing funny videos and pictures.',
          'JSTOR' => 'Digital library for academic journals and books.',
          'HBO' => 'Offical website for HBO shows.',
          'Cisco' => 'Official website for Cisco.',
          'NASA' => 'Web portal for NASA.',
          'Dilbert.com' => 'Offcial website for Dilbert, American comic strips.',
          'Xiami.com' => 'Chinese online music website.',
          'Ando Media' => 'Metrics and analytics for Internet radio.',
          'Dump Truck' => 'Cloud storage.',
          'Minus' => 'Website for file sharing.',
          'Boxoh' => 'A site that aggregates shipment tracking from different shipping providers.'
        };

--]]

require "DetectorCommon"


local DC = DetectorCommon

DetectorPackageInfo = {
    name =  "ssl_host_group_tmbg",
    proto =  DC.ipproto.tcp,
    client = {
        init =  'DetectorInit',
        clean =  'DetectorClean',
        minimum_matches =  1
    }
}

--serviceId, clientId, ClientType, PayloadId, PayloadType, hostPattern, pathPattern, schemePattern, queryPattern
gSSLHostPatternList = {

    -- Boxoh
    { 0, 2322, 'boxoh.com' },
    --  Svpply
    { 0, 2425, 'svpply.com' },
    --  Buffer
    { 1, 2428, 'bufferapp.com' },
    --  Pocket
    { 1, 2431, 'getpocket.com' },
    --  Instapaper
    { 1, 2434, 'instapaper.com' },
    { 1, 2434, 'staticinstapaper.s3.amazonaws.com' },
    --  Moped
    --{ 1, 2436, 'mopedlabs.s3.amazonaws.com' },
    --{ 1, 2436, 'moped-media.s3.amazonaws.com' },
    --{ 1, 2436, 'moped.com' },
    --  Pinboard
    { 0, 2437, 'pinboard.in' },
    --  Pushover
    { 1, 2438, 'pushover.net' },
    --  Dots
    { 1, 2440, 'weplaydots.com' },
    -- Dump Truck
    { 0, 2637, 'dumptruck.goldenfrog.com' },
    -- VyprVPN Login
    { 0, 2644, 'api.goldenfrog.com' },
    -- Tunnelbear
    { 0, 2645, 'tunnelbear.com' },
    -- Ivacy Login
    { 0, 2646, 'ivacy.com' },
    -- Hide My Ass!
    { 0, 2648, 'hidemyass.com' },
    -- ibVPN Login
    { 0, 2680, 'ibvpn.com' },
    -- Cloudnymous Login
    { 0, 2682, 'cloudnymous.com' },
    -- Samsung Wallet
    --{ 1, 2649, 'wallet.samsung.com' },
    -- VEVO.com
    { 0, 2650, 'vevo.com' },
    -- HBO
    { 0, 2652, 'hbo.com' },
    -- HBO Go
    { 0, 2711, 'hbogo.com' },
    -- Stitcher
    { 0, 2653, 'stitcher.com' },
    -- Panoramio
    { 0, 2654, 'panoramio.com' },
    -- Cisco
    { 0, 2655, 'cisco.com' },
    -- Dilbert.com
    { 0, 2657, 'thedilbertstore.com' },
    --  Google URL Shortenerite.
    { 0, 2658, 'goo.gl' },
    --  Hotels.com
    { 0, 2659, 'hotels.com' },
    --  JSTOR
    { 0, 2660, 'jstor.org' },
    --  Xiami.com
    { 0, 2661, 'xiami.com' },
    -- Minus
    { 0, 733, 'minus.com' },
    -- mathworks
    { 0, 2687, 'mathworks.com' },
    -- GoodSync
    { 0, 2688, 'goodsync.com' },
    { 0, 2688, 'www.goodsync.com' },
    -- UpToDate
    { 0, 2689, 'uptodate.com' },
    { 0, 2689, 'www.uptodate.com' },
    -- new relic
    { 0, 2690, 'staging.newrelic.com' },
    { 0, 2690, 'newrelic.com' },
    -- WorldCat
    { 0, 2691, 'www.worldcat.org' },
    { 0, 2691, 'worldcat.org' },
    --  Ando Media
    { 0, 2665, 'andomedia.com' },
    --  Break.com
    { 0, 2666, 'break.com' },
    --  NASA
    { 0, 1417, 'nasa.gov' },
    --  iTunes Radio
    { 1, 2669, 'radio-activity.itunes.apple.com' },
    { 1, 2669, 'radio.itunes.apple.com' },
}

--type (0-payload, 1-client), appid, pattern
gSSLCnamePatternList = {
    { 1, 2683, 'VMware vCenter Server Certificate' },
}

function DetectorInit(detectorInstance)

    gDetector = detectorInstance;

    if gDetector.addSSLCertPattern then
        for i,v in ipairs(gSSLHostPatternList) do
            gDetector:addSSLCertPattern(v[1],v[2],v[3]);
        end
    end
    if gDetector.addSSLCnamePattern then
        for i,v in ipairs(gSSLCnamePatternList) do
            gDetector:addSSLCnamePattern(v[1],v[2],v[3]);
        end
    end
    return gDetector;
end

function DetectorClean()
end

