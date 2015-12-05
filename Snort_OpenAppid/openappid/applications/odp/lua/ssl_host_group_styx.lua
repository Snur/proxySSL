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
detection_name: SSL Group "Styx"
version: 2
description: Group of SSL Host detectors.
bundle_description: $VAR1 = {
          'Campfire' => 'Business-focused group messaging and enterprise social networking.',
          'Postini' => 'A Google product that provides email security and archiving.',
          'Zootool' => 'Bookmarking app with visual images.',
          'Sony' => 'Official website for Sony Corporation.',
          'Flickr' => 'An image hosting and video hosting website, web services suite, and online community.',
          'Zapier' => 'Automatically sync the web apps.',
          'Readability' => 'A browser plugin and mobile app that converts articles to a cleaner format.',
          'WeTransfer' => 'Online file transferring platform.',
          'App.net' => 'A site with many apps for various platforms.',
          'Fifth Third Bank' => 'A bank.',
          'Storify' => 'Collect media, create stories and publish on the any social network.'
        };

--]]

require "DetectorCommon"


local DC = DetectorCommon

DetectorPackageInfo = {
    name =  "ssl_host_group_styx",
    proto =  DC.ipproto.tcp,
    client = {
        init =  'DetectorInit',
        clean =  'DetectorClean',
        minimum_matches =  1
    }
}

--serviceId, clientId, ClientType, PayloadId, PayloadType, hostPattern, pathPattern, schemePattern, queryPattern
gSSLHostPatternList = {

    -- Zapier
    { 0, 2206, 'zapier.com' },
    -- Sony 
    { 0, 2234, 'sony.com' },
    -- Zootool
    { 0, 2235, 'zootool.com' },
    -- WeTransfer
    { 0, 2236, 'wetransfer.com' },
    -- Sorify
    { 0, 2237, 'storify.com' },
    -- Readability
    { 0, 2243, 'readability.com' },
    -- Postini
    { 0, 2244, 'login.postini.com' },
    -- Fifth Third Bank
    { 0, 2257, 'www.53.com' },
    -- Flickr
    { 0, 159, 'flickr.com'},
    { 0, 159, 'static.flickr.com' },
    -- Campfire
    { 0, 2270, 'campfirenow.com'},
    -- App.net
    { 0, 2286, 'app.net'},
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

