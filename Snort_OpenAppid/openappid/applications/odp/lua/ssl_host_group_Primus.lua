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
detection_name: SSL Group "Primus"
version: 8
description: Group of SSL Host detectors.
bundle_description: $VAR1 = {
          'Presto' => 'Printable emails and photos.',
          'SockShare' => 'Provides online File sharing.',
          'NHL.com' => 'The National Hockey League official website.',
          'Atlassian' => 'Project Control and Management Software.',
          'Simpli.fi' => 'Ad portal.',
          'Wired.com' => 'Online magazine.',
          'IFTTT' => 'Service to connect channels.',
          'NBC' => 'Official website for NBC\'s Television network.',
          'Zmags' => 'Digital publisher for branded products to customer.',
          'Prezi' => 'Presentation tool.',
          'Brightcove' => 'Video hosting platform.',
          'ESTsoft' => 'Provides software tools and online games.',
          'Google Checkout' => 'Online Payment service by Google.',
          'Cabal Online' => 'Online multiplayer games.',
          'Redbox Instant' => 'Rental and online movie/game.',
          'Space.com' => 'Provides news related to Space and Astronomy.',
          'GNOME' => 'Official website for GNOME, a desktop environment and graphical UI.',
          'PixelMags' => 'Content delivery network for digital versions of magazine.',
          'Ubuntu' => 'Official website of Ubuntu.',
          'Apple iForgot' => 'Password reset portal for Apple.',
          'BitGravity' => 'Content delivery network.',
          'ALTools' => 'Software tools by ESTsoft.',
          'Slate Magazine' => 'Online daily magazine.'
        };

--]]

require "DetectorCommon"


local DC = DetectorCommon

DetectorPackageInfo = {
    name =  "ssl_host_group_Primus",
    proto =  DC.ipproto.tcp,
    client = {
        init =  'DetectorInit',
        clean =  'DetectorClean',
        minimum_matches =  1
    }
}

--serviceId, clientId, ClientType, PayloadId, PayloadType, hostPattern, pathPattern, schemePattern, queryPattern
gSSLHostPatternList = {

    -- NBC 
    { 0, 1988, 'nbc.com' },
    { 0, 1988, 'nbcuniversalstore.com' },
    { 0, 1988, 'nbcuniversalstore.resultspage.com' },
    -- Space.com
    { 0, 1990, 'hermanstreet.com' },
    -- SockShare
    { 0, 1991, 'sockshare.com' },
    -- BitGravity
    { 0, 1992, 'bitgravity.com' },
    -- PixelMags
    { 0, 1993, 'pixel-mags.com' },
    -- Zmags 
    { 0, 1994, 'zmags.com' },
    -- GNOME 
    { 0, 1995, 'gnome.org' },
    -- ESTSoft
    { 0, 1996, 'image.estgames.com' },
    { 0, 1996, 'www.estgames.com' },
    { 0, 1996, 'estgames.com' },
    -- Cabal Online
    { 0, 1997, 'cabal.com' },
    { 0, 1997, 'cabalonline.com' },
    -- ALTools
    { 0, 1998, 'altools.com' },
    { 0, 1998, 'altools.co.kr' },
    { 0, 1998, 'altools.jp' },
    -- Slate Magazine
    { 0, 2000, 'slate-id-prod.s3.amazonaws.com' },
    { 0, 2000, 'slate.com' },
    -- Ubuntu
    { 0, 2003, 'ubuntu.com' },
    -- Wired.com
    { 0, 2005, 'wired.com' },
    -- NHL
    { 0, 2007, 'nhl.com' },
    { 0, 2007, 'nhl.112.2o7.net' },
    -- Presto
    { 0, 2008, 'presto.com' },
    -- Redbox Instant
    { 0, 2015, 'redboxinstant.com' },
    -- Brightcove
    { 0, 2019, 'brightcove.com' },
    -- Simpli.fie
    { 0, 2021, 'simpli.fi' },
    -- nrelate 
    -- { 0, 2022, 'nrelate.com' },
    -- Atlassian
    { 0, 2038, 'atlassian.com' },
    { 0, 2038, 'atlassian.net' },
    -- Prezi
    { 0, 2040, 'prezi-a.akamaihd.net' },
    { 0, 2040, 'prezi.com' },
    -- IFTTT
    { 0, 2041, 'ifttt.com' },
    -- Apple iForgot
    { 0, 2045, 'iforgot.apple.com' },
    -- Google checkout
    { 0, 2046, 'checkout.google.com' },
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

