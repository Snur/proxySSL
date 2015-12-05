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
detection_name: Payload Group "NOFX"
version: 16
description: Group of payload detectors.
bundle_description: $VAR1 = {
          'Playstation.com' => 'Sony Playstation related e-commerce.',
          'Avast' => 'Anti-virus software for Windows PCs.',
          'ArtStack' => 'Social platform for Art.',
          'Nokia' => 'Official site for Nokia.',
          'Raptr' => 'Social Network for video game player.',
          'PBS' => 'Official website for Public Broadcasting Service, an American television network.',
          'PS3 web browser' => 'Web browser for Sony Playstation 3.',
          'WSDD' => 'Web Service Dynamic Discovery, a discovery protocol that allows a host machine to find web services on the local network.',
          'VLC Media Player' => 'Free and open source media player.',
          'TRUSTe' => 'Online security service.',
          'AIM Express' => 'Browser-based client for AIM.',
          'Playstation Store' => 'Sony Playstation online marketplace.',
          'Silk' => 'Web browser for the Kindle Fire.',
          'PS3 Updater' => 'Playstation software update client.',
          'Nokia Music' => 'Nokia Music store.',
          'FDSSDP' => 'A service discovery protocol.',
          'UPnP' => 'Discovery and resource negotiation protocol for residential networking devices.',
          'Nokia Store' => 'Nokia App store.',
          'DoubleVerify' => 'Verifies Online advertisements.',
          'PS3 Downloads' => 'Sony Playstation software updates and downloads.',
          'PS3 Messenger' => 'Messaging system in Sony Playstation Home.',
          'PS3 Home Client' => 'Client on a PS3 for interacting with Playstation Home.'
        };

--]]

require "DetectorCommon"


local DC = DetectorCommon

DetectorPackageInfo = {
    name =  "payload_group_NOFX",
    proto =  DC.ipproto.tcp,
    client = {
        init =  'DetectorInit',
        clean =  'DetectorClean',
        minimum_matches =  1
    }
}

--serviceId, clientId, ClientType, PayloadId, PayloadType, hostPattern, pathPattern, schemePattern, queryPattern
gUrlPatternList = {

   --VLC Media Player
    { 0, 0, 0, 874, 22, "videolan.org", "/vlc", "http:", "", 1756},
    -- Raptr
    { 0, 0, 0, 875, 22, "raptr.com", "/", "http:", "", 1757},
    -- AIM Express
    { 0, 0, 0, 878, 10, "aolcdn.com", "/aim/gromit/aim_express", "http:", "", 1759}, 
    -- -- Playstation Home
    -- { 0, 0, 0, 879, 28, "scea-home.playstation.net", "/", "http:", "", 1762},
    -- { 0, 0, 0, 879, 28, "scee-home.playstation.net", "/", "http:", "", 1762},
    -- { 0, 0, 0, 879, 28, "community.playstation.net", "/", "http:", "", 1762},
    -- Playstation Store
    { 0, 0, 0, 877, 28, "sonyentertainmentnetwork.com", "/store", "http:", "", 1764},
    -- Playstation Downloads
    { 0, 0, 0, 876, 28, "dl.playstation.net", "/", "http:", "", 1765},
    { 0, 0, 0, 876, 28, "update.playstation.net", "/", "http:", "", 1765},
    -- Playstation.com
    { 0, 0, 0, 880, 20, "playstation.com", "/", "http:", "", 1754},
   --Nokia
    { 0, 0, 0, 881,22, "nokia.com","/", "http:", "", 1769},
    { 0, 0, 0, 881,22, "nokiausa.com","/", "http:", "", 1769},
   --Nokia Music
    { 0, 0, 0, 882,22, "music.nokia.com","/", "http:", "", 1770},
    { 0, 0, 0, 882,22, "musicassets.vcdn.nokia.com","/", "http:", "", 1770},
    { 0, 0, 0, 882,22, "musicimg.ovi.com","/", "http:", "", 1770},
   --Nokia Store
    { 0, 0, 0, 883,22, "store.nokia.com","/", "http:", "", 1771},
    { 0, 0, 0, 883,22, "store.ovi.com","/", "http:", "", 1771},
    { 0, 0, 0, 883,22, "ovi.com","/store", "http:", "", 1771},
   --PBS
    { 0, 0, 0, 884,22, "pbs.org","/", "http:", "", 1772},
   --ArtStack
    { 0, 0, 0, 885,22, "theartstack.com","/", "http:", "", 1774},
   --TRUSTe
    { 0, 0, 0, 886,22, "truste.com","/", "http:", "", 1775},
   --DoubleVerify
    { 0, 0, 0, 887,22, "doubleverify.com","/", "http:", "", 1776},
   --Avast
    { 0, 0, 0, 888,22, "avast.com","/", "http:", "", 1264},
}


function DetectorInit(detectorInstance)

    gDetector = detectorInstance;

    gDetector:addHttpPattern(2, 5, 0, 284, 23, 0, 0, 'UPnP', 1758, 1);
    gDetector:addHttpPattern(2, 5, 0, 283, 19, 0, 0, 'Silk', 1760, 1);
    gDetector:addHttpPattern(2, 5, 0, 283, 19, 0, 0, 'Silk-Accelerated=true', 1760, 1);
    gDetector:addHttpPattern(2, 5, 0, 285, 19, 0, 0, 'PLAYSTATION', 1761, 1);
    gDetector:addHttpPattern(2, 5, 0, 228, 19, 0, 0, 'PSHome', 1767, 1);
    gDetector:addHttpPattern(2, 5, 0, 228, 19, 0, 0, 'PSApplication', 1767, 1);
    gDetector:addHttpPattern(2, 5, 0, 226, 19, 0, 0, 'PS3FriendImUtil', 1763, 1);
    gDetector:addHttpPattern(2, 5, 0, 227, 19, 0, 0, 'PS3Update-agent', 1766, 1);
    gDetector:addHttpPattern(2, 5, 0, 230, 23, 0, 0, 'WSDAPI', 1777, 1);
    gDetector:addHttpPattern(2, 5, 0, 231, 23, 0, 0, 'FDSSDP', 1779, 1);   
 
    if gDetector.addAppUrl then
        for i,v in ipairs(gUrlPatternList) do
            gDetector:addAppUrl(v[1],v[2],v[3],v[4],v[5],v[6],v[7],v[8],v[9],v[10]);
        end
    end

    return gDetector;
end

function DetectorClean()
end

