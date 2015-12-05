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
detection_name: BitTorrent
version: 3
description: A peer-to-peer file sharing protocol used for transferring large amounts of data.
--]]

require "DetectorCommon"


local DC = DetectorCommon

DetectorPackageInfo = {
    name =  "BitTorrent",
    proto =  DC.ipproto.tcp,
    client = {
        init =  'DetectorInit',
        clean =  'DetectorClean',
        validate =  'DetectorValidator',
        minimum_matches =  1
    }
}

function DetectorClean()
end

function DetectorInit(detectorInstance)
    gDetector = detectorInstance
    if (gDetector.CHPCreateApp and gDetector.CHPAddAction) then
        gDetector:CHPCreateApp(61, 2, 2);
        gDetector:CHPAddAction(61, 1, 1, "BitTorrent", 0, "");
        gDetector:CHPAddAction(61, 0, 3, "/announce", 0, "");
        gDetector:CHPAddAction(61, 0, 3, "info_hash", 0, "");
        gDetector:CHPAddAction(61, 0, 3, "peer_id", 0, "");
        gDetector:CHPAddAction(61, 0, 3, "port", 0, "");
        gDetector:CHPAddAction(61, 0, 3, "ip", 0, "");
        gDetector:CHPAddAction(61, 0, 3, "uploaded", 0, "");
        gDetector:CHPAddAction(61, 0, 3, "downloaded", 0, "");
        gDetector:CHPAddAction(61, 0, 3, "left", 0, "");
        gDetector:CHPAddAction(61, 0, 3, "event", 0, "");
        gDetector:CHPAddAction(61, 0, 3, "compact", 0, "");
        gDetector:CHPAddAction(61, 0, 3, "key", 0, "");
        gDetector:CHPAddAction(61, 0, 3, "trackerid", 0, "");
        gDetector:CHPAddAction(61, 0, 3, "numwant", 0, "");
    end
    return gDetector
end

function DetectorValidator()
    local context = {}
    return serviceFail(context)
end

function DetectorFini()
end
