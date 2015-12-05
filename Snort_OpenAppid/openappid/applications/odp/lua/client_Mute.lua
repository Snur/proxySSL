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
detection_name: Mute
version: 1
description: Peer to peer file sharing software.
--]]

require "DetectorCommon"



local DC = DetectorCommon
local FT = flowTrackerModule

DetectorPackageInfo = {
    name =  "Mute",
    proto =  DC.ipproto.tcp,
    client = {
        init =  'client_init',
        clean =  'client_clean',
        validate =  'client_validate',
        minimum_matches =  1
    }
}

seen_pub_key = nil
seen_aes_key = nil

gSfAppIdNone = 0
gSfAppIdMute = 745

gPatterns = {
    pub_key = {"PublicKey", 0, gSfAppIdMute},
    aes_key = {"AESKey", 0, gSfAppIdNone},
    stream  = {"Stream", 0, gSfAppIdNone},
}

gFastPatterns = {
    {DC.ipproto.tcp, gPatterns.pub_key},
}

gAppRegistry = {
	--AppIdValue          Extracts Info
	---------------------------------------
	{gSfAppIdMute,		         0}
}

--contains detector specific data related to a flow 
flowTrackerTable = {}

function clientInProcess(context)

    DC.printf('%s: Inprocess Client, packetCount: %d\n', DetectorPackageInfo.name, context.packetCount)
    return DC.clientStatus.inProcess
end

function clientSuccess(context)
    context.detectorFlow:setFlowFlag(DC.flowFlags.clientAppDetected)
    DC.printf('%s: Detected Client, appid %d\n', DetectorPackageInfo.name, appProductId)
    gDetector:client_addApp(appServiceId, appTypeId, appProductId, "", gSfAppIdMute);
    flowTrackerTable[context.flowKey] = Nil
    return DC.clientStatus.success
end
function clientFail(context)
    DC.printf('%s: Failed Client, packetCount: %d\n', DetectorPackageInfo.name, context.packetCount)
    flowTrackerTable[context.flowKey] = Nil
    return DC.clientStatus.einvalid
end

--[[ Core engine calls DetectorInit() to initialize a detector.
--]]
function client_init( detectorInstance, configOptions)
    gDetector = detectorInstance
    DC.printf ('%s:DetectorInit()\n', DetectorPackageInfo.name)
    gDetector:client_init()
    appTypeId = 15
    appProductId = 94
    appServiceId = 20086
    DC.printf ('%s:DetectorValidator(): appTypeId %d, product %d, service %d\n', DetectorPackageInfo.name, appTypeId, appProductId, appServiceId)

    --register pattern based detection
    for i,v in ipairs(gFastPatterns) do
        if ( gDetector:client_registerPattern(v[1], v[2][1], #v[2][1], v[2][2], v[2][3]) ~= 0) then
            DC.printf ('%s: register pattern failed for %s\n', DetectorPackageInfo.name,v[2][1])
        else
            DC.printf ('%s: register pattern successful for %s\n', DetectorPackageInfo.name,v[2][1])
        end
    end


	for i,v in ipairs(gAppRegistry) do
		pcall(function () gDetector:registerAppId(v[1],v[2]) end)
	end

    return gDetector
end

--[[Validator function registered in DetectorInit()
--]]
function client_validate()
    local context = {}

    context.detectorFlow = gDetector:getFlow()
    context.packetCount = gDetector:getPktCount()
    context.packetSize = gDetector:getPacketSize()
    context.packetDir = gDetector:getPacketDir()
    context.flowKey = context.detectorFlow:getFlowKey()
    local size = context.packetSize
    local dir = context.packetDir

    DC.printf ('packetCount %d dir %d, size %d\n', context.packetCount, dir, size)

    if (size == 0) then
        return clientInProcess(context)
    end

    if((dir == 0) and
       (size >= #gPatterns.pub_key[1] + 0) and
       (gDetector:memcmp(gPatterns.pub_key[1], #gPatterns.pub_key[1], gPatterns.pub_key[2]) == 0))
    then
        seen_pub_key = true
        return clientInProcess(context)
    end

    if((dir == 0) and
       (size >= #gPatterns.aes_key[1] + 0) and
       (gDetector:memcmp(gPatterns.aes_key[1], #gPatterns.aes_key[1], gPatterns.aes_key[2]) == 0) and
       (seen_pub_key))
    then
        seen_aes_key = true
        return clientInProcess(context)
    end

    if((dir == 0) and
       (size >= #gPatterns.stream[1] + 0) and
       (gDetector:memcmp(gPatterns.stream[1], #gPatterns.stream[1], gPatterns.stream[2]) == 0) and
       (seen_aes_key))
    then
        return clientSuccess(context)
    end

    return clientFail(context)

end

function client_clean()
end
