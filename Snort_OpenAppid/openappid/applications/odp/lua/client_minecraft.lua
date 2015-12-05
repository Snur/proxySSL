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
detection_name: Minecraft
version: 1
description: Online game.
--]]

require "DetectorCommon"



local DC = DetectorCommon
local FT = flowTrackerModule

DetectorPackageInfo = {
    name =  "Minecraft",
    proto =  DC.ipproto.tcp,
    client = {
        init =  'client_init',
        clean =  'client_clean',
        validate =  'client_validate',
        minimum_matches =  1
    }
}

gSfAppIdMinecraft = 1802

gPatterns = {
    init = { '\019\000\047\013', 0, gSfAppIdMinecraft},
    second = { '\008\000\006\086\048\109\105\099\097', 0, gSfAppIdMinecraft}
}

gFastPatterns = {
    {DC.ipproto.tcp, gPatterns.init},
}

gAppRegistry = {
	--AppIdValue          Extracts Info
	---------------------------------------
	{gSfAppIdMinecraft,		         0}
}

--contains detector specific data related to a flow 
flowTrackerTable = {}

function clientInProcess(context)

    DC.printf('minecraft client: Inprocess Client, packetCount: %d\n', context.packetCount)
    return DC.clientStatus.inProcess
end

function clientSuccess(context)
    context.detectorFlow:setFlowFlag(DC.flowFlags.clientAppDetected)
    DC.printf('minecraft client: Detected Client, packetCount: %d\n', context.packetCount)
    gDetector:client_addApp(appServiceId, appTypeId, appProductId, "", gSfAppIdMinecraft);
    return DC.clientStatus.success
end
function clientFail(context)
    DC.printf('minecraft client: Failed Client, packetCount: %d\n', context.packetCount)
    return DC.clientStatus.einvalid
end

--[[ Core engine calls DetectorInit() to initialize a detector.
--]]
function client_init( detectorInstance, configOptions)
    gDetector = detectorInstance
    DC.printf ('%s:DetectorInit()\n', DetectorPackageInfo.name)
    gDetector:client_init()
    appTypeId = 19
    appProductId = 469
    appServiceId = 20192
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
    context.srcPort = gDetector:getPktSrcPort()
    context.dstPort = gDetector:getPktDstPort()
    local size = context.packetSize
    local dir = context.packetDir
    local flowKey = context.flowKey

    DC.printf ('minecraft client packetCount %d dir %d, size %d\n', context.packetCount, dir, size)

    local rft = FT.getFlowTracker(flowKey)
    if (not rft) then
        DC.printf ('minecraft client adding ft for flowKey %s\n', flowKey)
        rft = FT.addFlowTracker(flowKey, {p=1})
    end

    if (rft.p == 1 and size >= 20) then
        rft.p = 2
        DC.printf ('minecraft client first packet\n')
        return clientInProcess(context)
    end

    if (rft.p == 2 and 
        gDetector:memcmp(gPatterns.second[1], #gPatterns.second[1], gPatterns.second[2]) == 0) then
        DC.printf ('got minecraft client\n')
        FT.delFlowTracker(flowKey)
        return clientSuccess(context)
    end

    FT.delFlowTracker(flowKey)
    return clientFail(context)

end

function client_clean()
end
