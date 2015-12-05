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
detection_name: NetWorker
version: 3
description: Network backup system made by EMC, formerly Legato.
--]]

require "DetectorCommon"

--require('debugger')

--local DC = require("DetectorCommon")
local DC = DetectorCommon
local HT = hostServiceTrackerModule
local FT = flowTrackerModule

DetectorPackageInfo = {
    name =  "NetWorker",
    proto =  DC.ipproto.tcp,
    server = {
        init =  'DetectorInit',
        validate =  'DetectorValidator',
    }
}

gServiceId = 20152
gServiceName = 'NetWorker'
gSfAppIdNetWorker = 2043

gPatterns = {
    first_hello = {'\000\084\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000', 0, gSfAppIdNetWorker},
}

gFastPatterns = {
    {DC.ipproto.tcp, gPatterns.first_hello},
}

gAppRegistry = {
	{2043, 0}
}

function serviceInProcess(context)

    local flowFlag = context.detectorFlow:getFlowFlag(DC.flowFlags.serviceDetected)

    if ((not flowFlag) or (flowFlag == 0)) then
        gDetector:inProcessService()
    end

    DC.printf('%s: Inprocess, packetCount: %d\n', gServiceName, context.packetCount);
    return DC.serviceStatus.inProcess
end

function serviceSuccess(context)
    local flowFlag = context.detectorFlow:getFlowFlag(DC.flowFlags.serviceDetected)

    if ((not flowFlag) or (flowFlag == 0)) then
        gDetector:addService(gServiceId, "EMC", "", gSfAppIdNetWorker)
    end

    DC.printf('%s: Detected, packetCount: %d\n', gServiceName, context.packetCount);
    return DC.serviceStatus.success
end

function serviceFail(context)
    local flowFlag = context.detectorFlow:getFlowFlag(DC.flowFlags.serviceDetected)

    if ((not flowFlag) or (flowFlag == 0)) then
        gDetector:failService()
    end

    context.detectorFlow:clearFlowFlag(DC.flowFlags.continue)
    DC.printf('%s: Failed, packetCount: %d\n', gServiceName, context.packetCount);
    return DC.serviceStatus.nomatch
end

function registerPortsPatterns()

    for i,v in ipairs(gFastPatterns) do
        if ( gDetector:registerPattern(v[1], v[2][1], #v[2][1], v[2][2], v[2][3]) ~= 0) then
            DC.printf ('%s: register pattern failed for %s\n', gServiceName,v[2][1])
        else
            DC.printf ('%s: register pattern successful for %s\n', gServiceName,v[2][1])
        end
    end

	for i,v in ipairs(gAppRegistry) do
		pcall(function () gDetector:registerAppId(v[1],v[2]) end)
	end

end

function DetectorInit( detectorInstance)

    gDetector = detectorInstance
    DC.printf('%s: DetectorInit()\n',gServiceName)

    gDetector:init(gServiceName, 'DetectorValidator', 'DetectorFini')
    registerPortsPatterns()

    return gDetector
end

function DetectorValidator()
    local context = {}
    context.detectorFlow = gDetector:getFlow()
    context.packetDataLen = gDetector:getPacketSize()
    context.packetDir = gDetector:getPacketDir()
    context.srcIp = gDetector:getPktSrcAddr()
    context.dstIp = gDetector:getPktDstAddr()
    context.srcPort = gDetector:getPktSrcPort()
    context.dstPort = gDetector:getPktDstPort()
    context.flowKey = context.detectorFlow:getFlowKey()
    context.packetCount = gDetector:getPktCount()
    local size = context.packetDataLen
    local dir = context.packetDir
    local srcPort = context.srcPort
    local dstPort = context.dstPort
    local flowKey = context.flowKey
    local rft = FT.getFlowTracker(flowKey) 

    if (size == 0) then
        return serviceInProcess(context)
    end

    DC.printf ('%s:DetectorValidator(): packetCount %d, dir %d, size %d\n', gServiceName, context.packetCount, dir, size);

    if (not rft) then
        rft = FT.addFlowTracker(flowKey, {client_hello=0, server_hello=0, msgId=0})
    end

    if (size == 20 and (gDetector:memcmp(gPatterns.first_hello[1], #gPatterns.first_hello[1],
                gPatterns.first_hello[2]) == 0)) then
        if (dir == 1 and rft.server_hello == 0) then
            DC.printf('%s:DetectorValidator(): server sends hello\n', gServiceName)
            rft.server_hello = 1
        elseif (dir == 0 and rft.client_hello == 0) then
            DC.printf('%s:DetectorValidator(): client sends hello\n', gServiceName)
            rft.client_hello = 1
        end
        return serviceInProcess(context)
    end

    if (rft.client_hello == 1 or rft.server_hello == 1) then
        matched, byte = gDetector:getPcreGroups("(.)", 0)
        if (matched) then
            current_id = DC.binaryStringToNumber(byte, 1)
            DC.printf('%s:DetectorValidator(): msgId is %d\n', gServiceName, current_id)
        end
        if (rft.msgId == 0) then
            DC.printf('%s:DetectorValidator(): setting msgId\n', gServiceName)
            rft.msgId = current_id
            return serviceInProcess(context)
        else
            DC.printf('%s:DetectorValidator(): checking if rft.msgId %d and current_id %d match\n', gServiceName, rft.msgId, current_id)
            if (current_id == rft.msgId) then
                DC.printf('%s:DetectorValidator(): they match\n', gServiceName)
                return serviceSuccess(context)
            end
        end
    end

    return serviceFail(context)

end

--[[Required DetectorFini function
--]]
function DetectorFini()
    --print (gServiceName .. ': DetectorFini()')
end
