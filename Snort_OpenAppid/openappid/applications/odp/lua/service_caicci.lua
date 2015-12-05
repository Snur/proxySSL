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
detection_name: CAICCI
version: 4
description: Communications between Computer Associates systems.
--]]

require "DetectorCommon"

--require('debugger')

--local DC = require("DetectorCommon")
local DC = DetectorCommon
local HT = hostServiceTrackerModule
local FT = flowTrackerModule

DetectorPackageInfo = {
    name =  "CAICCI",
    proto =  DC.ipproto.tcp,
    server = {
        init =  'DetectorInit',
        validate =  'DetectorValidator',
    }
}

gServiceId = 20045
gServiceName = 'CAICCI'

gSfAppIdCaicci = 68
--patterns used in DetectorInit()
gPatterns = {       
    --patternName        Pattern                                  offset
    --------------------------------------------------------------------
    server_query = {'\006\007\004\000\224', 0, gSfAppIdCaicci},
    client_data = {'\006\003\004\000\224', 0, gSfAppIdCaicci},
}

--fast pattern registerd with core engine - needed when not using CSD tables
gFastPatterns = {
    --protocol       patternName
    ------------------------------------
    {DC.ipproto.tcp, gPatterns.server_query},
    {DC.ipproto.tcp, gPatterns.client_data},
}

--port based detection - needed when not using CSD tables
    --{DC.ipproto.udp, 3478},
gPorts = {
    {DC.ipproto.tcp, 1721},
}

gAppRegistry = {
	--AppIdValue          Extracts Info
	---------------------------------------
	{gSfAppIdCaicci,		         1}
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
        gDetector:addService(gServiceId, "Computer Associates", "", gSfAppIdCaicci)
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

    --register port based detection
    for i,v in ipairs(gPorts) do
        gDetector:addPort(v[1], v[2])
    end

    --register pattern based detection
    for i,v in ipairs(gFastPatterns) do
        if ( gDetector:registerPattern(v[1], v[2][1], #v[2][1], v[2][2], v[2][3]) ~= 0) then
            --print (gServiceName .. ': register pattern failed for ' .. v[2])
        else
            --print (gServiceName .. ': register pattern successful for ' .. i)
        end
    end

	for i,v in ipairs(gAppRegistry) do
		pcall(function () gDetector:registerAppId(v[1],v[2]) end)
	end

end


--[[ Core engine calls DetectorInit() to initialize a detector.
--]]
function DetectorInit( detectorInstance)

    gDetector = detectorInstance
    DC.printf('%s: DetectorInit()\n',gServiceName)

    gDetector:init(gServiceName, 'DetectorValidator', 'DetectorFini')
    registerPortsPatterns()

    return gDetector
end


--[[Validator function registered in DetectorInit()

    (1+dir) and (2-dir) logic takes care of symmetric request response case. Once connection is established,
    client (server) can send request and server (client) should send a response.
--]]
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

    DC.printf ('%s:DetectorValidator(): packetCount %d, dir %d\n', gServiceName, context.packetCount, dir);

    if (not rft) then
        rft = FT.addFlowTracker(flowKey, {stage=0, msgId=0, helloPacketDetected=0})
    end

    if (dir == 1) then
        DC.printf ('%s: checking server packet pattern\n',gServiceName)
        if (size >= 5 and (gDetector:memcmp(gPatterns.server_query[1], #gPatterns.server_query[1], 
            gPatterns.server_query[2]) == 0)) then 
            if (rft.stage == 1) then
                return serviceSuccess(context)
	        else
                rft.stage = 1
                return serviceInProcess(context)
            end
        end
    elseif (dir == 0) then
        DC.printf ('%s: checking client packet pattern\n',gServiceName)
        if (size >= 5 and (gDetector:memcmp(gPatterns.client_data[1], #gPatterns.client_data[1],
            gPatterns.client_data[2]) == 0)) then
            if (rft.stage == 1) then
                return serviceSuccess(context)
            else
                rft.stage = 1
                return serviceInProcess(context)
            end
        end
    else
        return serviceInProcess(context)
    end

    return serviceFail(context)
    --return serviceFail(context)
end

--[[Required DetectorFini function
--]]
function DetectorFini()
    --print (gServiceName .. ': DetectorFini()')
end
