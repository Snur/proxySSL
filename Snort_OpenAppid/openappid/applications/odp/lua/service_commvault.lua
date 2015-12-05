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
detection_name: Commvault
version: 3
description: Enterprise data backup and storage management software.
--]]

require "DetectorCommon"

--require('debugger')
local DC = DetectorCommon
local HT = hostServiceTrackerModule
local FT = flowTrackerModule

gDetector = nil

DetectorPackageInfo = {
    name =  "Commvault",
    proto =  DC.ipproto.tcp,
    server = {
        init =  'DetectorInit',
        validate =  'DetectorValidator',
    }
}

--local DC = require("DetectorCommon")

gServiceId = 20171
gServiceName = 'Commvault'

gSfAppIdCommvault = 96

gPatterns = {
    server1 = {'\016\001\009\000\002\001', 2, gSfAppIdCommvault},
    client2 = {'\009\000\005\009', 4, gSfAppIdCommvault},
}

gFastPatterns = {
    {DC.ipproto.tcp, gPatterns.server1},
    
}

gAppRegistry = {
	{gSfAppIdCommvault, 0},
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

    DC.printf('%s: service %d, appId %d\n', gServiceName, gServiceId, gSfAppIdCommvault)

    if ((not flowFlag) or (flowFlag == 0)) then
        DC.printf('%s: adding service\n', gServiceName)
        gDetector:addService(gServiceId, "CommVault Systems, Inc.", "", gSfAppIdCommvault)
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

    --register pattern based detection
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
    DC.printf('%s: DetectorInit()\n',gServiceName);
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
        rft = FT.addFlowTracker(flowKey, {next_packet=0,first_client_skipped=0})
    end

    if (dir == 0) then
        if (rft.first_client_skipped == 0) then
            DC.printf('%s:first client packet\n',gServiceName)
            rft.first_client_skipped = 1
            return serviceInProcess(context)
        elseif (size >=6 and rft.next_packet == 1 and gDetector:memcmp(gPatterns.client2[1], #gPatterns.client2[1], gPatterns.client2[2]) == 0) then
            DC.printf('%s: second client packet\n', gServiceName)
            return serviceSuccess(context)
        else 
            FT.delFlowTracker(flowKey)
            return serviceFail(context)
        end
    end

    if (dir == 1 and size >= 10 and gDetector:memcmp(gPatterns.server1[1], #gPatterns.server1[1], gPatterns.server1[2]) == 0) then
        DC.printf('%s:first server packet\n', gServiceName)
        rft.next_packet = 1        
        rft.first_client_skipped = 1
        return serviceInProcess(context)
    end

    FT.delFlowTracker(flowKey)
    return serviceFail(context)

end

--[[Required DetectorFini function
--]]
function DetectorFini()
end
