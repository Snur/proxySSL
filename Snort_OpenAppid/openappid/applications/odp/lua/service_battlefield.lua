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
detection_name: Battlefield
version: 3
description: A multi-player video game.
--]]

require "DetectorCommon"


local bit = require("bit")
--require('debugger')

--local DC = require("DetectorCommon")
local DC = DetectorCommon
local HT = hostServiceTrackerModule
local FT = flowTrackerModule

DetectorPackageInfo = {
    name =  "Battlefield",
    proto =  DC.ipproto.udp,
    server = {
        init =  'DetectorInit',
        validate =  'DetectorValidator',
    }
}

gServiceId = 20039
gServiceName = 'Battlefield'
gDetector = nil

gSfAppIdBattlefield = 49
--patterns used in DetectorInit()
gPatterns = {       
    --patternName        Pattern                                  offset
    --------------------------------------------------------------------
    helloPattern      = {'battlefield2\000', 5, gSfAppIdBattlefield},
    pattern2          = {'\254\253', 0, gSfAppIdBattlefield},
    pattern3          = {'\017\032\000\001\000\000\080\185\016\17', 0, gSfAppIdBattlefield},
    pattern4          = {'\017\032\000\001\000\000\048\185\016\17', 0, gSfAppIdBattlefield},
    pattern5          = {'\017\032\000\001\000\000\160\152\000\17', 0, gSfAppIdBattlefield},
                        --fefd0900 000000
    pattern6          = {'\254\253\009\000\000\000\000', 0},
}

--fast pattern registerd with core engine - needed when not using CSD tables
gFastPatterns = {
    --protocol       patternName
    ------------------------------------
    {DC.ipproto.udp, gPatterns.helloPattern},
    {DC.ipproto.udp, gPatterns.pattern2},
    {DC.ipproto.udp, gPatterns.pattern3},
    {DC.ipproto.udp, gPatterns.pattern4},
    {DC.ipproto.udp, gPatterns.pattern5},
}


--port based detection - needed when not using CSD tables
gPorts = {
    --client and server side ports
    --*{DC.ipproto.tcp, 80}, 
    --UDP 1024-1124 ignored for now
    --TCP 1024-1124 ignored for now
    --UDP 1500-4999 ignored for now
    {DC.ipproto.tcp, 4711},
    {DC.ipproto.udp, 16567},
    {DC.ipproto.udp, 27900},
    {DC.ipproto.tcp, 27900},
    {DC.ipproto.udp, 29900},
    {DC.ipproto.tcp, 29900},
    {DC.ipproto.tcp, 27901},
    {DC.ipproto.udp, 28910},
    --UDP 55123-55125 ignored for now
}

gAppRegistry = {
	--AppIdValue          Extracts Info
	---------------------------------------
	{gSfAppIdBattlefield,		         0}
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
        gDetector:addService(gServiceId, "", "", gSfAppIdBattlefield)
    end

    HT.addHostServiceTracker(context.srcIp, 1)
    HT.addHostServiceTracker(context.dstIp, 1)

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

    --print (gServiceName .. ': DetectorInit()')

    gDetector = detectorInstance
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

    DC.printf ('%s:DetectorValidator(): packetCount %d, dir %d\n', gServiceName, context.packetCount, dir);
    if (size == 0) then
        return serviceInProcess(context)
    end

    if (not rft) then
        rft = FT.addFlowTracker(flowKey, {stage=0, msgId=0, helloPacketDetected=0})
    end

    --[[save connection method from opendpi is not used because it uses packet timing and no pattern
    to declare connection save packet. 
    --]]

    --[[ The following logic is commented out because it needs additional API function for
    determing if source or detination ipaddress+port of the current flow already has battlefield
    as identified service. Replace note001 with the api calls.
    --]]

    local srcHst = HT.getHostServiceTracker(context.srcIp)
    local dstHst = HT.getHostServiceTracker(context.dstIp)

    --[[The following block will not work when client sends first packet that is request and RNA does not 
    provide the packet to this detector. 
    --]]
    if ((srcPort >= 27000 or dstPort >= 27000) and (dstHst or srcHst)) then
        DC.printf ("BattleField: request/response block. Stage %d, size %d\n", rft.stage, size)
        if (rft.stage == 0 or rft.stage == (1 + dir)) then
            if (size > 8 and (gDetector:memcmp(gPatterns.pattern2[1], #gPatterns.pattern2[1], 0) == 0)) then
                matched, shortVar = gDetector:getPcreGroups("(..)", 2); 
                if shortVar then
                    rft.msgId = DC.getShortHostFormat (shortVar)
                    rft.stage = 1 + dir;
                    return serviceInProcess(context)
                end
            end
        elseif (rft.stage == (2 - dir)) then
            if (size > 8) then
                matched, shortVar = gDetector:getPcreGroups("(..)", 0); 
                if shortVar then
                    msgId = DC.getShortHostFormat (shortVar)
                    DC.printf("msgId %x, from packet %x\n", msgId, rft.msgId);
                    if (msgId == rft.msgId) then
                        FT.delFlowTracker(flowKey)
                        DC.printf ('%d :Battlefield message and reply detected.\n', context.packetCount)
                        return serviceSuccess(context)
                    end
                end
            end
        end
    end

    if (size == 18 and  gDetector:memcmp(gPatterns.helloPattern[1], #gPatterns.helloPattern[1], 5) == 0) then
        DC.printf ('%d :Battlefield 2 hello packet detected.\n', context.packetCount)
        rft.helloPacketDetected = 1
        return serviceInProcess(context)
    end

    if ((size == 7) 
        and (rft.helloPacketDetected == 1) 
        and (gDetector:memcmp(gPatterns.pattern6[1], #gPatterns.pattern6[1], 0) == 0)
        ) then

        rft.helloPacketDetected = 0
        FT.delFlowTracker(flowKey)
        DC.printf ('%d :Battlefield 2 hello packet reported.\n', context.packetCount)
        return serviceSuccess(context)
    end

    if ((size > 10)
        and ((gDetector:memcmp(gPatterns.pattern3[1], #gPatterns.pattern3[1], 0) == 0)
             or (gDetector:memcmp(gPatterns.pattern4[1], #gPatterns.pattern4[1], 0) == 0)
             or (gDetector:memcmp(gPatterns.pattern5[1], #gPatterns.pattern5[1], 0) == 0))) then
        DC.printf ('%d :Battlefield safe pattern detected.\n', context.packetCount)
        FT.delFlowTracker(flowKey)
        return serviceSuccess(context)

    end
    
    return serviceFail(context)
end

--[[Required DetectorFini function
--]]
function DetectorFini()
    --print (gServiceName .. ': DetectorFini()')
end
