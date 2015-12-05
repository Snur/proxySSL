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
detection_name: Direct Connect
version: 4
description: Peer-to-peer file sharing.
--]]

require "DetectorCommon"


local bit = require("bit")
--require('debugger')

--local DC = require("DetectorCommon")
local DC = DetectorCommon
local HT = hostServiceTrackerModule
local FT = flowTrackerModule

DetectorPackageInfo = {
    name =  "DirectConnect",
    proto =  DC.ipproto.tcp,
    server = {
        init =  'DetectorInit',
        validate =  'DetectorValidator',
    }
}

gServiceId = 20040
gServiceName = 'DirectConnect'
gDetector = nil

gSfAppIdDirectconnect = 118
--patterns used in DetectorInit()
gPatterns = {       
    --patternName        Pattern         offset
    -------------------------------------------
    pattern1     = {'$Lock ',         0, gSfAppIdDirectconnect},
    pattern2     = {'$MyNick ',       0, gSfAppIdDirectconnect},
    pattern3     = {'HSUP ADBAS0',    0, gSfAppIdDirectconnect},
    pattern4     = {'HSUP ADBASE',    0, gSfAppIdDirectconnect},
    pattern5     = {'CSUP ADBAS0',    0, gSfAppIdDirectconnect},
    pattern6     = {'CSUP ADBASE',    0, gSfAppIdDirectconnect},
    pattern7     = {'$SR ',           0, gSfAppIdDirectconnect},
}

--fast pattern registerd with core engine 
gFastPatterns = {
    --protocol       patternName
    ------------------------------------
    {DC.ipproto.tcp, gPatterns.pattern1},
    {DC.ipproto.tcp, gPatterns.pattern2},
    {DC.ipproto.tcp, gPatterns.pattern3},
    {DC.ipproto.tcp, gPatterns.pattern4},
    {DC.ipproto.tcp, gPatterns.pattern5},
    {DC.ipproto.tcp, gPatterns.pattern6},
    {DC.ipproto.udp, gPatterns.pattern7},
}


--port based detection 
gPorts = {
    {DC.ipproto.udp, 411},
    {DC.ipproto.tcp, 411},
    {DC.ipproto.udp, 412},
    {DC.ipproto.tcp, 412},
    {DC.ipproto.udp, 413},
    {DC.ipproto.tcp, 413},
    {DC.ipproto.udp, 414},
    {DC.ipproto.tcp, 414},
}

--[[returns true if flow is TCP based, false otherwise.
--]]
local function isFlowTcp(flowKey)
    local firstInteger = gDetector:htonl(DC.getLongHostFormat(flowKey))
    return (bit.band(firstInteger, DC.flowProtocol.tcp) ~= 0)
end

--[[returns true if flow is UDP based, false otherwise.
--]]
local function isFlowUdp(flowKey)
    local firstInteger = gDetector:htonl(DC.getLongHostFormat(flowKey))
    return (bit.band(firstInteger, DC.flowProtocol.udp) ~= 0)
end


gAppRegistry = {
	--AppIdValue          Extracts Info
	---------------------------------------
	{gSfAppIdDirectconnect,		         0}
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
        gDetector:addService(gServiceId, "", "", gSfAppIdDirectconnect)
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

    DC.printf ('%s:DetectorValidator(): packetCount %d, dir %d\n', gServiceName, context.packetCount, dir);
    if (size == 0) then 
        return serviceInProcess(context)
    end

    local rft = FT.getFlowTracker(flowKey)
    if (not rft) then
        rft = FT.addFlowTracker(flowKey, {directconnect_state=0, serviceDetected = 0})
    end

    --[[OpenDPI tracks timing between packets once the flow is identified as DirectConnect. If
    --timing is off, then DirectConnect service is removed from the flow. RNA will ignore the timing
    --once service is detected
    --]]


    local status = DC.serviceStatus.inProcess;

    if (isFlowTcp(flowKey)) then
        status = validateDirectConnectTcp(context)
    elseif (isFlowUdp(flowKey)) then
        status = validateDirectConnectUdp(context)
    end

    if ((dir == 0) and (status == DC.serviceStatus.success)) then
        status = DC.serviceStatus.inProcess
        rft.serviceDetected = 1
    end

    if ((dir == 1) and (rft.serviceDetected == 1)) then
       status = DC.serviceStatus.success
       rft.serviceDetected = 1
    end
    
    if (status == DC.serviceStatus.success) then
        FT.delFlowTracker(flowKey)
        return serviceSuccess(context)
    elseif (status == DC.serviceStatus.inProcess) then
        return serviceInProcess(context)
    else
        return serviceFail(detector)
    end

    return serviceFail(context)

end

function validateDirectConnectTcp(context)
    local size = context.packetDataLen
    local dir = context.packetDir
    local flowKey = context.flowKey
    local srcPort = context.srcPort
    local dstPort = context.dstPort
    local rft = FT.getFlowTracker(flowKey)

    --[[ Once directconnect is detected, openDPI continues to identify packets to identify ssl port used by direct connect.
    It also detects connection timeouts. These are not supported in this version.
    --]]
    
    if (rft.directconnect_state == 0) then
        if (size > 6) then
            local matched = gDetector:getPcreGroups("^[$]Lock .*[|]$", 0); 
            if matched then
                DC.printf("maybe first directconnect to hub  detected\n");
                rft.directconnect_state = 1
                return DC.serviceStatus.inProcess
            end

            matched = gDetector:getPcreGroups("^[$]MyNick .*[|]$", 0); 
            if matched then
                DC.printf("maybe first dc connect between peers  detected\n");
                rft.directconnect_state = 2
                return DC.serviceStatus.inProcess
            end
        end

        if (size >= 11) then
            matched1 = gDetector:getPcreGroups("HSUP ADBAS0", 0); 
            matched2 = gDetector:getPcreGroups("HSUP ADBASE", 0); 
            if matched1 or matched2  then
                DC.printf("found directconnect HSUP ADBAS0 E\n");
                return DC.serviceStatus.success
            end

            matched1 = gDetector:getPcreGroups("CSUP ADBAS0", 0); 
            matched2 = gDetector:getPcreGroups("CSUP ADBASE", 0); 
            if (matched1 or matched2)  then
                DC.printf("found directconnect CSUP ADBAS0 E\n");
                return DC.serviceStatus.success
            end
        end
    elseif (rft.directconnect_state == 1) then
        DC.printf ('ValidateDirectConnectTcp(): state 1 size %d\n', size);
        if (size >= 11) then
            local matched1 = gDetector:getPcreGroups("HSUP ADBAS0", 0); 
            local matched2 = gDetector:getPcreGroups("HSUP ADBASE", 0); 
            if (matched1 or matched2)  then
                DC.printf("found directconnect HSUP ADBAS E in second packet\n");
                return DC.serviceStatus.success
            end

            matched1 = gDetector:getPcreGroups("CSUP ADBAS0", 0); 
            matched2 = gDetector:getPcreGroups("CSUP ADBASE", 0); 
            if (matched1 or matched2)  then
                DC.printf("found directconnect HSUP ADBAS0 E in second packet\n");
                return DC.serviceStatus.success
            end
        end -- size >= 11

        if (size > 6) then
            local matched = gDetector:getPcreGroups("^[$<].*[|]$", 0); 
            if matched then
                DC.printf("second directconnect detected\n");
                return DC.serviceStatus.success
            else
                DC.printf("second directconnect not detected\n");
                return DC.serviceStatus.inProcess
            end
        end

    elseif (rft.directconnect_state == 2) then
        DC.printf ('ValidateDirectConnectTcp(): state 1 size %d\n', size);
        if (size > 6) then
            local matched = gDetector:getPcreGroups("^[$].*[|]$", 0); 
            if matched then
                DC.printf("second directconnect between peers detected\n");
                return DC.serviceStatus.success
            else
                DC.printf("second directconnect between peers not detected\n");
                return DC.serviceStatus.inProcess
            end
        end
    end --end of state 2

    DC.printf("validateDirectConnectTcp: default return\n");
    return DC.serviceStatus.inProcess
    --return serviceFail(detector)
end

function validateDirectConnectUdp(context)
    local size = context.packetDataLen
    local dir = context.packetDir
    --local detectorFlow = gDetector:getFlow()
    local flowKey = context.flowKey
    local srcPort = context.srcPort
    local dstPort = context.dstPort

    local srcHst = HT.getHostServiceTracker(context.srcIp)
    local dstHst = HT.getHostServiceTracker(context.dstIp)
    local rft = FT.getFlowTracker(flowKey)

    --print ("src tracker key: " .. srcTrackerKey)
    --print ("dst tracker key: " .. dstTrackerKey)

    --[[Packeting timing is not supported. This will need API extension for getting packet
    --timing information.
    --]]

    if (size > 58) then
        if (srcHst) then
            local matched = gDetector:getPcreGroups("^[$]SR .*[|]$", 0); 
            if matched then
                matched = gDetector:getPcreGroups(".*TTH:.*[(][^)]{0,21}[)][|]$", 0); 
                if matched then
                    DC.printf("directconnect udp detected\n");
                    return DC.serviceStatus.success
                end
            end
            rft.directconnect_state =  rft.directconnect_state + 1

            if (rft.directconnect_state < 3) then
                return DC.serviceStatus.inProcess
            end
        end -- gHostServiceTracker[srcTrackerKey] 

        if (dstHst) then
            local matched = gDetector:getPcreGroups("^[$]SR .*[|]$", 0); 
            if matched then
                matched = gDetector:getPcreGroups(".*TTH:.*[(][^)]{0,21}[)][|]$", 0); 
                if matched then
                    DC.printf("directconnect udp detected\n");
                    return DC.serviceStatus.success
                end
            end
            rft.directconnect_state =  rft.directconnect_state + 1

            if (rft.directconnect_state < 3) then
                return DC.serviceStatus.inProcess
            end
        end -- gHostServiceTracker[srcTrackerKey] 
    end --size > 58

    return DC.serviceStatus.inProcess
    --return serviceFail(context)
end

--[[Required DetectorFini function
--]]
function DetectorFini()
    --print (gServiceName .. ': DetectorFini()')
end
