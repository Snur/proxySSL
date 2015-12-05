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
detection_name: STUN
version: 3
description: Session Traversal Utilities for NAT is used in NAT traversal for applications with real-time voice, video, messaging, and other interactive communications.
--]]

require "DetectorCommon"


--require('debugger')
--local DC = require("DetectorCommon")
local DC = DetectorCommon
local FT = flowTrackerModule

DetectorPackageInfo = {
    name =  "stun",
    proto =  DC.ipproto.tcp,
    server = {
        init =  'DetectorInit',
        validate =  'DetectorValidator',
    }
}

gServiceId = 20037
gServiceName = 'STUN'
gDetector = nil
gSfAppIdStun = 853

--patterns used in DetectorInit()
gPatterns = {
    --patternName        Pattern         offset
    -------------------------------------------
    bindReq          = {"\000\001\000",    0, gSfAppIdStun},
    sharedSecretReq  = {"\000\002\000",    0, gSfAppIdStun},
    allocateReq      = {"\000\003\000",    0, gSfAppIdStun},
    refreshReq       = {"\000\004\000",    0, gSfAppIdStun},

    bindSuccess      = {"\001\001\000",    0, gSfAppIdStun},
    sharedSecSuccess = {"\001\002\000",    0, gSfAppIdStun},
    allocateSuccess  = {"\001\003\000",    0, gSfAppIdStun},
    refreshSuccess   = {"\001\004\000",    0, gSfAppIdStun},

    BindErrError     = {"\001\017\000",    0, gSfAppIdStun},
    sharedSecError   = {"\001\018\000",    0, gSfAppIdStun},
    allocateError    = {"\001\019\000",    0, gSfAppIdStun},
    refreshError     = {"\001\020\000",    0, gSfAppIdStun},
}

--fast pattern registerd with core engine 
gFastPatterns = {
    --protocol       patternName
    ------------------------------------
    {DC.ipproto.tcp, gPatterns.bindReq},
    {DC.ipproto.tcp, gPatterns.sharedSecretReq},
    {DC.ipproto.tcp, gPatterns.allocateReq},
    {DC.ipproto.tcp, gPatterns.refreshReq},
    {DC.ipproto.tcp, gPatterns.bindSuccess},
    {DC.ipproto.tcp, gPatterns.sharedSecSuccess},
    {DC.ipproto.tcp, gPatterns.allocateSuccess},
    {DC.ipproto.tcp, gPatterns.refreshSuccess},
    {DC.ipproto.tcp, gPatterns.BindErrError},
    {DC.ipproto.tcp, gPatterns.sharedSecError},
    {DC.ipproto.tcp, gPatterns.allocateError},
    {DC.ipproto.tcp, gPatterns.refreshError},

    {DC.ipproto.udp, gPatterns.bindReq},
    {DC.ipproto.udp, gPatterns.sharedSecretReq},
    {DC.ipproto.udp, gPatterns.allocateReq},
    {DC.ipproto.udp, gPatterns.refreshReq},
    {DC.ipproto.udp, gPatterns.bindSuccess},
    {DC.ipproto.udp, gPatterns.sharedSecSuccess},
    {DC.ipproto.udp, gPatterns.allocateSuccess},
    {DC.ipproto.udp, gPatterns.refreshSuccess},
    {DC.ipproto.udp, gPatterns.BindErrError},
    {DC.ipproto.udp, gPatterns.sharedSecError},
    {DC.ipproto.udp, gPatterns.allocateError},
    {DC.ipproto.udp, gPatterns.refreshError},
}

--port based detection - needed when not using CSD tables
gPorts = {
    {DC.ipproto.udp, 3478},
    {DC.ipproto.tcp, 3478},
}

gAppRegistry = {
	--AppIdValue          Extracts Info
	---------------------------------------
	{gSfAppIdStun,		         0}
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
        gDetector:addService(gServiceId, "", "", gSfAppIdStun)
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
            DC.printf ('%s: register pattern failed for %s\n', gServiceName,v[2][1])
        else
            DC.printf ('%s: register pattern successful for %s\n', gServiceName,v[2][1])
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
    DC.printf ('%s:DetectorInit()\n', gServiceName);

    gDetector:init(gServiceName, 'DetectorValidator', 'DetectorFini')

    registerPortsPatterns()

    return gDetector
end

function MatchPacket(context)
    local dir =  context.packetDir
    local size = context.packetDataLen
    local flowKey = context.flowKey
    local srcPort = context.srcPort
    local dstPort = context.dstPort

    if size < 4 then
        return 0;
    end

    --matched, rawMessageType, rawMessageLen = gDetector:getPcreGroups("([\\d][\\d])([\\d][\\d])", 0); 
    local matched, rawMessageType, rawMessageLen = gDetector:getPcreGroups("(..)(..)", 0); 
    local stunMessageType = DC.getShortHostFormat(rawMessageType)
    local stunMessageLen  = DC.getShortHostFormat(rawMessageLen)

    --see http://www.iana.org/assignments/stun-parameters/stun-parameters.xhtml for details on allocation
    if ((size >= 20) and (size == (stunMessageLen+20))
        and ((stunMessageType >= 0x0001 and stunMessageType <=0x0004) 
             or (stunMessageType >= 0x0101 and stunMessageType <=0x0104) 
             or (stunMessageType >= 0x0111 and stunMessageType <=0x0115))) then
        DC.printf ('%d :len and type match.\n', context.packetCount)

        if (size == 20) then
            DC.printf ('%d :found stun.\n', context.packetCount)
            return 1 
        end
        
        local currentOffset = 20;
        while ((size - currentOffset) >= 4) do
            matched, rawAttributeType, rawAttributeLen = gDetector:getPcreGroups("(..)(..)", currentOffset); 
            stunAttributeType = DC.getShortHostFormat(rawAttributeType)
            stunAttributeLen  = DC.getShortHostFormat(rawAttributeLen)

            if ((stunAttributeType >= 0x0001 and stunAttributeType <= 0x0015)
                or stunAttributeType == 0x0020
                or stunAttributeType == 0x0022
                or stunAttributeType == 0x0024
                or stunAttributeType == 0x8001
                or stunAttributeType == 0x8006
                or stunAttributeType == 0x8008
                or stunAttributeType == 0x8015
                or stunAttributeType == 0x8020
                or stunAttributeType == 0x8028
                or stunAttributeType == 0x802a
                or stunAttributeType == 0x8029
                or stunAttributeType == 0x8050
                or stunAttributeType == 0x8054 
                or stunAttributeType == 0x8055) then
                
                DC.printf ('%d :attribute match.\n', context.packetCount)
                currentOffset = currentOffset + (stunAttributeLen+4);
            else
                break;
            end
        end   --while loop

        if ((size - currentOffset) == 0) then 
            DC.printf ('%d :found stun.\n', context.packetCount)
            return 1
        end
    end
    return 0
end

--[[Validator function registered in DetectorInit()
--]]
function DetectorValidator()
    local context = {}

    context.detectorFlow = gDetector:getFlow()
    context.packetCount = gDetector:getPktCount()
    context.packetDataLen = gDetector:getPacketSize()
    context.packetDir = gDetector:getPacketDir()
    context.flowKey = context.detectorFlow:getFlowKey()
    context.srcPort = gDetector:getPktSrcPort()
    context.dstPort = gDetector:getPktDstPort()

    local dir =  context.packetDir
    local size = context.packetDataLen
    local flowKey = context.flowKey
    local srcPort = context.srcPort
    local dstPort = context.dstPort

    DC.printf ('%s:DetectorValidator(): packetCount %d\n', gServiceName, context.packetCount);

    if (size == 0) then
        return serviceInProcess(context)
    end

    local rft = FT.getFlowTracker(flowKey)
    if (not rft) then
        rft = FT.addFlowTracker(flowKey,  {serviceStatus=DC.serviceStatus.inProcess})
    end

    if (dir == 0) then
        --client side
        if (MatchPacket(context) == 1) then
            if (rft == nil) then
                FT.addFlowTracker(flowKey, {stage=2})
            else
                rft.stage = 2
            end

            DC.printf ('packet %d: detected stun on client side\n', context.packetCount)
            return serviceInProcess(context)
        end
    else
        --server side
        --first server response received after getting client request.
        if ((rft) and (rft.stage == 2)) then
            FT.delFlowTracker(flowKey)
            return serviceSuccess(context)
        end

        --[[First server packet received. Server side patterns have the same reliability 
        as client side pattern therefore declaring service detected.
        --]]
        
        if (MatchPacket(context) == 1) then
            DC.printf ('packet %d: detected stun on server side\n', context.packetCount)
            if (rft) then
                FT.delFlowTracker(flowKey)
            end
            return serviceSuccess(context)
        end
    end

    return serviceInProcess(context)
end

--[[Required DetectorFini function
--]]
function DetectorFini()
    --print (gServiceName .. ': DetectorFini()')
end
