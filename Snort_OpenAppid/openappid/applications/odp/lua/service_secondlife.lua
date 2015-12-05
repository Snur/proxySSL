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
detection_name: Second Life
version: 4
description: A multiplayer online shared virtual world.
--]]

require "DetectorCommon"


local DC = DetectorCommon
local FT = flowTrackerModule

DetectorPackageInfo = {
    name =  "secondlife",
    proto =  DC.ipproto.udp,
    server = {
        init =  'DetectorInit',
        validate =  'DetectorValidator',
    }
}

gServiceId = 20033
gServiceName = 'secondlife'
gSfAppIdSecondlife = 415
gDetector = nil

--patterns used in DetectorInit()
gPatterns = {
    reqPacket = "\064\000\000\000\001",
}

--fast pattern registerd with core engine - needed when not using CSD tables
gFastPatterns = {
    {DC.ipproto.udp, gPatterns.reqPacket,      #gPatterns.reqPacket, 0, gSfAppIdSecondlife},
}

--port based detection - needed when not using CSD tables
gPorts = {
    {DC.ipproto.udp, 12035},
    {DC.ipproto.udp, 12036},
}

gAppRegistry = {
	--AppIdValue          Extracts Info
	---------------------------------------
	{415,		         0}
}

--contains detector specific data related to a flow 
gFlowDataTable = {}

function serviceInProcess(context)

    local flowFlag = context.detectorFlow:getFlowFlag(DC.flowFlags.serviceDetected)

    if ((not flowFlag) or (flowFlag == 0)) then
        gDetector:inProcessService()
    end

    DC.printf('%s: inProcess, packetCount: %d\n', gServiceName, context.packetCount);
    return DC.serviceStatus.inProcess
end

function serviceSuccess(context)
    local flowFlag = context.detectorFlow:getFlowFlag(DC.flowFlags.serviceDetected)

    if ((not flowFlag) or (flowFlag == 0)) then
        gDetector:addService(gServiceId, "", "", gSfAppIdSecondlife)
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

    DC.printf('%s: Fail, packetCount: %d\n', gServiceName, context.packetCount);
    return DC.serviceStatus.nomatch
end

function registerPortsPatterns()

    --register port based detection
    for i,v in ipairs(gPorts) do
        gDetector:addPort(v[1], v[2])
    end

    for i=13000,13050 do 
        gDetector:addPort(DC.ipproto.udp, i)
    end

    --register pattern based detection
    for i,v in ipairs(gFastPatterns) do
        --ret = detector:registerPattern(v[1], v[2], v[3], v[4])
        --if (ret == 0) then
        if (gDetector:registerPattern(v[1], v[2], v[3], v[4], v[5]) ~= 0) then
            DC.printf ('%s: register pattern failed for %s\n', gServiceName,v[2])
        else
            DC.printf ('%s: register pattern successful for %s\n', gServiceName,v[2])
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

    rfd = gFlowDataTable[flowKey]
    if not rfd
    then
        gFlowDataTable[flowKey] =  {serviceStatus=DC.serviceStatus.inProcess}
        rfd = gFlowDataTable[flowKey]
    end

    DC.printf ('%s:DetectorValidator(): packetCount %d, dir %d, size %d, dstPort %d\n', gServiceName, context.packetCount, dir, size, dstPort);

    if (size == 0) then
        return serviceInProcess(context)
    end

    if (dir == 0) then
        if ((dstPort == 12035 or dstPort == 12036 or (dstPort >= 13000 and dstPort <= 13050))) then 
            if ((size > 6) and (gDetector:memcmp(gPatterns.reqPacket, #gPatterns.reqPacket, 0) == 0)) then
                DC.printf ('%s:DetectorValidator(): found request packet\n',gServiceName)
                rfd.serviceStatus = DC.serviceStatus.success
                return serviceInProcess(context)
            end
        else
            rfd.serviceStatus = DC.serviceStatus.nomatch
        end

    else
        if (rfd.serviceStatus == DC.serviceStatus.success) then
            gFlowDataTable[flowKey] = nil
            return serviceSuccess(context)
        else
            if (context.packetCount < 20) then
                return serviceInProcess(context)
            else
                gFlowDataTable[flowKey] = nil
                return  serviceFail(context)
            end
        end
    end

    if (context.packetCount < 20) then
        return serviceInProcess(context)
    else
        return serviceFail(context)
    end

end

--[[Required DetectorFini function
--]]
function DetectorFini()
    --print (gServiceName .. ': DetectorFini()')
end
