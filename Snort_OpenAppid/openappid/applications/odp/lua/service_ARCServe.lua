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
detection_name: ARCServe
version: 2
description: Distributed network backup system.
--]]

require "DetectorCommon"



local DC = DetectorCommon
local FT = flowTrackerModule

gServiceId = 20069
gServiceName = 'ARCServe'
gDetector = nil

DetectorPackageInfo = {
    name =  "ARCServe",
    proto =  DC.ipproto.tcp,
    server = {
        init =  'DetectorInit',
        validate =  'DetectorValidator',
    }
}

--global variables for event flags
gFBca_arcserve_discovery_service = nil
gSfAppIdArcserve = 552
gSfAppIdDceRpc = 603
gSfAppIdMapi = 277

gPatterns = {
    bind_ack = {'\005\000\012\003\016\000\000\000', 0, gSfAppIdDceRpc},
}

gFastPatterns = {
    {DC.ipproto.tcp, gPatterns.bind_ack},
}

gPorts = {
    {DC.ipproto.tcp, 135},
    {DC.ipproto.tcp, 139},
    {DC.ipproto.tcp, 445},
    {DC.ipproto.tcp, 6502},
    {DC.ipproto.tcp, 6503},
    {DC.ipproto.tcp, 6504},
    {DC.ipproto.tcp, 41523}, 
}


gAppRegistry = {
	--AppIdValue          Extracts Info
	---------------------------------------
    {gSfAppIdDceRpc,                 1},
	{gSfAppIdArcserve,		         1},
    {gSfAppIdMapi,                   1},
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
        gDetector:addService(context.service_id, "Computer Associates", "", context.appid)
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
        DC.printf('%s: registering port %d\n',gServiceName,v[2])
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

    arcserve_id = 552
    mapi_id = 277
    dcerpc_id = 603

    arcserve_service_id = 20069
    mapi_service_id = 20081
    dcerpc_service_id = 5

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

    DC.printf ('%s:DetectorValidator(): packetCount %d, dir %d, size %d\n', gServiceName,
               context.packetCount, dir, size);

    if (size == 0 or dir == 0) then
        return serviceInProcess(context)
    end

    if (dir == 1)
    then
        if (context.srcPort == 41523) then
            context.appid = arcserve_id
            context.service_id = arcserve_service_id
            return serviceSuccess(context)
        elseif ((size >= 10) and
            (gDetector:memcmp(gPatterns.bind_ack[1], #gPatterns.bind_ack[1], gPatterns.bind_ack[2]) == 0))
        then
            matched, len_raw = gDetector:getPcreGroups('(..)', 8)
            if (matched) then
                len = DC.reverseBinaryStringToNumber(len_raw, 2)
                DC.printf('%s: size %d, len %d\n', gServiceName, size, len)
                if (len == size) then
                    if (context.srcPort == 135 or context.srcPort == 139 or context.srcPort == 445) then
                        context.appid = mapi_id
                        context.service_id = mapi_service_id
                    elseif (context.srcPort == 6502 or context.srcPort == 6503 or context.srcPort == 6504) then
                        context.appid = arcserve_id
                        context.service_id = arcserve_service_id
                    else
                        context.appid = dcerpc_id
                        context.service_id = dcerpc_service_id
                    end 
                    return serviceSuccess(context)
                end
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

