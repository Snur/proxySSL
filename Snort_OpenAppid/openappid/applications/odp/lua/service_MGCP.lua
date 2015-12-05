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
detection_name: MGCP
version: 1
description: VoIP control protocol.
--]]

require "DetectorCommon"



local DC = DetectorCommon
local FT = flowTrackerModule

gServiceId = 20082
gServiceName = 'MGCP'
gDetector = nil

DetectorPackageInfo = {
    name =  "MGCP",
    proto =  DC.ipproto.udp,
    server = {
        init =  'DetectorInit',
        validate =  'DetectorValidator',
    }
}

gSfAppIdMgcp = 730
gPatterns = {
    string00 = { "RSIP", 0, gSfAppIdMgcp},
    string01 = { "AUCX", 0, gSfAppIdMgcp},
    string02 = { "AUEP", 0, gSfAppIdMgcp},
    string03 = { "NTFY", 0, gSfAppIdMgcp},
    string04 = { "RQNT", 0, gSfAppIdMgcp},
    string05 = { "DLCX", 0, gSfAppIdMgcp},
    string06 = { "MDCX", 0, gSfAppIdMgcp},
    string07 = { "CRCX", 0, gSfAppIdMgcp},
    string08 = { "EPCF", 0, gSfAppIdMgcp},
}

gFastPatterns = {
    {DC.ipproto.udp, gPatterns.string00},
    {DC.ipproto.udp, gPatterns.string01},
    {DC.ipproto.udp, gPatterns.string02},
    {DC.ipproto.udp, gPatterns.string03},
    {DC.ipproto.udp, gPatterns.string04},
    {DC.ipproto.udp, gPatterns.string05},
    {DC.ipproto.udp, gPatterns.string06},
    {DC.ipproto.udp, gPatterns.string07},
    {DC.ipproto.udp, gPatterns.string08},
}

gPorts = {
    {DC.ipproto.udp, 2427},
    {DC.ipproto.udp, 2727},
}

gAppRegistry = {
	--AppIdValue          Extracts Info
	---------------------------------------
	{gSfAppIdMgcp,		         0}
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
        gDetector:addService(gServiceId, "", "", gSfAppIdMgcp)
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
    local flowKey = context.flowKey

    DC.printf ('%s:DetectorValidator(): packetCount %d, dir %d, size %d\n', gServiceName,
               context.packetCount, dir, size);
    if (size == 0) then
        return serviceInProcess(context)
    end

    if (dir == 0 and size >= 20) 
    then
        matched, client_transid = gDetector:getPcreGroups('(.....)', 5)
        return serviceInProcess(context)
    end

    if (dir == 1 and client_transid and size >= 10)
    then
        matched, server_transid = gDetector:getPcreGroups('(.....)', 4)
        DC.printf("%s: server transid %s, client transid %s\n", gServiceName, server_transid, client_transid)
        if (client_transid == server_transid) 
        then
            return serviceSuccess(context)
        end
        client_transid = nil
    end

    return serviceFail(context)
end

--[[Required DetectorFini function
--]]
function DetectorFini()
    --print (gServiceName .. ': DetectorFini()')
end

