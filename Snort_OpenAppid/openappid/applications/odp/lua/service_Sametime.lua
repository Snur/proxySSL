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
detection_name: Sametime
version: 5
description: An IBM/Lotus collaboration product.
--]]

require "DetectorCommon"

--require('debugger')

--local DC = require("DetectorCommon")
local DC = DetectorCommon

gServiceId = 20162
gServiceName = 'Sametime'
gSfAppIdSametime = 2727
gAltAppIdHamachi = 1156

DetectorPackageInfo = {
    name =  "Sametime",
    proto =  DC.ipproto.tcp,
    server = {
        init =  'DetectorInit',
        validate =  'DetectorValidator',
        minimum_matches = 1,
    }
}

gPatterns = {
    cli_pat = {'\000\000\000\000\000\000\000\000\255\255', 4, gSfAppIdSametime},
    srv_pat = {'\000\037\000\000\000\000\000\000\000\000\000\064\150', 4, gSfAppIdSametime},
}

gFastPatterns = {
    {DC.ipproto.tcp, gPatterns.cli_pat},
    {DC.ipproto.tcp, gPatterns.srv_pat},
}

gPorts = {
    {DC.ipproto.tcp, 1533},
}

gAppRegistry = {
	{gSfAppIdSametime,		         0},
    {gAltAppIdHamachi,               0},
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
        gDetector:addService(gServiceId, "IBM", "", gSfAppIdSametime)
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

    --register port based detection
    for i,v in ipairs(gPorts) do
        gDetector:addPort(v[1], v[2])
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
    local current_index = 0


    DC.printf('%s:DetectorValidator(): packetCount %d, dir %d, size %d, srcPort %d\n', gServiceName, context.packetCount, dir, size, srcPort)    

    if (size == 0 or dir == 0) then
        return serviceInProcess(context)
    end

    if (dir == 1 and size > 18 and (gDetector:memcmp(gPatterns.srv_pat[1], #gPatterns.srv_pat[1], gPatterns.srv_pat[2]) == 0)) then
        DC.printf('%s: server packet, checking it out\n', gServiceName)
        matched, rawlen = gDetector:getPcreGroups('...(.)',0)
        len = DC.binaryStringToNumber(rawlen, 1)      
        if (len == size-4) then
            DC.printf('%s: len %d is equal to size %d minus 4, we got it\n', gServiceName, len, size)
            return serviceSuccess(context)
        end
    end

    return serviceFail(context)
    --return serviceFail(context)
end

--[[Required DetectorFini function
--]]
function DetectorFini()
    --print (gServiceName .. ': DetectorFini()')
end
