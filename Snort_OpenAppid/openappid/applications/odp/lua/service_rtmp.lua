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
detection_name: RTMP
version: 4
description: Real Time Messaging Protocol is commonly used for streaming Flash Video.
--]]

require "DetectorCommon"

--require('debugger')

--local DC = require("DetectorCommon")
local DC = DetectorCommon

gServiceId = 20063
gServiceName = 'Real Time Messenging Protocol'

DetectorPackageInfo = {
    name = "Real Time Messenging Protocol",
    proto = DC.ipproto.tcp,
    server = {
        init = 'DetectorInit',
        validate = 'DetectorValidator',
    }
}

--port based detection - needed when not using CSD tables
gPorts = {
    {DC.ipproto.tcp, 1935},
}

gAppRegistry = {
	--AppIdValue          Extracts Info
	---------------------------------------
	{812,		         0}
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
        gDetector:addService(gServiceId, "", "", 812)
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

function binaryStringToNumberOther (binString, numBytes)
    local totalValue = 0
    local index=numBytes
    while (index > 0) do
        totalValue = bit.lshift(totalValue, 8)
        local curValue
        if binString:byte(index) then
            curValue = binString:byte(index)
            totalValue = totalValue + curValue
        end
        -- DC.printf("offset %d, cur %d, total %d\n",index,curValue,totalValue)
        index = index-1
    end
    return totalValue
end

function getStringPlain (data, length)
    local stringValue=""
    local index=0

    while (index <  length) do
        stringValue = string.format('%s%.2x', stringValue, string.byte(data,index+1))
        index = index + 1
    end
    return stringValue
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

    -- DC.printf ('%s:DetectorValidator(): packetCount %d, dir %d\n', gServiceName, context.packetCount, dir);
    if (size == 0 or dir == 0) then
        return serviceInProcess(context)
    end

    if (dir == DC.flowDirection.fromResponder and srcPort == 1935 and size >= 12) then
        matched, body_size_raw = gDetector:getPcreGroups("(...)", 4)
        body_size = DC.binaryStringToNumber(body_size_raw, 3)
        matched_string = getStringPlain(matched, 3)
        if (body_size == size -12) then
            return serviceSuccess(context)
        else 
            return serviceInProcess(context)
        end
    else
        return serviceInProcess(context)
    end

    --return serviceInProcess(context)
    return serviceFail(context)
end

--[[Required DetectorFini function
--]]
function DetectorFini()
    --print (gServiceName .. ': DetectorFini()')
end
