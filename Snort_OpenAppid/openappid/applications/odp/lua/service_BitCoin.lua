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
detection_name: BitCoin
version: 3
description: Application and website for mining and exchanging BitCoins, a cryptographic currency.
bundle_description: $VAR1 = {
          'LiteCoin' => 'A cryptopgraphic currency similar to BitCoin which requires lighter-weight resources to mine.',
          'BitCoin' => 'Application and website for mining and exchanging BitCoins, a cryptographic currency.'
        };

--]]

require "DetectorCommon"

--require('debugger')

--local DC = require("DetectorCommon")
local DC = DetectorCommon
local HT = hostServiceTrackerModule
local FT = flowTrackerModule

DetectorPackageInfo = {
    name =  "BitCoin",
    proto =  DC.ipproto.tcp,
    server = {
        init =  'DetectorInit',
        validate =  'DetectorValidator',
    }
}

gServiceId = 20154
gLiteCoinServiceId = 20155

gServiceName = 'BitCoin'

gSfAppIdBitCoin = 2083
gSfAppIdLiteCoin = 2084

gPatterns = {
    version = {'version', 4, gSfAppIdBitCoin},
    verack = {'verack', 4, gSfAppIdBitCoin},
}

gFastPatterns = {
    {DC.ipproto.tcp, gPatterns.version},
    {DC.ipproto.tcp, gPatterns.verack},
}

gAppRegistry = {
	{gSfAppIdBitCoin, 0},
    {gSfAppIdLiteCoin, 0},
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
        gDetector:addService(context.serviceId, "", "", context.appId)
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
    DC.printf('%s: DetectorInit()\n',gServiceName)

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

    DC.printf ('%s:DetectorValidator(): packetCount %d, dir %d, dstport %d srcport %d size %d\n', gServiceName, context.packetCount, dir, srcPort, dstPort, size);

    if (not rft) then
        rft = FT.addFlowTracker(flowKey, {client_hello=0, server_hello=0, msgId=0})
    end

    if (dir == 1 and size > 11) then
        if ((gDetector:memcmp(gPatterns.version[1], #gPatterns.version[1], gPatterns.version[2]) == 0) or 
            (gDetector:memcmp(gPatterns.verack[1], #gPatterns.verack[1], gPatterns.verack[2]) == 0)) then
            rft.conn_id = gDetector:getPcreGroups("(....)", 0)
            DC.printf('%s:DetectorValidator(): conn_id is %s\n', gServiceName, rft.conn_id)
            return serviceInProcess(context)
        end
    end

    if (dir == 0 and size > 11 and rft.conn_id) then
        client_conn_id = gDetector:getPcreGroups("(....)", 0)
        DC.printf('%s:DetectorValidator(): client_conn_id is %s\n', gServiceName, client_conn_id)
        if (client_conn_id == rft.conn_id) then
            DC.printf('%s:DetectorValidator(): conn_id match\n', gServiceName)
            if (dstPort == 9333) then
                context.serviceId = gLiteCointServiceId
                context.appId = gSfAppIdLiteCoin
                return serviceSuccess(context)
            elseif (dstPort == 8333) then
                context.serviceId = gServiceId
                context.appId = gSfAppIdBitCoin
                return serviceSuccess(context)
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
