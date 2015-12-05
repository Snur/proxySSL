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
detection_name: TPKT
version: 9
description: A protocol used to tunnel OSI protocols over TCP/IP.
bundle_description: $VAR1 = {
          'RDP' => 'Remote Desktop Protocol provides users with a graphical interface to another computer.',
          'TPKT' => 'A protocol used to tunnel OSI protocols over TCP/IP.',
          'ISO MMS' => 'Manufacturer Messaging Specification, the ISO session-layer protocol.',
          'COTP' => 'Connection-oriented ISO protocol.',
          'Q.931' => 'ISO standard signalling protocol.',
          'ITU H.323' => 'Packet-based mulimedia conferencing protocol.'
        };

--]]

require "DetectorCommon"

--require('debugger')

--local DC = require("DetectorCommon")
local DC = DetectorCommon
local HT = hostServiceTrackerModule
local FT = flowTrackerModule

DetectorPackageInfo = {
    name =  "TPKT",
    proto =  DC.ipproto.tcp,
    server = {
        init =  'DetectorInit',
        validate =  'DetectorValidator',
    }
}

gServiceId = 20163
gServiceName = 'TPKT'

gSfAppIdTPKT = 2311
gSfAppIdCOTP = 2312
gSfAppIdISOMMS = 2313
gSfAppIdQ931 = 2314
gSfAppIdH323 = 688
gSfAppIdRDP = 803

gServiceIdTPKT = gServiceId
gServiceIdCOTP = 20164
gServiceIdISOMMS = 20165
gServiceIdQ931 = 20166
gServiceIdH323 = 20076
gServiceIdRDP = 20029

gPatterns = {
    tpkt = { "\003\000", 0, gSfAppIdTPKT},
    q931 = { "\008\002", 4, gSfAppIdTPKT},
}

gFastPatterns = {
    {DC.ipproto.tcp, gPatterns.tpkt},
    {DC.ipproto.tcp, gPatterns.q931},
}

gPorts = {
    {DC.ipproto.tcp, 102},
    {DC.ipproto.tcp, 3389},
    {DC.ipproto.tcp, 1718},
    {DC.ipproto.udp, 1718},
    {DC.ipproto.tcp, 1719},
    {DC.ipproto.udp, 1719},
    {DC.ipproto.tcp, 1720},
    {DC.ipproto.udp, 1720},
}

gAppRegistry = {
	{gSfAppIdTPKT, 0},
    {gSfAppIdH323, 0},
    {gSfAppIdRDP, 0},
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

    DC.printf('%s: service %d, appId %d\n', gServiceName, context.service_id, context.appId)

    if ((not flowFlag) or (flowFlag == 0)) then
        DC.printf('%s: adding service\n', gServiceName)
        gDetector:addService(context.service_id, "ISO", "", context.appId)
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

    if (size == 0 or dir == 0) then
        return serviceInProcess(context)
    end

    DC.printf ('%s:DetectorValidator(): packetCount %d, dir %d, size %d\n', gServiceName, context.packetCount, dir, size);

    if (not rft) then
        rft = FT.addFlowTracker(flowKey, {next_packet=0})
    end

    if (size >= 6 and gDetector:memcmp(gPatterns.tpkt[1], #gPatterns.tpkt[1], gPatterns.tpkt[2]) == 0) then
        DC.printf('%s:TPKT header\n', gServiceName)
        
        matched, byte_four_raw, byte_five_raw = gDetector:getPcreGroups("(.)(.)",4)
        byte_four = DC.binaryStringToNumber(byte_four_raw, 1)
        byte_five = DC.binaryStringToNumber(byte_five_raw, 1)        

        if (byte_four == 8 and byte_five == 2) then
            DC.printf('%s:Q.931\n',gServiceName)
            if (gDetector:getPcreGroups('\008\145\074\000\004')) then
                DC.printf('%s:got H323\n',gServiceName)
                context.service_id = gServiceIdH323
                context.appId = gSfAppIdH323
            else
                DC.printf('%s:it is only Q.931\n',gServiceName)
                context.service_id = gServiceIdQ931
                context.appId = gSfAppIdQ931
            end
            return serviceSuccess(context)
        end

        if (rft.next_packet == 0) then 
            if (byte_four == size-5 and byte_five == 208) then 
                DC.printf('%s:COPT packet\n',gServiceName)
                rft.next_packet = 1
                return serviceInProcess(context)
            else
                DC.printf('%s:All we know is this is TPKT frame\n',gServiceName)
                context.service_id = gServiceIdTPKT
                context.appId = gSfAppIdTPKT
                return serviceSuccess(context) 
            end
        elseif (rft.next_packet == 1) then 
            if (byte_five == 240 and gDetector:getPcreGroups('\202\034\002\003')) then
                DC.printf('%s:got MMS!\n',gServiceName)
                context.service_id = gServiceIdISOMMS
                context.appId = gSfAppIdISOMMS
            elseif (byte_five == 240 and srcPort == 3398) then
                DC.printf('%s:this is RDP\n',gServiceName)
                context.service_id = gServiceIdRDP
                context.appId = gSfAppIdRDP
            else 
                DC.printf('%s:All we know is this is COPT frame\n',gServiceName)
                context.service_id = gServiceIdCOTP
                context.appId = gSfAppIdCOTP
            end            
            return serviceSuccess(context)
        end
    end

    return serviceFail(context)

end

--[[Required DetectorFini function
--]]
function DetectorFini()
    --print (gServiceName .. ': DetectorFini()')
end
