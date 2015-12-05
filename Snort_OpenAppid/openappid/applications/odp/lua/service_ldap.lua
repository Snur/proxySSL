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
detection_name: LDAP
version: 6
description: Lightweight Directory Access Protocol, a protocol for reading and editing directories over an IP network.
--]]

require "DetectorCommon"

--local DC = require("DetectorCommon")
local DC = DetectorCommon
local FT = flowTrackerModule

DetectorPackageInfo = {
    name =  "BitCoin",
    proto =  DC.ipproto.tcp,
    server = {
        init =  'DetectorInit',
        validate =  'DetectorValidator',
    }
}

gServiceIdLdap = 20012
gServiceIdLdaps = 20123
gServiceName = 'LDAP'
gDetector = nil

-- Port based detection since there are no fixed fields in the message.
gPorts = {
    {DC.ipproto.tcp, 389},
    {DC.ipproto.udp, 389}
}

-- It may be possible to use fast pattern matching on the message ID field which
-- may be at offsets from 3 to 6.  The two byte pattern consists of 0x02 and a
-- field length that can be any value from 1 to 4.  This means match any one of
-- four two byte patters over a range of four offsets may cause excessive false
-- hits.

gAppRegistry = {
	--AppIdValue          Extracts Info
	---------------------------------------
	{710,		         0},
	{1116,		         0}
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
    FT.delFlowTracker(context.flowKey)
    local flowFlag = context.detectorFlow:getFlowFlag(DC.flowFlags.serviceDetected)

    if ((not flowFlag) or (flowFlag == 0)) then
        gDetector:addService(context.serviceIdLdapVsLdaps, "", "", context.LdapVsLdaps)
        DC.printf('%s: Detected %d, packetCount: %d\n', gServiceName, context.LdapVsLdaps, context.packetCount);
    end

    return DC.serviceStatus.success
end

function serviceFail(context)
    FT.delFlowTracker(context.flowKey)
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

    gDetector = detectorInstance
    gDetector:init(gServiceName, 'DetectorValidator', 'DetectorFini')
    registerPortsPatterns()

    DC.printf (gServiceName .. ': DetectorInit()')

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

    DC.printf ('%s:DetectorValidator(): packetCount %d, dir %d, size %d\n', gServiceName,
               context.packetCount, dir, size);
    if (size == 0) then
        return serviceInProcess(context)
    end

    local offset = 0
    local matched, rawStr = gDetector:getPcreGroups("(..)", offset);
    if (matched) then
        tag = string.byte(rawStr,1)
        len = string.byte(rawStr,2)
        DC.printf('%s:DetectorValidator(): Sequence Tag: %x len: %x\n', gServiceName, tag, len);
        offset = offset + 2
    else
        return serviceFail(context)
    end

    -- LDAP requests and responses start with an ASN.1 sequence tag
    if (tag ~= 0x30) then
        return serviceFail(context)
    end

    -- Validate the sequence langth
    if (len == 0 or len == 0x80 or len == 0xff) then
        return serviceFail(context)
    end

    -- adjust length if multibyte field
    if (len > 0x80) then
        len = len - 0x80
        offset = offset + len
    end

    -- Verify the message id field
    matched, rawStr = gDetector:getPcreGroups("(..)", offset);
    if (matched) then
        offset = offset + 2
        tag = string.byte(rawStr,1)
        len = string.byte(rawStr,2)
        DC.printf('%s:DetectorValidator(): Message ID Tag: %x len: %x\n', gServiceName, tag, len);
    else
        return serviceFail(context)
    end

    if(tag ~= 0x02) then          -- ASN.1 integer tag
        return serviceFail(context)
    end

    -- Verify the message id field width
    if (len < 1 or len > 4) then
        return serviceFail(context)
    end

    -- Verify that the packet op is valid
    offset = offset + len
    matched, rawStr = gDetector:getPcreGroups("(.)", offset);
    if (matched) then
        tag = string.byte(rawStr,1)
        DC.printf('%s:DetectorValidator(): Packet Op: 0x%x\n', gServiceName, tag);
    else
        return serviceFail(context)
    end

    if(tag >= 0x60 and tag <= 0x7f) then
        local rft = FT.getFlowTracker(flowKey)
        if (not rft) then
            rft = FT.addFlowTracker(flowKey, {startTlsSeen=0})
        end
        DC.printf('%s:DetectorValidator(): Detected\n', gServiceName);
        -- Check for the LDAP START TLS extended req OID (a length-preceded ASCII string NOT an ASN.1 encoding of an OID)
        if(dir == 0) then
            if (tag == 0x77 and gDetector:matchSimplePattern("\x161.3.6.1.4.1.1466.20037",0x17, offset+3)) then
                DC.printf('%s:DetectorValidator(): LDAP START TLS sent by client.\n', gServiceName);
                rft.startTlsSeen = 1
            end
            DC.printf('%s:DetectorValidator():packet detected on client side\n', gServiceName);
            return serviceInProcess(context)
        else
            if (rft.startTlsSeen == 1 and (tag ~= 0x78  or not gDetector:matchSimplePattern("\x01\x00",0x02, offset+3))) then
                DC.printf('%s:DetectorValidator(): LDAP START TLS rejected by server.\n', gServiceName);
                rft.startTlsSeen = 0
            end
        end
        if (rft.startTlsSeen ~= 1) then
            context.LdapVsLdaps = 710
            context.serviceIdLdapVsLdaps = gServiceIdLdap
        else
            context.LdapVsLdaps = 1116
            context.serviceIdLdapVsLdaps = gServiceIdLdaps
        end
        return serviceSuccess(context)
    else
        return serviceFail(context)
    end

    return serviceFail(context)
end

--[[Required DetectorFini function
--]]
function DetectorFini()
    --DC.printf(gServiceName .. ': DetectorFini()')
end
