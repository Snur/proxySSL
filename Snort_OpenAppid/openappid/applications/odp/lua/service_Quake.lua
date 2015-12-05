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
detection_name: Quake
version: 1
description: First person shooter.
--]]

require "DetectorCommon"



local DC = DetectorCommon
local FT = flowTrackerModule

gServiceId = 20090
gServiceName = 'Quake'
gDetector = nil

DetectorPackageInfo = {
    name =  "Quake",
    proto =  DC.ipproto.udp,
    server = {
        init =  'DetectorInit',
        validate =  'DetectorValidator',
    }
}


gSfAppIdQuake = 795

gPatterns = {
    client_getservers = { "\255\255getServers", 0, gSfAppIdQuake},
    server_servers = { "\255\255servers", 0, gSfAppIdQuake},
    client_getinfo = { "\255\255getInfo", 0, gSfAppIdQuake},
    server_info = { "\255\255infoResponse", 0, gSfAppIdQuake},
    client_challenge = { "\255\255challenge", 0, gSfAppIdQuake},
    server_chalresp = { "\255\255challengeResponse", 0, gSfAppIdQuake},
    client_conn = { "\255\255connect", 0, gSfAppIdQuake},
    client_auth = { "\255\255clAuth", 0, gSfAppIdQuake},
    server_authkey = { "\255\255authkey", 0, gSfAppIdQuake},
    server_authreq = { "\255\255authrequired", 0, gSfAppIdQuake},
    server_print = { "\255\255print", 0, gSfAppIdQuake},
}

gFastPatterns = {
    {DC.ipproto.udp, gPatterns.server_servers},
    {DC.ipproto.udp, gPatterns.server_info},
    {DC.ipproto.udp, gPatterns.server_chalresp},
    {DC.ipproto.udp, gPatterns.server_authkey},
    {DC.ipproto.udp, gPatterns.server_authreq},
    {DC.ipproto.udp, gPatterns.server_print}, 
}

gPorts = {
}


gAppRegistry = {
	--AppIdValue          Extracts Info
	---------------------------------------
	{gSfAppIdQuake,		         0}
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
        gDetector:addService(gServiceId, "", "", gSfAppIdQuake)
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
    local srcPort = context.srcPort
    local dstPort = context.dstPort
    local flowKey = context.flowKey

    DC.printf ('%s:DetectorValidator(): packetCount %d, dir %d, size %d\n', gServiceName,
               context.packetCount, dir, size);
    if (size == 0 or dir == 0) then
        return serviceInProcess(context)
    end

	--Just recheck patterns to handle bruteforce
	if (dir == 1 and size >= 6) then
		if ((gDetector:memcmp(gPatterns.server_servers[1], #gPatterns.server_servers[1], gPatterns.server_servers[2]) == 0) or
			(gDetector:memcmp(gPatterns.server_info[1], #gPatterns.server_info[1], gPatterns.server_info[2]) == 0) or
			(gDetector:memcmp(gPatterns.server_chalresp[1], #gPatterns.server_chalresp[1], gPatterns.server_chalresp[2]) == 0) or
			(gDetector:memcmp(gPatterns.server_authkey[1], #gPatterns.server_authkey[1], gPatterns.server_authkey[2]) == 0) or
			(gDetector:memcmp(gPatterns.server_authreq[1], #gPatterns.server_authreq[1], gPatterns.server_authreq[2]) == 0) or
			(gDetector:memcmp(gPatterns.server_print[1], #gPatterns.server_print[1], gPatterns.server_print[2]) == 0))
		then
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

