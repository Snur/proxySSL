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
description: First person shooter.
--]]

require "DetectorCommon"



local DC = DetectorCommon
local FT = flowTrackerModule

gDetector = nil

DetectorPackageInfo = {
    name =  "Quake",
    proto =  DC.ipproto.udp,
    client = {
        init =  'client_init',
        clean = 'client_clean',
		validate =  'client_validate',
		minimum_matches = 1
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
    {DC.ipproto.udp, gPatterns.client_getservers},
    {DC.ipproto.udp, gPatterns.client_getinfo},
    {DC.ipproto.udp, gPatterns.client_challenge},
    {DC.ipproto.udp, gPatterns.client_conn},
    {DC.ipproto.udp, gPatterns.client_auth},
}

gAppRegistry = {
	--AppIdValue          Extracts Info
	---------------------------------------
	{gSfAppIdQuake,		         0}
}

flowTrackerTable = {}

function clientInProcess(context)

	DC.printf('%s: Inprocess Client, packetCount: %d\n', DetectorPackageInfo.name, context.packetCount)
	return DC.clientStatus.inProcess
end

function clientSuccess(context)
    context.detectorFlow:setFlowFlag(DC.flowFlags.clientAppDetected)
    DC.printf('%s: Detected Client, packetCount: %d\n', DetectorPackageInfo.name, context.packetCount)
    gDetector:client_addApp(appServiceId, appTypeId, appProductId, "", gSfAppIdQuake);
    flowTrackerTable[context.flowKey] = Nil
    return DC.clientStatus.success
end

function clientFail(context)
    DC.printf('%s: Failed Client, packetCount: %d\n', DetectorPackageInfo.name, context.packetCount)
    flowTrackerTable[context.flowKey] = Nil
    return DC.clientStatus.einvalid
end

function registerPortsPatterns()

    --register port based detection
    for i,v in ipairs(gPorts) do
        gDetector:addPort(v[1], v[2])
    end

end

--[[ Core engine calls DetectorInit() to initialize a detector.
--]]
function client_init( detectorInstance, configOptions)
    gDetector = detectorInstance
    DC.printf ('%s:DetectorInit()\n', DetectorPackageInfo.name);
	gDetector:client_init()
	appTypeId = 18
	appProductId = 99
	appServiceId = 20090
	--DC.printf ('%s:DetectorValidator(): appTypeId %d, product %d, service %d\n', DetectorPackageInfo.name, appTypeId, appProductId, appServiceId)

    --register pattern based detection
    for i,v in ipairs(gFastPatterns) do
        if ( gDetector:client_registerPattern(v[1], v[2][1], #v[2][1], v[2][2], v[2][3]) ~= 0) then
            DC.printf ('%s: register pattern failed for %s\n', DetectorPackageInfo.name,v[2][1])
        else
            DC.printf ('%s: register pattern successful for %s\n', DetectorPackageInfo.name,v[2][1])
        end
    end

	for i,v in ipairs(gAppRegistry) do
		pcall(function () gDetector:registerAppId(v[1],v[2]) end)
	end

    return gDetector
end


--[[Validator function registered in DetectorInit()
--]]
function client_validate()
    local context = {}
    context.detectorFlow = gDetector:getFlow()
	context.packetCount = gDetector:getPktCount()
    context.packetDataLen = gDetector:getPacketSize()
    context.packetDir = gDetector:getPacketDir()
	context.flowKey = context.detectorFlow:getFlowKey()
    context.srcPort = gDetector:getPktSrcPort()
    context.dstPort = gDetector:getPktDstPort()
    local size = context.packetDataLen
    local dir = context.packetDir
    local srcPort = context.srcPort
    local dstPort = context.dstPort
    local flowKey = context.flowKey

    DC.printf ('packetCount %d, dir %d, size %d\n', context.packetCount, dir, size);
    if (size == 0) then
        return clientInProcess(context)
    end

    if (dir == 0 and size >= 6) then 
		if ((gDetector:memcmp(gPatterns.client_getservers[1], #gPatterns.client_getservers[1], gPatterns.client_getservers[2]) == 0) or
			(gDetector:memcmp(gPatterns.client_getinfo[1], #gPatterns.client_getinfo[1], gPatterns.client_getinfo[2]) == 0) or
			(gDetector:memcmp(gPatterns.client_challenge[1], #gPatterns.client_challenge[1], gPatterns.client_challenge[2]) == 0) or
			(gDetector:memcmp(gPatterns.client_conn[1], #gPatterns.client_conn[1], gPatterns.client_conn[2]) == 0) or
			(gDetector:memcmp(gPatterns.client_auth[1], #gPatterns.client_auth[1], gPatterns.client_auth[2]) == 0))
		then
			return clientSuccess(context)
		end
    end    

    return clientFail(context)
end

function client_clean()
end

