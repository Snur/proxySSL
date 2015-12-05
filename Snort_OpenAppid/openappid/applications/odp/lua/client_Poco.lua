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
detection_name: Poco
description: P2P file sharing program.
--]]

require "DetectorCommon"



local DC = DetectorCommon
local FT = flowTrackerModule

gDetector = nil

DetectorPackageInfo = {
    name =  "Poco",
    proto =  DC.ipproto.tcp, --should be both
    client = {
        init =  'client_init',
        clean = 'client_clean',
		validate =  'client_validate',
		minimum_matches = 1
    }
}

gSfAppIdPoco = 786

gPatterns = {
	tcpPattern = { "POCO CONNECT/", 26, gSfAppIdPoco},
	udpPattern = { "\002\000POCO", 0, gSfAppIdPoco},	
}

gFastPatterns = {
	{DC.ipproto.tcp, gPatterns.tcpPattern},
    {DC.ipproto.udp, gPatterns.udpPattern},
}


gAppRegistry = {
	--AppIdValue          Extracts Info
	---------------------------------------
	{gSfAppIdPoco,		         0}
}

flowTrackerTable = {}

function clientInProcess(context)
	DC.printf('%s: Inprocess Client, packetCount: %d\n', DetectorPackageInfo.name, context.packetCount)
	return DC.clientStatus.inProcess
end

function clientSuccess(context)
    context.detectorFlow:setFlowFlag(DC.flowFlags.clientAppDetected)
    DC.printf('%s: Detected Client, packetCount: %d\n', DetectorPackageInfo.name, context.packetCount)
    gDetector:client_addApp(appServiceId, appTypeId, appProductId, "", gSfAppIdPoco);
    flowTrackerTable[context.flowKey] = Nil
    return DC.clientStatus.success
end

function clientFail(context)
    DC.printf('%s: Failed Client, packetCount: %d\n', DetectorPackageInfo.name, context.packetCount)
    flowTrackerTable[context.flowKey] = Nil
    return DC.clientStatus.einvalid
end


--[[ Core engine calls DetectorInit() to initialize a detector.
--]]
function client_init( detectorInstance, configOptions)
    gDetector = detectorInstance
    DC.printf ('%s:DetectorInit()\n', DetectorPackageInfo.name);
	gDetector:client_init()
	appTypeId = 15
	appProductId = 101
	appServiceId = 20093
	DC.printf ('%s:DetectorValidator(): appTypeId %d, product %d, service %d\n', DetectorPackageInfo.name, appTypeId, appProductId, appServiceId)

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

    DC.printf ('packetCount %d dir %d, size %d\n', context.packetCount, dir, size)

	if (size == 0 or dir == 1) then
    	return clientInProcess(context)
    end

	--UDP
	if ((size >= 16) and
		(gDetector:memcmp(gPatterns.udpPattern[1], #gPatterns.udpPattern[1], gPatterns.udpPattern[2]) == 0)) 	
	then
		matched, nullString1, nullString2 = gDetector:getPcreGroups("POCO(...)\100..(...).")
		if (matched and nullString1 == nullString2 and nullString1 == "\000\000\000") then --annoying work around for dealing with nulls
			return clientSuccess(context)
		end
	end

	--TCP
	if ((gDetector:memcmp(gPatterns.tcpPattern[1], #gPatterns.tcpPattern[1], gPatterns.tcpPattern[2]) == 0) and
		(size >= #gPatterns.tcpPattern[1] + 49) and
		(gDetector:getPcreGroups("\013\010AGENT: .*\013\010ULTRA: .*\013\010CLIENTID: .*\013\010PEER: .*\013\010AUTHCHA: ")))
	then
		return clientSuccess(context)
	end 
	
    return clientFail(context)
end

function client_clean()
end

