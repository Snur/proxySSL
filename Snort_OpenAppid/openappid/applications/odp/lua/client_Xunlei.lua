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
detection_name: Xunlei
description: Chinese P2P program.
--]]

require "DetectorCommon"



local DC = DetectorCommon
local FT = flowTrackerModule

gDetector = nil

DetectorPackageInfo = {
    name =  "Xunlei",
    proto =  DC.ipproto.tcp, 
    client = {
        init =  'client_init',
        clean = 'client_clean',
		validate =  'client_validate',
		minimum_matches = 1
    }
}

gSfAppIdXunlei = 924

gPatterns = {
	download1 = {"CONNECT", 16, gSfAppIdXunlei},
	download2 = {"GET", 16, gSfAppIdXunlei},
	tcp1 = {"GETCH%", 14, gSfAppIdXunlei},
	tcp2 = {"SYNC%", 14, gSfAppIdXunlei},
	tcp3 = {"PRECAST%", 14, gSfAppIdXunlei},
	tcp4 = {"POPUP%", 14, gSfAppIdXunlei}, 
}


gFastPatterns = {
	{DC.ipproto.tcp, gPatterns.download1},
	{DC.ipproto.tcp, gPatterns.download2},
	{DC.ipproto.tcp, gPatterns.tcp1},
	{DC.ipproto.tcp, gPatterns.tcp2},
	{DC.ipproto.tcp, gPatterns.tcp3},
	{DC.ipproto.tcp, gPatterns.tcp4},
}


gAppRegistry = {
	--AppIdValue          Extracts Info
	---------------------------------------
	{gSfAppIdXunlei,		         0}
}

flowTrackerTable = {}

function clientInProcess(context)
	DC.printf('%s: Inprocess Client, packetCount: %d\n', DetectorPackageInfo.name, context.packetCount)
	return DC.clientStatus.inProcess
end

function clientSuccess(context)
    context.detectorFlow:setFlowFlag(DC.flowFlags.clientAppDetected)
    DC.printf('%s: Detected Client, packetCount: %d\n', DetectorPackageInfo.name, context.packetCount)
    gDetector:client_addApp(appServiceId, appTypeId, appProductId, "", gSfAppIdXunlei);
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
	appProductId = 109
	appServiceId = 20104
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

	if (size == 0) then
    	return clientInProcess(context)
    end

	--Impossible to grab login messages with a client detector, but can still see downloads/tcp messages

	if (size >= 15) then
		--handling various TCP messages
		if ((gDetector:memcmp("\000\002\000", 3, 1) == 0) and
			((gDetector:memcmp(gPatterns.tcp1[1], #gPatterns.tcp1[1], gPatterns.tcp1[2]) == 0) or
			 (gDetector:memcmp(gPatterns.tcp2[1], #gPatterns.tcp2[1], gPatterns.tcp2[2]) == 0) or
			 (gDetector:memcmp(gPatterns.tcp3[1], #gPatterns.tcp3[1], gPatterns.tcp3[2]) == 0) or
			 (gDetector:memcmp(gPatterns.tcp4[1], #gPatterns.tcp4[1], gPatterns.tcp4[2]) == 0)))
		then
			return clientSuccess(context)
		--handling downloads
		elseif (((gDetector:memcmp(gPatterns.download1[1], #gPatterns.download1[1], gPatterns.download1[2]) == 0) or
			 	 (gDetector:memcmp(gPatterns.download2[1], #gPatterns.download2[1], gPatterns.download2[2]) == 0)) and
				(gDetector:memcmp(")", 1, 0) == 0))
		then
			return clientSuccess(context)
		end	
	end

    return clientFail(context)
end

function client_clean()
end

