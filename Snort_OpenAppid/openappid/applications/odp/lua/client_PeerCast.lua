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
detection_name: PeerCast
version: 1
description: P2P file sharing service.
--]]

require "DetectorCommon"



local DC = DetectorCommon
local FT = flowTrackerModule

gDetector = nil

DetectorPackageInfo = {
    name =  "PeerCast",
    proto =  DC.ipproto.tcp,
    client = {
        init =  'client_init',
        clean = 'client_clean',
		validate =  'client_validate',
		minimum_matches = 1
    }
}

gFBsaw_give = nil
gFBsaw_binary = nil
gFBsaw_download = nil

gSfAppIdNone = 0
gSfAppIdPeerCast = 782

gPatterns = {
	downloadPattern = { "GET\032\047channel\047", 0, gSfAppIdPeerCast},
	uploadPattern = { "GIV\032\047", 0, gSfAppIdPeerCast},
	binaryPattern = { "pcp\010", 0, gSfAppIdPeerCast},

	uploadFollowup = { "\013\010\013\010", 0, gSfAppIdNone},
	binaryFollowup = { "helo", 0, gSfAppIdNone},
	downloadFollowup1 = {"x-peercast-pos", 0, gSfAppIdNone},
	downloadFollowup2 = {"x-peercast-pcp", 0, gSfAppIdNone},
}

gFastPatterns = {
    {DC.ipproto.tcp, gPatterns.downloadPattern},
    {DC.ipproto.tcp, gPatterns.uploadPattern},
    {DC.ipproto.tcp, gPatterns.binaryPattern},
}


gAppRegistry = {
	--AppIdValue          Extracts Info
	---------------------------------------
	{gSfAppIdPeerCast,		         0}
}

flowTrackerTable = {}

function clientInProcess(context)
	DC.printf('%s: Inprocess Client, packetCount: %d\n', DetectorPackageInfo.name, context.packetCount)
	return DC.clientStatus.inProcess
end

function clientSuccess(context)
    context.detectorFlow:setFlowFlag(DC.flowFlags.clientAppDetected)
    DC.printf('%s: Detected Client, packetCount: %d\n', DetectorPackageInfo.name, context.packetCount)
    gDetector:client_addApp(appServiceId, appTypeId, appProductId, "", gSfAppIdPeerCast);
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
	appProductId = 100
    appServiceId = 20092
	DC.printf ('%s:DetectorValidator(): appTypeId %d, product %d\n', DetectorPackageInfo.name, appTypeId, appProductId)

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

	--UPLOAD CASE
	if ((size >= #gPatterns.uploadPattern[1]) and
        (gDetector:memcmp(gPatterns.uploadPattern[1], #gPatterns.uploadPattern[1], gPatterns.uploadPattern[2]) == 0) and
        (not gFBsaw_give))
	then
		gFBsaw_give = true
		return clientInProcess(context)
	end

	--BINARY REQUEST CASE
	if ((size == 4) and
		(gDetector:memcmp(gPatterns.binaryPattern[1], #gPatterns.binaryPattern[1], gPatterns.binaryPattern[2]) == 0) and
		(not gFBsaw_binary))
	then
		gFBsaw_binary = true
		return clientInProcess(context)
	end


	--DOWNLOAD CASE 
	if ((size >= #gPatterns.downloadPattern[1]) and
		(gDetector:memcmp(gPatterns.downloadPattern[1], #gPatterns.downloadPattern[1], gPatterns.downloadPattern[2]) == 0) and
		(not gFBsaw_download))
	then
		gFBsaw_download = true
		return clientInProcess(context)
	end
	

	--If we find one of the potential messages, use handleCases to inspect further
	if (gFBsaw_give or gFBsaw_binary or gFBsaw_download) then
		return handleCases(dir, context, size)
	end
	

	gFBsaw_download = false
	gFBsaw_binary = false
	gFBsaw_give = false	
    return clientFail(context)
end

function handleCases(dir, context, size)
	if ((gFBsaw_give) and
		(size == 4) and
		(gDetector:memcmp(gPatterns.uploadFollowup[1], #gPatterns.uploadFollowup[1], gPatterns.uploadFollowup[2]) == 0))
	then
		gFBsaw_give = false
		return clientSuccess(context)	
	end

	if ((gFBsaw_binary) and 
	    (gDetector:getPcreGroups(gPatterns.binaryFollowup[1])))
	 then
		gFBsaw_binary = false
		return clientSuccess(context)
	end

	if ((gFBsaw_download) and
		(gDetector:getPcreGroups(gPatterns.downloadFollowup1[1])) and
		(gDetector:getPcreGroups(gPatterns.downloadFollowup2[1])))
	then
		gFBsaw_download = false
		return clientSuccess(context)
	end

	return clientFail(context)
end

function client_clean()
end

