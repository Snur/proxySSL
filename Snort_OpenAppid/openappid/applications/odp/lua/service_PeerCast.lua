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
version: 2
description: P2P file sharing service.
--]]

require "DetectorCommon"



local DC = DetectorCommon
local FT = flowTrackerModule

gServiceId = 20092
gServiceName = 'PeerCast'
gDetector = nil

DetectorPackageInfo = {
    name =  "PeerCast",
    proto =  DC.ipproto.tcp,
    server = {
        init =  'DetectorInit',
        validate =  'DetectorValidator',
    }
}

gFBsaw_give = nil
gFBsaw_binary = nil
gFBsaw_download = nil

gSfAppIdPeerCast = 782

gPatterns = {
    uploadResponse = { "GET\032\047channel\047", 0, gSfAppIdPeerCast},
    downloadResponse = {"HTTP/1.", 0, gSfAppIdPeerCast}, 
    binaryHeader = { "pcp\010", 0, gSfAppIdPeerCast},

    binaryFollowup = { "oleh", 0, gSfAppIdPeerCast},
    uploadFollowup1 = {"x-peercast-pos", 0, gSfAppIdPeerCast},
    uploadFollowup2 = {"x-peercast-pcp", 0, gSfAppIdPeerCast},
    httpFollowup = {"\013\010Content-Type: application/x-peercast-pcp\013\010\013\010",0, gSfAppIdPeerCast},
}

gFastPatterns = {
    {DC.ipproto.tcp, gPatterns.uploadResponse},
    {DC.ipproto.tcp, gPatterns.binaryHeader},
}

gPorts = {
	{DC.ipproto.tcp, 7144},
}


gAppRegistry = {
	--AppIdValue          Extracts Info
	---------------------------------------
	{gSfAppIdPeerCast,		         0}
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
        gDetector:addService(gServiceId, "", "", gSfAppIdPeerCast)
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

	if (size == 0) then
		return serviceInProcess(context)
	end
	
	--3 potential cases. Expect either an Upload, binary, or download message

	--BINARY REQUEST CASE (requires a specific client packet first)
	if (dir == 0) then
		if ((size == 4) and
			(gDetector:memcmp(gPatterns.binaryHeader[1], #gPatterns.binaryHeader[1], gPatterns.binaryHeader[2]) == 0) and
			(not gFBsaw_binary))
		then
			gFBsaw_binary = true
		end
		return serviceInProcess(context)
	end

	--UPLOAD RESPONSE AND DOWNLOAD RESPONSE CASES
	if (dir == 1) then
		if ((size >= #gPatterns.uploadResponse[1]) and
        	(gDetector:memcmp(gPatterns.uploadResponse[1], #gPatterns.uploadResponse[1], gPatterns.uploadResponse[2]) == 0) and
        	(not gFBsaw_give))
		then
			gFBsaw_give = true
			return serviceInProcess(context)
		elseif ((gDetector:memcmp(gPatterns.downloadResponse[1], #gPatterns.downloadResponse[1], gPatterns.downloadResponse[2]) == 0) and
				(not gFBsaw_download))
		then
			gFBsaw_download = true
			return serviceInProcess(context)
		end
	end

	--If we find one of the potential messages, use handleCases to make sure
	if (gFBsaw_give or gFBsaw_binary or gFBsaw_download) then
		return handleCases(dir, context, size)
	end

    return serviceFail(context)
end

function handleCases(dir, context, size)
	if ((gFBsaw_give) and
		(gDetector:getPcreGroups(gPatterns.uploadFollowup1[1])) and
		(gDetector:getPcreGroups(gPatterns.uploadFollowup2[1])))
	then
		gFBsaw_give = false
		return serviceSuccess(context)
	end

	if ((gFBsaw_download) and
		(gDetector:getPcreGroups(gPatterns.httpFollowup[1])))
	then
		gFBsaw_download = false
		return serviceSuccess(context)
	end

	if ((gFBsaw_binary) and
		(size == 4) and
		(gDetector:memcmp(gPatterns.binaryFollowup[1], #gPatterns.binaryFollowup[1], gPatterns.binaryFollowup[2]) == 0))
	then
		gFBsaw_binary = false
		return serviceSuccess(context)
	end

	return serviceFail(context)
end

--[[Required DetectorFini function
--]]
function DetectorFini()
    --print (gServiceName .. ': DetectorFini()')
end

