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
version: 1
description: Chinese P2P program.
--]]

require "DetectorCommon"



local DC = DetectorCommon
local FT = flowTrackerModule

gServiceId = 20104
gServiceName = 'Xunlei'
gDetector = nil

DetectorPackageInfo = {
    name =  "XunLei",
    proto =  DC.ipproto.tcp,
    server = {
        init =  'DetectorInit',
        validate =  'DetectorValidator',
    }
}

gSfAppIdXunlei = 924

gPatterns = {
	download1 = {"CONNECTRESP", 16, gSfAppIdXunlei},
	download2 = {"GETRESP", 16, gSfAppIdXunlei},
	tcpMessage = {'\000\002\000', 1, gSfAppIdXunlei},
	login1 = {"RESPAES", 69, gSfAppIdXunlei},
	login2 = {"RESPAUTHEN", 69, gSfAppIdXunlei},

	
	tcp1Resp = {"GETCHRESP", 2, gSfAppIdXunlei},
	tcp2Resp = {"SYNCRESP", 2, gSfAppIdXunlei},
	tcp3Resp = {"PRECASTRESP", 2, gSfAppIdXunlei},
	tcp4Resp = {"POPUPRESP", 2, gSfAppIdXunlei}, 
}

gFastPatterns = {
    {DC.ipproto.tcp, gPatterns.download1},
    {DC.ipproto.tcp, gPatterns.download2},
	{DC.ipproto.tcp, gPatterns.tcpMessage},
	{DC.ipproto.tcp, gPatterns.login1},
	{DC.ipproto.tcp, gPatterns.login2},
}

gPorts = {
	{DC.ipproto.tcp, 3076},
	{DC.ipproto.tcp, 3077},
	{DC.ipproto.tcp, 5200},
	{DC.ipproto.tcp, 6200},
}


gAppRegistry = {
	--AppIdValue          Extracts Info
	---------------------------------------
	{gSfAppIdXunlei,		         0}
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
        gDetector:addService(gServiceId, "", "", gSfAppIdXunlei)
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

	--handling signing in
	if ((size >= 70) and
 		((gDetector:memcmp(gPatterns.login1[1], #gPatterns.login1[1], gPatterns.login1[2]) == 0) or
 	 	 (gDetector:memcmp(gPatterns.login2[1], #gPatterns.login2[1], gPatterns.login2[2]) == 0)))
	then
		return serviceSuccess(context)
	end
		 
	
	--handling basic TCP messages	
	if ((sawTCP) and
		(gDetector:memcmp(gPatterns.tcp1Resp[1], #gPatterns.tcp1Resp[1], gPatterns.tcp1Resp[2]) == 0) or
		 (gDetector:memcmp(gPatterns.tcp2Resp[1], #gPatterns.tcp2Resp[1], gPatterns.tcp2Resp[2]) == 0) or
		 (gDetector:memcmp(gPatterns.tcp3Resp[1], #gPatterns.tcp3Resp[1], gPatterns.tcp3Resp[2]) == 0) or
		 (gDetector:memcmp(gPatterns.tcp4Resp[1], #gPatterns.tcp4Resp[1], gPatterns.tcp4Resp[2]) == 0))
	then
		sawTCP = false
		return serviceSuccess(context)
	end

	if ((size == 12) and
		(gDetector:memcmp(gPatterns.tcpMessage[1], #gPatterns.tcpMessage[1], gPatterns.tcpMessage[2]) == 0))
	then
		sawTCP = true
		return serviceInProcess(context)
	end

	--handling downloads
	if ((size >= 4) and
		((gDetector:memcmp(gPatterns.download1[1], #gPatterns.download1[1], gPatterns.download1[2]) == 0) or
 	 	 (gDetector:memcmp(gPatterns.download2[1], #gPatterns.download2[1], gPatterns.download2[2]) == 0)) and
		(gDetector:memcmp(")\000\000\000", 4, 0) == 0))
	then
		return serviceSuccess(context)
	end

	sawTCP = false
    return serviceFail(context)
end

--[[Required DetectorFini function
--]]
function DetectorFini()
    --print (gServiceName .. ': DetectorFini()')
end

