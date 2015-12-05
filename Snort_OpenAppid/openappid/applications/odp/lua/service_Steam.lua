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
detection_name: Steam
version: 1
description: Massive gaming and communications platform.
--]]

require "DetectorCommon"



local DC = DetectorCommon
local FT = flowTrackerModule

gServiceId = 20113
gServiceName = 'Steam'
gDetector = nil

DetectorPackageInfo = {
    name =  "Steam",
    proto =  DC.ipproto.tcp,
    server = {
        init =  'DetectorInit',
        validate =  'DetectorValidator',
    }
}

gSfAppIdSteam = 1086
gPatterns = {
	udpChat = {"VS01", 0, gSfAppIdSteam},
}

gFastPatterns = {
	{DC.ipproto.udp, gPatterns.udpChat},
}

gPorts = {
	{DC.ipproto.udp, 27017},
	{DC.ipproto.tcp, 27014},
	{DC.ipproto.tcp, 27015},
	{DC.ipproto.tcp, 27016},
	{DC.ipproto.tcp, 27017},
	{DC.ipproto.tcp, 27018},
	{DC.ipproto.tcp, 27019},
	{DC.ipproto.tcp, 27020},
	{DC.ipproto.tcp, 27021},
	{DC.ipproto.tcp, 27022},
	{DC.ipproto.tcp, 27023},
	{DC.ipproto.tcp, 27024},
	{DC.ipproto.tcp, 27025},
	{DC.ipproto.tcp, 27026},
	{DC.ipproto.tcp, 27027},
	{DC.ipproto.tcp, 27028},
	{DC.ipproto.tcp, 27029},
	{DC.ipproto.tcp, 27030},
	{DC.ipproto.tcp, 27031},
	{DC.ipproto.tcp, 27032},
	{DC.ipproto.tcp, 27033},
	{DC.ipproto.tcp, 27034},
	{DC.ipproto.tcp, 27035},
	{DC.ipproto.tcp, 27036},
	{DC.ipproto.tcp, 27037},
	{DC.ipproto.tcp, 27038},
	{DC.ipproto.tcp, 27039},
	{DC.ipproto.tcp, 27040},
	{DC.ipproto.tcp, 27041},
	{DC.ipproto.tcp, 27042},
	{DC.ipproto.tcp, 27043},
	{DC.ipproto.tcp, 27044},
	{DC.ipproto.tcp, 27045},
	{DC.ipproto.tcp, 27046},
	{DC.ipproto.tcp, 27047},
	{DC.ipproto.tcp, 27048},
	{DC.ipproto.tcp, 27049},
	{DC.ipproto.tcp, 27050},
}


gAppRegistry = {
	--AppIdValue          Extracts Info
	---------------------------------------
	{gSfAppIdSteam,		         1}
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
        gDetector:addService(gServiceId, "Valve Corporation", "", gSfAppIdSteam)
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

	--UDP messages 
	if ((gDetector:memcmp(gPatterns.udpChat[1], #gPatterns.udpChat[1], gPatterns.udpChat[2]) == 0) and
		(size >= 36)) 
	then
		matched, rawSize = gDetector:getPcreGroups("VS01(..)", 0)
		if (matched) then
			guessSize = DC.reverseBinaryStringToNumber(rawSize, 2)
			if (guessSize + 36 == size) then
				return serviceSuccess(context)
			end
		end
	end	

	
	--steam TCP messages
	--from service
	if (dir == 1) then
		if ((sawTCP1) and
			(size == 1))
		then
			sawTCP1 = false
			return serviceSuccess(context)
		elseif ((sawTCP2) and
			(size == 5)) 
		then
			sawTCP2 = false
			return serviceSuccess(context)
		end
	end

	--from client
	if ((size == 4) and
		(dir == 0) and
		(gDetector:memcmp("\000\000\000", 3, 0) == 0))
	then
		matched, mType =  gDetector:getPcreGroups("(.)", 3)
		if (mType == "\002" or mType == "\007") then
			sawTCP1 = true
			return serviceInProcess(context)
		elseif (mType == "\003") then
			sawTCP2 = true
			return serviceInProcess(context)
		end
	end

    return serviceFail(context)
end

--[[Required DetectorFini function
--]]
function DetectorFini()
    --print (gServiceName .. ': DetectorFini()')
end

