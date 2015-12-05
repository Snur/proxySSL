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
detection_name: WinMX
version: 1
description: P2P file sharing program.
--]]

require "DetectorCommon"



local DC = DetectorCommon
local FT = flowTrackerModule

gServiceId = 20099
gServiceName = 'WinMX'
gDetector = nil

DetectorPackageInfo = {
    name =  "WinMX",
    proto =  DC.ipproto.tcp,
    server = {
        init =  'DetectorInit',
        validate =  'DetectorValidator',
    }
}

--global variables for event flags
gFBwinmx_cts_keys_sent = nil
gFBwinmx_first_packet = nil

gSfAppIdWinMx = 913

gPatterns = {
	identifier = { "1", 0, gSfAppIdWinMx},
	sendPattern = { "SEND", 0, gSfAppIdWinMx},
	getPattern = { "GET", 0, gSfAppIdWinMx},
}

gFastPatterns = {
}

gPorts = {
	{DC.ipproto.tcp, 6699},
}


gAppRegistry = {
	--AppIdValue          Extracts Info
	---------------------------------------
	{gSfAppIdWinMx,		         0}
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
        gDetector:addService(gServiceId, "", "", gSfAppIdWinMx)
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

	--service always sends a 1 byte "1" first. From there, client can either send a 'get' or 'send' message, or client and service can send each other
	--16 byte messages for encryption
	if (dir == 1) then
		if ((size == 1) and
			(not sawIdentifier) and
			(gDetector:memcmp(gPatterns.identifier[1], #gPatterns.identifier[1], gPatterns.identifier[2]) == 0)) 
		then
			sawIdentifier = true
			return serviceInProcess(context)
		elseif (sawFirstEncryption and size == 16) then
			sawIdentifier = false
			sawFirstEncryption = false	
			return serviceSuccess(context)
		end
	end 

	if (dir == 0) then
		if (sawIdentifier) then
			if (((size == 3) and
				 (gDetector:memcmp(gPatterns.getPattern[1], #gPatterns.getPattern[1], gPatterns.getPattern[2]) == 0)) or
				((size == 4) and
				 (gDetector:memcmp(gPatterns.sendPattern[1], #gPatterns.sendPattern[1], gPatterns.sendPattern[2]) == 0)))
			then
				sawIdentifier = false
				sawFirstEncryption = false
				return serviceSuccess(context)	
			elseif (size == 16) then
				sawFirstEncryption = true
				return serviceInProcess(context)
			else
				sawIdentifier = false
				sawFirstEncryption = false
				return serviceFail(context)
			end
		end
		return serviceInProcess(context) --To handle when client sends first; want to wait for first service packet
	end

	sawIdentifier = false
	sawFirstEncryption = false
    return serviceFail(context)
end

--[[Required DetectorFini function
--]]
function DetectorFini()
    --print (gServiceName .. ': DetectorFini()')
end

