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
detection_name: Battle.net
version: 1
description: Game networking service.
--]]

require "DetectorCommon"



local DC = DetectorCommon
local FT = flowTrackerModule

gServiceId = 20101
gServiceName = 'Battle.net'
gDetector = nil

DetectorPackageInfo = {
    name =  "Battle.net",
    proto =  DC.ipproto.tcp,
    server = {
        init =  'DetectorInit',
        validate =  'DetectorValidator',
    }
}

gSfAppIdBattlenet = 564
gPatterns = {
	connect = {'\255\080\058\000\000\000\000\000', 0, gSfAppIdBattlenet},
	mpq = {"lockdown", 24, gSfAppIdBattlenet},
	smk = {"smk\000", 13, gSfAppIdBattlenet},

}

gFastPatterns = {
	{DC.ipproto.tcp, gPatterns.connect},
	{DC.ipproto.tcp, gPatterns.mpq},
	{DC.ipproto.tcp, gPatterns.smk},
}

gPorts = {
	{DC.ipproto.tcp, 6112},
	{DC.ipproto.tcp, 6113},
	{DC.ipproto.tcp, 6114},
	{DC.ipproto.tcp, 6115},
	{DC.ipproto.tcp, 6116},
	{DC.ipproto.tcp, 6117},
	{DC.ipproto.tcp, 6118},
	{DC.ipproto.tcp, 6119},
}


gAppRegistry = {
	--AppIdValue          Extracts Info
	---------------------------------------
	{gSfAppIdBattlenet,		         0}
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
        gDetector:addService(gServiceId, "", "", gSfAppIdBattlenet)
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

	if (dir == 0) then
		if (gDetector:memcmp(gPatterns.connect[1], #gPatterns.connect[1], gPatterns.connect[2]) == 0) then
			matched, platform = gDetector:getPcreGroups("\255\080\058.....(....)", 0)
			if (matched and (platform == "68XI" or platform == "CAMP" or platform == "CAMX")) then
				DC.printf("login\n")
				return serviceSuccess(context)
			end
		else
			return serviceInProcess(context)
		end
	end

	if (dir == 1) then
		if (gDetector:memcmp(gPatterns.mpq[1], #gPatterns.mpq[1], gPatterns.mpq[2]) == 0) then
			mpqMatched, platform2 = gDetector:getPcreGroups("lockdown-(....)-")
			if (mpqMatched and (platform2 == "IX86" or platform2 == "PMAC" or platform2 == "XMAC")) then
				DC.printf("mpq\n")
				return serviceSuccess(context)
			end
		elseif ((gDetector:memcmp(gPatterns.smk[1], #gPatterns.smk[1], gPatterns.smk[2]) == 0) and
				(size >= 11) and
				(gDetector:getPcreGroups('[-%]', 0)))
		then
			DC.printf("smk\n")
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

