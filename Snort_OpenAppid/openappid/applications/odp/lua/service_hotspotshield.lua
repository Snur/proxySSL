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
detection_name: Hotspot Shield
version: 4
description: Anonymizer and tunnel that encrypts communications.
--]]

require "DetectorCommon"



local DC = DetectorCommon
local FT = flowTrackerModule

gServiceId = 20133
gServiceName = 'hotspotshield'
gDetector = nil

DetectorPackageInfo = {
    name =  "hotspotshield",
    proto =  DC.ipproto.tcp,
    server = {
        init =  'DetectorInit',
        validate =  'DetectorValidator',
		minimum_matches = 2,
    }
}

gSfAppIdHotspotShield = 1140

gPatterns = {
	pat0 = {"\136", 0, gSfAppIdHotspotShield},
	pat1 = {"\000\000\000\000", 9, gSfAppIdHotspotShield},

	pat2 = {"\064", 0, gSfAppIdHotspotShield},
	pat3 = {"\040", 0, gSfAppIdHotspotShield},
}

gFastPatterns = {
}

gPorts = {
    {DC.ipproto.udp, 1194}, 
    {DC.ipproto.udp, 1755}, 
    {DC.ipproto.udp, 1935}, 
    {DC.ipproto.udp, 3211}, 
    {DC.ipproto.udp, 3398}, 
    {DC.ipproto.udp, 5050}, 
    {DC.ipproto.udp, 5231}, 
    {DC.ipproto.udp, 5245}, 
    {DC.ipproto.udp, 5265}, 
    {DC.ipproto.udp, 5345}, 
    {DC.ipproto.udp, 5396}, 
    {DC.ipproto.udp, 8040}, 
    {DC.ipproto.udp, 8041}, 
    {DC.ipproto.udp, 8042}, 
    {DC.ipproto.udp, 8043}, 
    {DC.ipproto.udp, 8044}, 
    {DC.ipproto.udp, 8045}, 
    {DC.ipproto.udp, 8245}, 
    {DC.ipproto.udp, 9000}, 
    {DC.ipproto.udp, 10000}, 
    {DC.ipproto.udp, 10001}, 
    {DC.ipproto.udp, 10002}, 
    {DC.ipproto.udp, 10003}, 
    {DC.ipproto.udp, 10004}, 
    {DC.ipproto.udp, 10005}, 
    {DC.ipproto.udp, 10006}, 
    {DC.ipproto.udp, 10007}, 
    {DC.ipproto.udp, 10008}, 
    {DC.ipproto.udp, 10009}, 
    {DC.ipproto.udp, 10010}, 
    {DC.ipproto.udp, 15000}, 
    {DC.ipproto.udp, 15001}, 
    {DC.ipproto.udp, 15002}, 
    {DC.ipproto.udp, 15003}, 
    {DC.ipproto.udp, 15004}, 
    {DC.ipproto.udp, 15005}, 
    {DC.ipproto.udp, 15006}, 
    {DC.ipproto.udp, 15007}, 
    {DC.ipproto.udp, 15008}, 
    {DC.ipproto.udp, 15009}, 
    {DC.ipproto.udp, 15010}, 
}



gAppRegistry = {
	--AppIdValue          Extracts Info
	---------------------------------------
	{gSfAppIdHotspotShield,		         0}
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
        gDetector:addService(gServiceId, "", "", gSfAppId9p) 
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

    DC.printf ('%s:DetectorValidator(): packetCount %d, dir %d, size %d\n', gServiceName, context.packetCount, dir, size);
  
	if (size == 0) then
        return serviceInProcess(context)
    end

    local rft = FT.getFlowTracker(flowKey)
    if (not rft) then
        rft = FT.addFlowTracker(flowKey, {serviceState=0, serviceDetected = 0})
    end

	--on startup, hotspot shield has a distinguishable pattern of three packets
	if ((rft.serviceState == 0) and
		(size == 14) and
		(dir == 0) and
		(gDetector:memcmp(gPatterns.pat0[1], #gPatterns.pat0[1], gPatterns.pat0[2]) == 0) and
		(gDetector:memcmp(gPatterns.pat1[1], #gPatterns.pat1[1], gPatterns.pat1[2]) == 0))
	then
		rft.serviceState = 1
		return serviceInProcess(context)	
	end

	if ((rft.serviceState == 1) and
		(size == 26) and
		(dir == 1) and
		(gDetector:memcmp(gPatterns.pat2[1], #gPatterns.pat2[1], gPatterns.pat2[2]) == 0))
	then
		rft.serviceState = 2
		return serviceInProcess(context)
	end

	if ((rft.serviceState == 2) and
		(size == 22) and
		(dir == 0) and
		(gDetector:memcmp(gPatterns.pat3[1], #gPatterns.pat3[1], gPatterns.pat3[2]) == 0))
	then
		rft.serviceState = 3
		return serviceInProcess(context)
	end

    if (dir == 1) then
        if (rft.serviceState == 3) then
            FT.delFlowTracker(flowKey)
		    return serviceSuccess(context)
        else
	        return serviceFail(context)
        end

    end
	return serviceInProcess(context)


end

--[[Required DetectorFini function
--]]
function DetectorFini()
    --print (gServiceName .. ': DetectorFini()')
end

