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
detection_name: AMMYY
version: 2
description: Remote access software.
--]]

require "DetectorCommon"



local DC = DetectorCommon
local FT = flowTrackerModule

gServiceId = 20181
gServiceName = 'AMMYY'
gDetector = nil

DetectorPackageInfo = {
    name =  "AMMYY",
    proto =  DC.ipproto.tcp,
    server = {
        init =  'DetectorInit',
        validate =  'DetectorValidator',
    }
}


gSfAppIdParallels = 2894
gUrlPatternList = {

    -- AMMYY
    { 0, 0, 0, 1351, 22, "ammyy.com", "/", "http:", "", 2894},
}

--gPatterns = {
--	header = {"\061", 0, gSfAppIdParallels},
--}

--gFastPatterns = {
--	{DC.ipproto.tcp, gPatterns.header}
--}

gPorts = {
	{DC.ipproto.tcp, 5931},
}


gAppRegistry = {
	--AppIdValue          Extracts Info
	---------------------------------------
	{gSfAppIdParallels,		         0}
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
        gDetector:addService(gServiceId, "", "", gSfAppIdParallels)
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
--    for i,v in ipairs(gFastPatterns) do
 --       if ( gDetector:registerPattern(v[1], v[2][1], #v[2][1], v[2][2], v[2][3]) ~= 0) then
  --          DC.printf ('%s: register pattern failed for %s\n', gServiceName,v[2][1])
   --     else
    --        DC.printf ('%s: register pattern successful for %s\n', gServiceName,v[2][1])
     --   end
    --end

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
    if gDetector.addAppUrl then
        for i,v in ipairs(gUrlPatternList) do
            gDetector:addAppUrl(v[1],v[2],v[3],v[4],v[5],v[6],v[7],v[8],v[9],v[10]);
        end
    end


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


  
	if (size == 0) then
        return serviceInProcess(context)
    end
    local rft = FT.getFlowTracker(flowKey)
    if (not rft) then
            rft = FT.addFlowTracker(flowKey, {clientPkt=0, servicePkt = 0 })
    end
    DC.printf ('%s:DetectorValidator(): packetCount %d, dir %d, size %d, dstport %d, clientPkt %d \n', gServiceName, context.packetCount, dir, size, dstPort, rft.clientPkt);

	if ((size == 37) and
	    (dstPort == 5931 ) and
		(gDetector:memcmp("\061", 1, 0) ) and
        rft.clientPkt == 0  and 
        dir ==0 )
	then
        rft.clientPkt = 1
        return serviceInProcess(context)
	elseif ((size == 36) and
	    (srcPort == 5931 ) and
		(gDetector:memcmp("\061", 1, 0) ) and 
        rft.clientPkt == 1 and
        dir == 1)
	then
        rft.servicePkt = 1
        return serviceInProcess(context)
	elseif( (srcPort == 5931 ) and
		(gDetector:memcmp("\061", 1, 0) ) and 
        rft.servicePkt == 1 and 
        dir ==1)
	then
        return serviceSuccess(context)
	end

    return serviceFail(context)
end

--[[Required DetectorFini function
--]]
function DetectorFini()
    --print (gServiceName .. ': DetectorFini()')
end

