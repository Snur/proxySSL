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
detection_name: OPC-UA
version: 3
description: Cross platform framework standards for accessing the real and historical data.
--]]

require "DetectorCommon"


local DC = DetectorCommon
local FT = flowTrackerModule

DetectorPackageInfo = {
    name =  "OPCUA",
    proto =  DC.ipproto.tcp,
    server = {
        init =  'DetectorInit',
        validate =  'DetectorValidator',
    }
}
gServiceId = 20151
gServiceName = 'OPC-UA'
gSfAppId = 2042

--patterns used in DetectorInit()
--
gPatterns = {       
    pattern1         = {"HELF", 0, gSfAppId},
    pattern2         = {"ACKF", 0, gSfAppId},
    pattern3         = {"OPNF", 0, gSfAppId},
}

--fast pattern registerd with core engine - needed when not using CSD tables
gFastPatterns = {
    --protocol       patternName
    ------------------------------------
    {DC.ipproto.tcp, gPatterns.pattern1},
    {DC.ipproto.tcp, gPatterns.pattern2},
    {DC.ipproto.tcp, gPatterns.pattern3},
}


gAppRegistry = {
	--AppIdValue          Extracts Info
	---------------------------------------
	{gSfAppId,		         0}
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
        gDetector:addService(gServiceId, "", "", gSfAppId)
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

    
    --register pattern based detection
    for i,v in ipairs(gFastPatterns) do
        if ( gDetector:registerPattern(v[1], v[2][1], #v[2][1], v[2][2], v[2][3]) ~= 0) then
	    DC.printf('%s: Failed to register the pattern\n', gServiceName )
        else
	    DC.printf('%s: Successful in registering the pattern\n', gServiceName)
        end
    end

	for i,v in ipairs(gAppRegistry) do
		pcall(function () gDetector:registerAppId(v[1],v[2]) end)
	end

end

--[[ Core engine calls DetectorInit() to initialize a detector.
--]]
function DetectorInit( detectorInstance)

    DC.printf (gServiceName .. ': DetectorInit()\n')

    gDetector = detectorInstance
    gDetector:init(gServiceName, 'DetectorValidator', 'DetectorFini')
    registerPortsPatterns()

    return gDetector
end


function DetectorValidator()
    local context = {}
    context.packetDir = gDetector:getPacketDir()
    context.packetCount = gDetector:getPktCount()
    context.packetDataLen = gDetector:getPacketSize()
    context.detectorFlow = gDetector:getFlow()
    context.srcIp = gDetector:getPktSrcAddr()
    context.dstIp = gDetector:getPktDstAddr()
    context.srcPort = gDetector:getPktSrcPort()
    context.dstPort = gDetector:getPktDstPort()
    context.flowKey = context.detectorFlow:getFlowKey()
    local dir = context.packetDir
    local size = context.packetDataLen
    local srcPort = context.srcPort
    local dstPort = context.dstPort
    local flowFlag = context.detectorFlow:getFlowFlag(DC.flowFlags.serviceDetected)
    local flowKey = context.flowKey
    local headBanner= "/UA/" 


--if (size == 0 ) then
  --    	return serviceInProcess(context)
    --nd
    DC.printf ('%s: DetectorValidator(): packetCount %d, dir %d, size %d and Flowflag is:%x\n', gServiceName, 
               context.packetCount, dir, size, flowFlag)

	local rft = FT.getFlowTracker(flowKey)
	if (not rft) then
	        rft = FT.addFlowTracker(flowKey, {servicecount=0, serviceSequenceID = 0, clientPktMatch=0})
	end

	if ((rft.servicecount == 0) and
               (size == 61) and
               (dir == 0) and
              (gDetector:memcmp(gPatterns.pattern1[1], #gPatterns.pattern1[1], gPatterns.pattern1[2]) == 0))  
          then
		   DC.printf ('%s: DetectorValidator(): Inside the 1st match \n', gServiceName) 
                   clientPktMatch = 1
                  return serviceInProcess(context)
          end

        if (    ( rft.servicecount == 0) and
		(size == 28) and
                (dir == 1) and
                (gDetector:memcmp(gPatterns.pattern2[1], #gPatterns.pattern2[1], gPatterns.pattern2[2]) == 0))
        then
    		DC.printf ('%s: DetectorValidator(): Inside the 2nd match \n', gServiceName) 
                rft.servicecount = 1
                return serviceInProcess(context)
        end

        if (    ( rft.servicecount == 1) and
		(size == 132) and
                (dir == 0) and
                (gDetector:memcmp(gPatterns.pattern3[1], #gPatterns.pattern3[1], gPatterns.pattern3[2]) == 0) and
		(gDetector:memcmp(headBanner ,#headBanner, 40 ) == 0))
        then
    		DC.printf ('%s: DetectorValidator(): Inside the 3rd match  and successful\n', gServiceName) 
            	FT.delFlowTracker(flowKey)
                return serviceSuccess(context)
        end

        return serviceFail(context)

end

function DetectorFini()
end
