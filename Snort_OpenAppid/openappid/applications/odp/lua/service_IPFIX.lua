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
detection_name: IPFIX
version: 3
description: IP Flow Information Export.
--]]

require "DetectorCommon"


local DC = DetectorCommon
local FT = flowTrackerModule

DetectorPackageInfo = {
    name =  "IPFIX",
    proto =  DC.ipproto.tcp,
    server = {
        init =  'DetectorInit',
        validate =  'DetectorValidator',
    }
}

gServiceId = 20147
gServiceName = 'IPFIX'
gSfAppId = 1800

--patterns used in DetectorInit()
gPatterns = {       
    pattern          = {'\000\010', 0, gSfAppId},
}

--fast pattern registerd with core engine - needed when not using CSD tables
gFastPatterns = {
    --protocol       patternName
    ------------------------------------
    {DC.ipproto.udp, gPatterns.pattern},
}

--gPorts = {
 --   {DC.ipproto.udp, 19000}
--}

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

function getStringPlain (data, length)
    local stringValue=""
    local index=0
    while (index <  length) do
        stringValue = string.format('%s%.2x', stringValue, string.byte(data,index+1))
        index = index + 1
    end
    return stringValue
end


function convertDectoHex(nValue)
	nHexVal = string.format("%04x", nValue)  -- %X returns uppercase hex, %x gives lowercase letters
	sHexVal =  nHexVal.."";
	return sHexVal
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
    local headBanner=gPatterns.pattern[1]
    --local dataLength=tostring(context.packetDataLen)
    local dataLength=gPatterns.pattern[1]
    local flowFlag = context.detectorFlow:getFlowFlag(DC.flowFlags.serviceDetected)
    local flowKey = context.flowKey


--if (size == 0 ) then
  --    	return serviceInProcess(context)
    --nd
    DC.printf ('%s: DetectorValidator(): packetCount %d, dir %d, size %d and Flowflag is:%x\n', gServiceName, 
               context.packetCount, dir, size, flowFlag)

	local rft = FT.getFlowTracker(flowKey)
	if (not rft) then
	        rft = FT.addFlowTracker(flowKey, {servicecount=0, serviceSequenceID = 0, serviceObservationID=0})
	end

	matched, msg_length, msg_sequence, msg_observationId = gDetector:getPcreGroups('..(..)....(....)(....)', 0)
 	if matched then
	        msg_length_str = getStringPlain(msg_length , 2)
                pkt_length_str = convertDectoHex(size)

	        msg_sequence_str = getStringPlain(msg_sequence, 4)
        	msg_observationId_str = getStringPlain(msg_observationId , 4)

  		if msg_length_str == pkt_length_str then
			if((rft.serviceSequenceID==0)) then
				rft.serviceSequenceID = msg_sequence
				rft.serviceObservationID = msg_observationId
				rft.servicecount=rft.servicecount+1
				return serviceInProcess(context)

			elseif((( msg_sequence>rft.serviceSequenceID) or msg_sequence_str== '00000000') and (rft.serviceObservationID == msg_observationId) ) then
				if ( rft.servicecount<3) then
					rft.serviceSequenceID = msg_sequence
					rft.servicecount=rft.servicecount+1
					return serviceInProcess(context)

				elseif(rft.servicecount==3) then				
					DC.printf('%s: Matched successfully\n', gServiceName)                
					 FT.delFlowTracker(flowKey)
				   	return serviceSuccess(context)
				end
			else
				DC.printf('Packet doesnot match the sequence number \n')                
	        	end
		else
			DC.printf('Length of packet and data value did not matched \n')                
		end 
	else
		DC.printf('No match found in PCREGroups\n')                
	end	


	FT.delFlowTracker(flowKey)
	return serviceFail(context)
end

function DetectorFini()
end
