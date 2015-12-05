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
detection_name: VMware Server Console
description: Management console for Cloud computing from VMWare.
--]]

require "DetectorCommon"



local DC = DetectorCommon
local FT = flowTrackerModule

gDetector = nil

DetectorPackageInfo = {
    name =  "VMware Server Console",
    proto =  DC.ipproto.tcp, 
    client = {
        init =  'client_init',
        clean = 'client_clean',
		validate =  'client_validate',
		minimum_matches = 1
    }
}

gSfAppIdVMWareVNCClient = 2709
gSfServiceAppIdVMWareVNCClient = 20161

gPatterns = {
    tcpPattern = {"\022\003\001\000\049\001\000\000\045\003\001\082", 0, gSfAppIdVMWareVNCClient},
}

gFastPatterns = {
    {DC.ipproto.tcp, gPatterns.tcpPattern},
}

gPorts = {
    {DC.ipproto.tcp, 902},
}

gAppRegistry = {
	{gSfAppIdVMWareVNCClient, 0},
}

flowTrackerTable = {}

function clientInProcess(context)
	DC.printf('%s: Inprocess Client, packetCount: %d\n', DetectorPackageInfo.name, context.packetCount)
	return DC.clientStatus.inProcess
end

function clientSuccess(context)
    context.detectorFlow:setFlowFlag(DC.flowFlags.clientAppDetected)
    DC.printf('%s: Detected Client, serviceId %d appId %d packetCount: %d\n', DetectorPackageInfo.name, gSfServiceAppIdVMWareVNCClient , gSfAppIdVMWareVNCClient , context.packetCount)
    gDetector:client_addApp(gSfServiceAppIdVMWareVNCClient , appTypeId, VMWareVNCClientProductId , "", gSfAppIdVMWareVNCClient )
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

	appTypeId = 8

    VMWareVNCClientProductId = 412
     

	DC.printf ('%s:DetectorInit(): appTypeId %d, product %d\n', DetectorPackageInfo.name, appTypeId, VMWareVNCClientProductId )

 --register port based detection
--    for i,v in ipairs(gPorts) do
 --       gDetector:addPort(v[1], v[2])
  --  end
	DC.printf ('%s:DetectorInit(): After port registring\n', DetectorPackageInfo.name )

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

 -- VSphere Console tcp pattern
    gDetector:addHttpPattern(2, 5, 0, 412, 1, 0, 0, 'VMware VI Client/', 2709);

	DC.printf ('%s:DetectorInit(): End of the VSphere Console\n', DetectorPackageInfo.name )

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
--    context.protocol = gDetector:getProtocolType()
    local size = context.packetDataLen
    local dir = context.packetDir
    local srcPort = context.srcPort
    local dstPort = context.dstPort
    local flowKey = context.flowKey

    DC.printf ('VSphere Console packetCount %d dir %d, size %d dstPort %d \n', context.packetCount, dir, size, dstPort )
	if (size == 0) then
    	return clientInProcess(context)
	end

-- TCP data processing
  --  if (context.protocol== 17) then
    	DC.printf ('Inside the TCP block\n')

	    if (( dstPort == 902) and (gDetector:memcmp(gPatterns.tcpPattern[1], #gPatterns.tcpPattern[1], gPatterns.tcpPattern[2]) == 0)) then

		   if (size == 54) then
			DC.printf("VSphere Console matched \n")
			return clientSuccess(context)
		    end
	    end
    --end


    return clientFail(context)
end

function client_clean()
end

