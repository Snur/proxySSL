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
detection_name: Network PID Checker
description: Network anti-piracy mechanism for MS Office product.
--]]

require "DetectorCommon"



local DC = DetectorCommon
local FT = flowTrackerModule

gDetector = nil

DetectorPackageInfo = {
    name =  "Network PID Checker",
    proto =  DC.ipproto.udp, 
    client = {
        init =  'client_init',
        clean = 'client_clean',
		validate =  'client_validate',
		minimum_matches = 1
    }
}

gSfAppIdNetworkPIDChecker = 2759
gSfServiceAppIdNetworkPIDChecker = 20169

gPatterns = {
    udpPattern = {"MSOPID", 0, gSfAppIdNetworkPIDChecker},
}

gFastPatterns = {
    {DC.ipproto.udp, gPatterns.udpPattern},
}


gAppRegistry = {
	{gSfAppIdNetworkPIDChecker, 0},
}

flowTrackerTable = {}

function clientInProcess(context)
	DC.printf('%s: Inprocess Client, packetCount: %d\n', DetectorPackageInfo.name, context.packetCount)
	return DC.clientStatus.inProcess
end

function clientSuccess(context)
    context.detectorFlow:setFlowFlag(DC.flowFlags.clientAppDetected)
    DC.printf('%s: Detected Client, serviceId %d appId %d packetCount: %d\n', DetectorPackageInfo.name, gSfServiceAppIdNetworkPIDChecker , gSfAppIdNetworkPIDChecker , context.packetCount)
    gDetector:client_addApp(gSfServiceAppIdNetworkPIDChecker , appTypeId, NetworkPIDCheckerProductId , "", gSfAppIdNetworkPIDChecker )
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

    NetworkPIDCheckerProductId = 430
     

	DC.printf ('%s:DetectorInit(): appTypeId %d, product %d\n', DetectorPackageInfo.name, appTypeId, NetworkPIDCheckerProductId )


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

    DC.printf ('Network PID Checker packetCount %d dir %d, size %d dstPort %d \n', context.packetCount, dir, size, dstPort )

-- UDP data processing
	DC.printf ('Inside the UDP block\n')

    if ((gDetector:memcmp(gPatterns.udpPattern[1], #gPatterns.udpPattern[1], gPatterns.udpPattern[2]) == 0) and size >=6 ) then

        DC.printf("Network PID Checker matched \n")
        return clientSuccess(context)
    end


    return clientFail(context)
end

function client_clean()
end

