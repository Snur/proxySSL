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
detection_name: HL7
description: Health Level 7, a protocol for the electronic exchange of healthcare information.
bundle_description: $VAR1 = {
          'Epic' => 'Software that uses the Health Level 7 protocol.',
          'Medipac' => 'Hospital software for Admissions, Discharges, and Transfers.',
          'IDXRad' => 'Radiology imagery transmission system.',
          'PScribe' => 'Medical transcription management and transmission software.',
          'HL7' => 'Health Level 7, a protocol for the electronic exchange of healthcare information.',
          'UPMC' => 'Software that uses the Health Level 7 protocol.',
          'Sunquest' => 'Laboratory and diagnostic medical information software.'
        };

--]]

require "DetectorCommon"



local DC = DetectorCommon
local FT = flowTrackerModule

gDetector = nil

DetectorPackageInfo = {
    name =  "HL7",
    proto =  DC.ipproto.tcp, 
    client = {
        init =  'client_init',
        clean = 'client_clean',
		validate =  'client_validate',
		minimum_matches = 1
    }
}

gSfAppIdHL7Client = 201
gSfAppIdIdxrad = 2087
gSfAppIdPscribe = 2088
gSfAppIdSunquest = 2089
gSfAppIdMedipac = 2090
gSfAppIdEpic = 2096
gSfAppIdUpmc = 2097

gPatterns = {
    HL7_header = {'MSH', 1, gSfAppIdHL7Client},
    idxrad = {'IDXRAD', 10, gSfAppIdIdxrad},
    pscribe = {'PSCRIBE', 10, gSfAppIdPscribe},
    sunquest = {'SUNQUEST', 10, gSfAppIdSunquest},
    medipac = {'MEDIPAC', 10, gSfAppIdMedipac},
    epic = {'EPIC', 10, gSfAppIdEpic},
    upmc = {'UPMC_MR', 10, gSfAppIdUpmc},
}


gFastPatterns = {
	{DC.ipproto.tcp, gPatterns.HL7_header},
}


gAppRegistry = {
	{gSfAppIdHL7Client, 0},
    {gSfAppIdIdxrad, 0},
    {gSfAppIdPscribe, 0},
    {gSfAppIdSunquest, 0},
    {gSfAppIdMedipac, 0},
    {gSfAppIdEpic, 0},
    {gSfAppIdUpmc, 0},
}

flowTrackerTable = {}

function clientInProcess(context)
	DC.printf('%s: Inprocess Client, packetCount: %d\n', DetectorPackageInfo.name, context.packetCount)
	return DC.clientStatus.inProcess
end

function clientSuccess(context)
    context.detectorFlow:setFlowFlag(DC.flowFlags.clientAppDetected)
    DC.printf('%s: Detected Client, packetCount: %d\n', DetectorPackageInfo.name, context.packetCount)
    gDetector:client_addApp(appServiceIdHL7, appTypeId, context.productId, "", context.appId)
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

	appTypeId = 23
	appServiceIdHL7 = 20153

	appProductIdHL7 = 262
    appProductIdIdxrad = 265
    appProductIdPscribe = 266
    appProductIdSunquest = 267
    appProductIdMedipac = 268
    appProductIdEpic = 272
    appProductIdUpmc = 273

	DC.printf ('%s:DetectorValidator(): appTypeId %d, product %d, service %d\n', DetectorPackageInfo.name, appTypeId, appProductIdHL7, appServiceIdHL7)

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
    local size = context.packetDataLen
    local dir = context.packetDir
    local srcPort = context.srcPort
    local dstPort = context.dstPort
    local flowKey = context.flowKey

	if (size == 0) then
    	return clientInProcess(context)
	end

    DC.printf ('HL7 client packetCount %d dir %d, size %d\n', context.packetCount, dir, size)

	if (dir == 0 and size > 10) then
        if (gDetector:memcmp(gPatterns.idxrad[1], #gPatterns.idxrad[1], gPatterns.idxrad[2]) == 0) then
            context.appId = gSfAppIdIdxrad
            context.productId = appProductIdIdxrad
        elseif (gDetector:memcmp(gPatterns.pscribe[1], #gPatterns.pscribe[1], gPatterns.pscribe[2]) == 0) then
            context.appId = gSfAppIdPscribe
            context.productId = appProductIdPscribe
        elseif (gDetector:memcmp(gPatterns.sunquest[1], #gPatterns.sunquest[1], gPatterns.sunquest[2]) == 0) then
            context.appId = gSfAppIdSunquest
            context.productId = appProductIdSunquest
        elseif (gDetector:memcmp(gPatterns.medipac[1], #gPatterns.medipac[1], gPatterns.medipac[2]) == 0) then
            context.appId = gSfAppIdMedipac
            context.productId = appProductIdMedipac
        elseif (gDetector:memcmp(gPatterns.epic[1], #gPatterns.epic[1], gPatterns.epic[2]) == 0) then
            context.appId = gSfAppIdEpic
            context.productId = appProductIdEpic
        elseif (gDetector:memcmp(gPatterns.upmc[1], #gPatterns.upmc[1], gPatterns.upmc[2]) == 0) then
            context.appId = gSfAppIdUpmc
            context.productId = appProductIdUpmc
        else
            context.appId = gSfAppIdHL7Client
            context.productId = appProductIdHL7
        end

        return clientSuccess(context)
    end

    return clientFail(context)
end

function client_clean()
end

