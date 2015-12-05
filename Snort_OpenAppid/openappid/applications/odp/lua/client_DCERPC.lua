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
detection_name: DCE/RPC
description: Distributed Computing Environment / Remote Procedure Calls is the remote procedure call system for the Distributed Computing Environment.
--]]

require "DetectorCommon"



local DC = DetectorCommon
local FT = flowTrackerModule

DetectorPackageInfo = {
    name =  "DCERPC",
    proto =  DC.ipproto.tcp,
    client = {
        init =  'client_init',
        clean =  'client_clean',
        validate =  'client_validate',
        minimum_matches =  1
    }
}

gSfAppIdDceRpc = 603

gPatterns = {
    bind = { '\005\000\011\003\016\000\000\000', 0, gSfAppIdDceRpc},
}

gFastPatterns = {
    {DC.ipproto.tcp, gPatterns.bind},
}

gAppRegistry = {
	--AppIdValue          Extracts Info
	---------------------------------------
	{gSfAppIdDceRpc,		         0}
}

--contains detector specific data related to a flow 
flowTrackerTable = {}

function clientInProcess(context)

    DC.printf('%s: Inprocess Client, packetCount: %d\n', DetectorPackageInfo.name, context.packetCount)
    return DC.clientStatus.inProcess
end

function clientSuccess(context)
    context.detectorFlow:setFlowFlag(DC.flowFlags.clientAppDetected)
    DC.printf('%s: Detected Client, packetCount: %d\n', DetectorPackageInfo.name, context.packetCount)
    gDetector:client_addApp(context.serviceid, context.typeid, context.appid, "", gSfAppIdDceRpc);
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
    DC.printf ('%s:DetectorInit()\n', DetectorPackageInfo.name)
    gDetector:client_init()

    arcserve_id = 70
    mapi_id = 89
    
    arcserve_type_id = 21
    mapi_type_id = 2

    arcserve_service_id = 20069
    mapi_service_id = 20081

    DC.printf ('%s:DetectorValidator(): appTypeId %d, product %d, service %d\n', DetectorPackageInfo.name, mapi_type_id, mapi_id, mapi_service_id)

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
    context.packetSize = gDetector:getPacketSize()
    context.packetDir = gDetector:getPacketDir()
    context.flowKey = context.detectorFlow:getFlowKey()
    context.srcPort = gDetector:getPktSrcPort()
    context.dstPort = gDetector:getPktDstPort()
    local size = context.packetSize
    local dir = context.packetDir

    DC.printf ('packetCount %d dir %d, size %d\n', context.packetCount, dir, size)

    if ((dir ~= 0) or
        (size < 10))
    then
        return clientFail(context)
    end

    if ((context.dstPort == 6502) or
        (context.dstPort == 6503) or
        (context.dstPort == 6504)) 
    then
        context.appid = arcserve_id
        context.typeid = arcserve_type_id
        context.serviceid = arcserve_service_id
        DC.printf("looks like ARCServe\n")
    elseif ((context.dstPort == 135) or
            (context.dstPort == 139) or
            (context.dstPort == 445)) 
    then
        context.appid = mapi_id
        context.typeid = mapi_type_id
        context.serviceid = mapi_service_id
        DC.printf("looks like MAPI\n")
    else
        return clientFail(context)
    end


    if (gDetector:memcmp(gPatterns.bind[1], #gPatterns.bind[1], gPatterns.bind[2]) == 0) 
    then
        matched, len_raw = gDetector:getPcreGroups('(..)', 8)
            if (matched) then
                len = DC.reverseBinaryStringToNumber(len_raw, 2)
                DC.printf(' size %d, len %d\n', size, len)
                if (len == size) then
                    return clientSuccess(context)
                else
                    return clientFail(context)
                end
            end
    end

    return clientFail(context)

end

function client_clean()
end
