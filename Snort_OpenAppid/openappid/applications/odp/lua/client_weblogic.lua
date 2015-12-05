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
detection_name: WebLogic
version: 1
description: Middleware application linking databases to browser-based thin clients.
--]]

require "DetectorCommon"

--require('debugger')
--local DC = require("DetectorCommon")
local DC = DetectorCommon
local FT = flowTrackerModule

DetectorPackageInfo = {
    name =  "weblogic",
    proto =  DC.ipproto.tcp,
    client = {
        init =  'client_init',
        clean =  'client_clean',
        validate =  'client_validate',
        minimum_matches =  1
    },
    --[[
    server = {
        init =  'smsn_init',
        clean =  'smsn_clean',
        validate =  'smsn_validate',
    },
    --]]
}

gSfAppIdWebLogic = 500
--patterns used in DetectorInit()
gPatterns = {
    --patternName        Pattern         offset
    -------------------------------------------
    pattern               = {'\001\001\000\001\000\000',    0, gSfAppIdWebLogic},
}

--fast pattern registerd with core engine 
gFastPatterns = {
    --protocol       patternName
    ------------------------------------
    {DC.ipproto.tcp, gPatterns.pattern},
}

gAppRegistry = {
	--AppIdValue          Extracts Info
	---------------------------------------
	{gSfAppIdWebLogic,		         0}
}

function clientInProcess(context)

    DC.printf('%s: Inprocess Client, packetCount: %d\n', DetectorPackageInfo.name, context.packetCount);
    return DC.clientStatus.inProcess
end
function clientSuccess(context)

    context.detectorFlow:setFlowFlag(DC.flowFlags.clientAppDetected)
    DC.printf('%s: Detected Client, packetCount: %d\n', DetectorPackageInfo.name, context.packetCount);
    gDetector:client_addApp(service_id, type_id, product_id, "", gSfAppIdWebLogic);
    return DC.clientStatus.success
end

--[[ Core engine calls DetectorInit() to initialize a detector.
--]]
function client_init( detectorInstance, configOptions)


    gDetector = detectorInstance
    DC.printf ('%s:DetectorInit()\n', DetectorPackageInfo.name);
    gDetector:client_init()

    type_id = 10
    product_id = 44
    service_id = 100

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

    DC.printf ('%s:DetectorValidator() Custom: packetCount %d\n', DetectorPackageInfo.name, context.packetCount);

    if (context.packetSize == 0 or context.packetDir ~= DC.flowDirection.fromInitiator) then
        return clientInProcess(context)
    elseif (gDetector:memcmp(gPatterns.pattern[1], #gPatterns.pattern[1], gPatterns.pattern[2]) == 0) then
        return clientSuccess(context) 
    end

    return clientFail(context)

end

function client_clean()
end

