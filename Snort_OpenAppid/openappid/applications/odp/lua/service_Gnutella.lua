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
detection_name: Gnutella
version: 1
description: A large peer-to-peer file-sharing network.
bundle_description: $VAR1 = {
          'Gnutella' => 'A large peer-to-peer file-sharing network.',
          'Gnutella2' => 'A branch of Gnutella, also known as Mike\'s Protocol (MP).'
        };

--]]

require "DetectorCommon"



local DC = DetectorCommon
local FT = flowTrackerModule

gServiceId = 20074
gServiceName = 'Gnutella'
gDetector = nil

DetectorPackageInfo = {
    name =  "Gnutella",
    proto =  DC.ipproto.tcp,
    server = {
        init =  'DetectorInit',
        validate =  'DetectorValidator',
    }
}

gSfAppIdGnutella = 659 
gPatterns = {
    response = { "GNUTELLA/0", 0, gSfAppIdGnutella},
}

gFastPatterns = {
    {DC.ipproto.tcp, gPatterns.response},
}

gPorts = {
    {DC.ipproto.tcp, 3585},
    {DC.ipproto.tcp, 6346},
}


gAppRegistry = {
	--AppIdValue          Extracts Info
	---------------------------------------
	{gSfAppIdGnutella,		         1}
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
        gDetector:addService(context.service, context.vendor, context.version, gSfAppIdGnutella)
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

    gnutellaID = 20030
    gnutella2ID = 20074

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
    context.service = gServiceId
    context.vendor = ""


    DC.printf ('%s:DetectorValidator(): packetCount %d, dir %d, size %d\n', gServiceName,
               context.packetCount, dir, size);
    if (size == 0 or dir == 0) then
        return serviceInProcess(context)
    end

    if((dir == 1) and
       (size >= 20) and
       (gDetector:memcmp(gPatterns.response[1], #gPatterns.response[1], gPatterns.response[2]) == 0))
    then
        DC.printf('server packet. dir %d size %d\n',dir, size)
        if (gDetector:getPcreGroups('x-gnutella2')) then
            context.service = gnutella2ID
        else
            context.service = gnutellaID
        end
        
    matched, agent, divider, ver = gDetector:getPcreGroups('User-Agent: ([-0-9a-zA-Z]*)( |/)([-0-9.]*).*(\013|\010)')
        if (matched) then
            DC.printf('agent: %s ver: %s\n', agent, ver)
            if (string.find(agent, 'Lime')) then
                context.vendor = "Lime Wire LLC"
            elseif (string.find(agent, 'BearShare')) then
                context.vendor = "MusicLab LLC"
            elseif (string.find(agent, 'Shareaza')) then
                context.vendor = "Shareaza Development Team"
            elseif (string.find(agent, 'morph')) then
                context.vendor = "StreamCast Networks"
            elseif (string.find(agent, 'Foxy')) then
                context.vendor = "Vastel Technology"
            end
            context.version = ver
        end

        DC.printf("vendor %s, version %s, service %d\n", context.vendor, context.version, context.service)

        return serviceSuccess(context)
    end

    return serviceFail(context)
end

--[[Required DetectorFini function
--]]
function DetectorFini()
    --print (gServiceName .. ': DetectorFini()')
end

