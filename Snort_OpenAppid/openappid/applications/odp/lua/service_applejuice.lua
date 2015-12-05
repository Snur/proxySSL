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
detection_name: Applejuice
version: 3
description: Peer-to-peer file sharing.
--]]

require "DetectorCommon"


--require('debugger')
--local DC = require("DetectorCommon")
local DC = DetectorCommon
local FT = flowTrackerModule

DetectorPackageInfo = {
    name =  "Applejuice",
    proto =  DC.ipproto.tcp,
    server = {
        init =  'DetectorInit',
        validate =  'DetectorValidator',
    }
}

gServiceId = 20038
gServiceName = 'Applejuice'
gDetector = nil

gSfAppIdApplejuice = 29
--patterns used in DetectorInit()
gPatterns = {
    --patternName        Pattern         offset
    -------------------------------------------
    clientReq = {'ajprot\013\010', 0, gSfAppIdApplejuice},
    serverRsp = {'\000\145', 0, gSfAppIdApplejuice},
}

--fast pattern registerd with core engine 
gFastPatterns = {
    --protocol       patternName
    ------------------------------------
    {DC.ipproto.tcp, gPatterns.serverRsp},
}

--port based detection - needed when not using CSD tables
    --{DC.ipproto.udp, 3478},
gPorts = {
    {DC.ipproto.tcp, 9858},
}

gAppRegistry = {
	--AppIdValue          Extracts Info
	---------------------------------------
	{gSfAppIdApplejuice,		         0}
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
        gDetector:addService(gServiceId, "", "", gSfAppIdApplejuice)
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
    context.packetCount = gDetector:getPktCount()
    context.packetDataLen = gDetector:getPacketSize()
    context.packetDir = gDetector:getPacketDir()
    context.flowKey = context.detectorFlow:getFlowKey()

    local dir =  context.packetDir
    local size = context.packetDataLen
    local flowKey = context.flowKey
    local  rft = FT.getFlowTracker(flowKey)

    DC.printf ('%s:DetectorValidator(): packetCount %d, dir %d, size %d\n', gServiceName, context.packetCount, dir, size);

    if (size == 0) then
        return serviceInProcess(context)
    end

    --first client packet is received
    if ((dir == 0) and (size > 7)) then
        matched = gDetector:getPcreGroups(gPatterns.clientReq[1], 0); 
        if matched then
            --detected here but reported on server response
            if (rft == nil) then
                FT.addFlowTracker(flowKey, {stage=2})
            else
                rft.stage = 2
            end

            DC.printf ('packet %d: detected applejuice\n', context.packetCount)
            return serviceInProcess(context)
        end
    end

    if (dir == 1) then 

        --first server response received after getting client request.
        if ((rft) and (rft.stage == 2)) then
            FT.delFlowTracker(flowKey)
            return serviceSuccess(context)
        end

        --first server packet received 
        if ((size == 2) and (gDetector:memcmp(gPatterns.serverRsp[1], #gPatterns.serverRsp[1],0) == 0)) then
            if (rft == nil) then
                --detected here but reported on server response
                FT.addFlowTracker(flowKey, {stage=1})
            else
                rft.stage = 1
            end
        end
    end

    if ((rft) and (rft.stage == 1)) then
        return serviceInProcess(context)
    end

    --fails since the detector get syn packet also.
    return serviceFail(context)
end

--[[Required DetectorFini function
--]]
function DetectorFini()
    --DC.printf ('%s:DetectorFini()\n', gServiceName);
end
