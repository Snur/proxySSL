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
detection_name: VNC
version: 3
description: Graphical desktop sharing protocol.
bundle_description: $VAR1 = {
          'VNC' => 'Graphical desktop sharing protocol.',
          'Apple Remote Desktop' => 'VNC on Mac OSX.'
        };

--]]

require "DetectorCommon"



local DC = DetectorCommon
local FT = flowTrackerModule

gServiceId = 24
gServiceName = 'VNC'
gDetector = nil

DetectorPackageInfo = {
    name =  "VNC",
    proto =  DC.ipproto.tcp,
    server = {
        init =  'DetectorInit',
        validate =  'DetectorValidator',
    }
}


gSfAppIdVNC = 894
gSfAppIdARD = 2959
gSfServiceIdARD = 20189

--port based detection 
gPorts = {
    {DC.ipproto.tcp, 902},
    {DC.ipproto.tcp, 5900},
}

gPatterns = {
    ARD_ver = {"\048\048\051\046\056\056\057", 4, gSfAppIdARD},    
}

gFastPatterns = {
    {DC.ipproto.tcp, gPatterns.ARD_ver}
}

gAppRegistry = {
	--AppIdValue          Extracts Info
	---------------------------------------
	{gSfAppIdVNC,		         0}
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
        DC.printf('%s: Detected, app ID : %d\n', gServiceName, context.appId);
        gDetector:addService(context.serviceId, "", "", context.appId)
    end
        DC.printf('%s: Detected, appID : %d\n', gServiceName, context.appId);

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
    DC.printf ('%s:DetectorInit() before %d\n', gServiceName, gServiceId);
    gDetector:init(gServiceName, 'DetectorValidator', 'DetectorFini')
    DC.printf ('%s:DetectorInit() after %d\n', gServiceName, gServiceId);
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

    DC.printf ('%s:DetectorValidator(): packetCount %d, dir %d, size %d\n', gServiceName,
               context.packetCount, dir, size);

	if (size == 0 or dir == 0) then
        return serviceInProcess(context)
    end

	--handling downloading (caught by port only)
	if ((dir == 1) and (size >= 4)) then 
            DC.printf ('%s:DetectorValidator(): inside the service packet\n', gServiceName);
            if (gDetector:memcmp(gPatterns.ARD_ver[1], #gPatterns.ARD_ver[1], gPatterns.ARD_ver[2]) == 0) then
                context.serviceId = gSfServiceIdARD
                context.appId = gSfAppIdARD
                return serviceSuccess(context)
            else
                local matched = gDetector:getPcreGroups("MKSDisplayProtocol:VNC", 0)
                if matched then
                    context.serviceId = gServiceId
                    context.appId = gSfAppIdVNC
                    return serviceSuccess(context)
                end
            end
            DC.printf ('%s:DetectorValidator(): Not Matched \n', gServiceName);
	end

    --FT.delFlowTracker(flowKey)
    return serviceFail(context)
end

--[[Required DetectorFini function
--]]
function DetectorFini()
    --print (gServiceName .. ': DetectorFini()')
end

