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
detection_name: KAD
version: 4
description: P2P network that uses the Kademlia algorithm.
--]]

require "DetectorCommon"



local DC = DetectorCommon
local FT = flowTrackerModule

gServiceId = 20079
gServiceName = 'KAD'
gDetector = nil

DetectorPackageInfo = {
    name =  "KAD",
    proto =  DC.ipproto.udp,
    server = {
        init =  'DetectorInit',
        validate =  'DetectorValidator',
    }
}

gSfAppIdKad = 697
gPatterns = {
    kad_req1 = { '\228\032', 0, gSfAppIdKad },
    kad_req2 = { '\229\032', 0, gSfAppIdKad },
    kad_res = { '\228\040', 0, gSfAppIdKad },
    kad_hello_req = { '\228\016', 0, gSfAppIdKad },
    kad_hello_res = { '\228\024', 0, gSfAppIdKad },
    kad_firewalled_req = { '\228\080', 0, gSfAppIdKad },
    kad_firewalled_res = { '\228\088', 0, gSfAppIdKad },
    kad_publish_req = { '\228\064', 0, gSfAppIdKad },
    kad_publish_res = { '\228\072', 0, gSfAppIdKad },
    edonkey_searchfile_req = { '\227\152', 0, gSfAppIdKad },
    edonkey_searchfile_res = { '\227\153', 0, gSfAppIdKad },
    edonkey_server_status_req = { '\227\150', 0, gSfAppIdKad },
    edonkey_server_status_res = { '\227\151', 0, gSfAppIdKad },
    edonkey_server_info_req = { '\227\162', 0, gSfAppIdKad },
    edonkey_server_info_res = { '\227\163', 0, gSfAppIdKad },
    edonkey_unknown1_req = { '\227\014', 0, gSfAppIdKad },
    edonkey_unknown1_res = { '\227\015', 0, gSfAppIdKad },
    edonkey_unknown2_req = { '\227\012', 0, gSfAppIdKad },
    edonkey_unknown2_res = { '\227\013', 0, gSfAppIdKad },
}

gFastPatterns = {
    {DC.ipproto.udp, gPatterns.kad_req1},
    {DC.ipproto.udp, gPatterns.kad_req2},
    {DC.ipproto.udp, gPatterns.kad_res},
    {DC.ipproto.udp, gPatterns.kad_hello_req},
    {DC.ipproto.udp, gPatterns.kad_hello_res},
    {DC.ipproto.udp, gPatterns.kad_firewalled_req},
    {DC.ipproto.udp, gPatterns.kad_firewalled_res},
    {DC.ipproto.udp, gPatterns.kad_publish_req},
    {DC.ipproto.udp, gPatterns.kad_publish_res},
    {DC.ipproto.udp, gPatterns.edonkey_searchfile_req},
    {DC.ipproto.udp, gPatterns.edonkey_searchfile_res},
    {DC.ipproto.udp, gPatterns.edonkey_server_status_req},
    {DC.ipproto.udp, gPatterns.edonkey_server_status_res},
    {DC.ipproto.udp, gPatterns.edonkey_server_info_req},
    {DC.ipproto.udp, gPatterns.edonkey_server_info_res},
    {DC.ipproto.udp, gPatterns.edonkey_unknown1_req},
    {DC.ipproto.udp, gPatterns.edonkey_unknown1_res},
    {DC.ipproto.udp, gPatterns.edonkey_unknown2_req},
    {DC.ipproto.udp, gPatterns.edonkey_unknown2_res},
}

gPorts = {
}

client_protocol = nil
client_msg_type = nil

gAppRegistry = {
	--AppIdValue          Extracts Info
	---------------------------------------
	{gSfAppIdKad,		         0}
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
        gDetector:addService(context.serviceid, "", "", gSfAppIdKad)
    end

    if (context.serviceid == kad_id) then
        DC.printf('%s: Detected KAD, packetCount: %d\n', gServiceName, context.packetCount)
    else
        DC.printf('%s: Detected eDonkey, packetCount: %d\n', gServiceName, context.packetCount)
    end

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

    kad_id = 20079
    edonkey_id = 20080    

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
    context.serviceid = kad_id

    DC.printf('%s: packetCount %d, dir %d, size %d\n', gServiceName,
               context.packetCount, dir, size);

    matched, flag_raw, msg_type = gDetector:getPcreGroups('(.)(.)', 0)

    if (matched) then
        flag_num = DC.binaryStringToNumber(flag_raw, 1)
        msg_type_num = DC.binaryStringToNumber(msg_type, 1)
    else
        DC.printf("%s: couldn't match two bytes\n", gServiceName)
        return serviceFail(context)
    end

    if (dir == 0) then
        client_protocol = flag_num
        client_msg_type = msg_type_num
        DC.printf("client packet, proto %d msg type %d\n", client_protocol, client_msg_type)
        return serviceInProcess(context)
    elseif ((dir == 1) and
            (client_protocol) and
            (client_protocol == flag_num) and
            (client_msg_type)) then

            DC.printf("server packet, proto %d, msg type %d\n", flag_num, msg_type_num)

            if ((client_protocol == 227) and
                (client_msg_type == msg_type_num - 1)) then
                DC.printf("its eDonkey\n")
                context.serviceid = edonkey_id
                return serviceSuccess(context)
            end

            if ((client_protocol == 228) and
                (client_msg_type == msg_type_num - 8)) then
                DC.printf("its KAD\n")
                return serviceSuccess(context)
            end
            
    end

    return serviceFail(context)
end

--[[Required DetectorFini function
--]]
function DetectorFini()
    --print (gServiceName .. ': DetectorFini()')
end

