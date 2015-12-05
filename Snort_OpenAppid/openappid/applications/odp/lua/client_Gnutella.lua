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
description: A large peer-to-peer file-sharing network.
bundle_description: $VAR1 = {
          'Gnucleus' => 'Peer to peer software.',
          'LimeWire' => 'Peer to peer file sharing software.',
          'Foxy' => 'Peer to peer client.',
          'Morpheus' => 'Peer to peer file sharing software.',
          'BearShare' => 'Peer to peer file sharing software.',
          'Shareaza' => 'Peer to peer client.',
          'gtk-gnutella' => 'Graphical Gnutella client.',
          'giFT' => 'Gnutella client.'
        };

--]]

require "DetectorCommon"



local DC = DetectorCommon
local FT = flowTrackerModule

DetectorPackageInfo = {
    name =  "Gnutella",
    proto =  DC.ipproto.tcp,
    client = {
        init =  'client_init',
        clean =  'client_clean',
        validate =  'client_validate',
        minimum_matches =  1
    }
}

gSfAppIdGnutella = 658

gPatterns = {
    connect = { "GNUTELLA\032CONNECT/0", 0, gSfAppIdGnutella},
}

gFastPatterns = {
    {DC.ipproto.tcp, gPatterns.connect},
}

gAppRegistry = {
	--AppIdValue          Extracts Info
	---------------------------------------
	{gSfAppIdGnutella,		         1}
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
    gDetector:client_addApp(context.service, typeID, context.product, context.version, gSfAppIdGnutella);
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

    gnutella_serviceID = 20030 
    gnutella2_serviceID = 20074

    typeID = 15

    gnutellaID = 27
    limewireID = 76
    bearshareID = 77
    shareazaID = 78
    morpheusID = 79
    foxyID = 80
    gtkID = 81
    gnucleusID = 82
    giftID = 83
    
    DC.printf ('%s:DetectorValidator(): appTypeId %d, product %d, service %d\n', DetectorPackageInfo.name, typeID, gnutellaID, gnutella_serviceID)

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
    context.version = ""

    DC.printf ('packetCount %d dir %d, size %d\n', context.packetCount, dir, size)

    if (size == 0) then
        return clientInProcess(context)
    end

    if ((dir == 0) and 
        (size >= 20))
    then
        if (gDetector:getPcreGroups('x-gnutella2')) then
            context.service = gnutella2_serviceID
        else
            context.service = gnutella_serviceID
        end

        matched, agent, divider, ver = gDetector:getPcreGroups('User-Agent: ([-0-9a-zA-Z]*)( |/)([-0-9.]*).*(\013|\010)')
        if (matched) then
            DC.printf('agent: %s ver: %s\n', agent, ver)
            if (string.find(agent, 'Lime')) then
                context.product = limewireID
            elseif (string.find(agent, 'BearShare')) then
                context.product = bearshareID
            elseif (string.find(agent, 'Shareaza')) then
                context.product = shareazaID
            elseif (string.find(agent, 'morph')) then
                context.product = morpheusID
            elseif (string.find(agent, 'Foxy')) then
                context.product = foxyID    
            elseif (string.find(agent, 'gtk')) then
                context.product = gtkID 
            elseif (string.find(agent, 'Gnucleus')) then
                context.product = gnucleusID
            elseif (string.find(agent, 'giFT')) then
                context.product = giftID
            end
            context.version = ver
        else
            context.product = gnutellaID
        end

        DC.printf("product %d, version %s, service %d\n", context.product, context.version, context.service)

        return clientSuccess(context)
    end

    return clientFail(context)

end

function client_clean()
end
