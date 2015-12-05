--[[
# Copyright (C) Cisco and/or its affiliates. All rights reserved.
# Copyright 2001-2013 Sourcefire, Inc. All Rights Reserved.
#
# This file contains detector content that was created,
# tested, and certified by Sourcefire, Inc. that is
# distributed under the OpenAppID Detector Content License
# Agreement (v 1.0).
#
# The detector content is owned by Sourcefire, Inc.
#
# Please refer to the OpenAppID Detector Content License
# Agreement (v1.0) for details.
--]]

local bit = require("bit")

--[[ Protocol type. See IPPROTO_xxxx defined in /usr/include/netinet/in.h
--]]
local ipproto = {
    ip = 0,	       --Dummy protocol for TCP.  
    hopopts = 0,   --IPv6 Hop-by-Hop options.  
    icmp = 1,	   --Internet Control Message Protocol.  
    igmp = 2,	   --Internet Group Management Protocol. 
    ipip = 4,	   --IPIP tunnels (older KA9Q tunnels use 94).  
    tcp = 6,	   --Transmission Control Protocol.  
    egp = 8,	   --Exterior Gateway Protocol.  
    pup = 12,	   --PUP protocol.  
    udp = 17,	   --User Datagram Protocol.  
    idp = 22,	   --XNS IDP protocol.  
    tp = 29,	   --SO Transport Protocol Class 4.  
    ipv6 = 41,     --IPv6 header.  
    routing = 43,  --IPv6 routing header.  
    fragment = 44, --IPv6 fragmentation header.  
    rsvp = 46,	   --Reservation Protocol.  
    gre = 47,	   --General Routing Encapsulation.  
    esp = 50,      --encapsulating security payload.  
    ah = 51,       --authentication header.  
    icmpv6 = 58,   --ICMPv6.  
    none = 59,     --IPv6 no next header.  
    dstopts = 60,  --IPv6 destination options.  
    mtp = 92,	   --Multicast Transport Protocol.  
    encap = 98,	   --Encapsulation Header.  
    pim = 103,	   --Protocol Independent Multicast.  
    comp = 108,	   --Compression Header Protocol.  
    sctp = 132,	   --Stream Control Transmission Protocol.  
    raw = 255,	   --Raw IP packets.  
}

--[[Flow flag values as defined in rna_flow.h. Any additional flags for flow should
--be added here.
--]]
local flowFlags = {
    udpReversed       = 0x00400000,
    incompatible      = 0x00800000, -- Service protocol had incompatible client data 
    ignoreHost        = 0x01000000, -- Call service detection even if the host does not exist 
    ignoreTcpSeq      = 0x02000000, -- Ignore TCP state tracking 
    clientAppDetected = 0x04000000, -- Finsihed with client app detection 
    gotBanner         = 0x08000000, -- Acquired a banner 
    notAService       = 0x10000000, -- Flow is a data connection not a service 
    logUnknown        = 0x20000000, -- Log packets of the session
    continue          = 0x40000000, -- Continue calling the routine after the service has been identified.
    serviceDetected   = 0x80000000, --Service protocol was detected
}

--[[SERVICE_RETCODE as defined in service_base.h
--]]
local serviceStatus = {
    success = 0,
    inProcess = 10,
    needReassembly = 11,
    notCompatible = 12,
    invalidClient = 13,
    reversed = 14,
    nomatch = 100,
    enull = -10,
    einvalid = -11,
    enomem = -12
} 

local clientStatus = {
    success = 0,
    inProcess = 10,
    enull = -10,
    einvalid = -11,
    enomem = -12
} 

local flowDirection = {
    fromInitiator = 0,
    fromResponder = 1
}

local logLevel = {
    crit = 0,  -- critical conditions
    err = 1,  -- error conditions
    warning = 2,  -- warning conditions
    notice = 3,  -- normal but significant condition
    info = 4,  -- informational
    debug = 5, -- debug-level messages
}

local flowProtocol =  {
    tcp = 0x00000004,
    udp = 0x00000008,
}

local function ntop(netString)
    _, _, octet1, octet2, octet3, octet4 = string.find(netString, "(%d+)%.(%d+)%.(%d+)%.(%d+)")
    if (octet4) then
        return octet1 * octet2 * octet3 * octet4
    end
    return nil
end

local function realPrintf(s,...)
    return io.write(s:format(...))
end

local function dummyPrintf(s,...)
end

local function reverseBinaryStringToNumber(binString, numBytes)
    local totalValue = 0
    local i = numBytes
    while (i > 0) do
        totalValue = bit.lshift(totalValue, 8)
        if binString:byte(i) then
            totalValue = totalValue + binString:byte(i)
        end
        i = i - 1
    end
    return totalValue
end

local function binaryStringToNumber(binString, numBytes) 
    local totalValue = 0
    for i = 1,numBytes  do
        totalValue = bit.lshift(totalValue, 8)
        if binString:byte(i) then
            totalValue = totalValue + binString:byte(i)
        end
        --print ("offset " .. i .. " total " .. totalValue)
    end
    return totalValue
end

--[[tonumber() assumes input is being given in network byte order, that is converted to host order. So
if input is from packet directly, then it works fine. If input is from some bytestring from C, then one 
has to change the bytestring to network order before calling the function.
--]]
local function getShortHostFormat (netShort)
    return binaryStringToNumber(netShort,2)
end

local function getLongHostFormat (netLong)
    return binaryStringToNumber(netLong,4)
end

local function getStringValue (data, length)
    local stringValue = '0x'
    local index=0
    
    while (index <  length) do
        stringValue = string.format('%s%.2x', stringValue, string.byte(data,index+1))
        index = index + 1
    end
    return stringValue
end

--[[ Exporting functions and data in this package. Function/data not listed here will remain 
--hidden from other lua files. Any helper functions that are needed often should be moved
--into this package.
--]]
DetectorCommon = {
    ipproto = ipproto,
    flowFlags = flowFlags,
    serviceStatus = serviceStatus,
    clientStatus = clientStatus,
    flowDirection = flowDirection,
    ntop = ntop,
    logLevel = logLevel,
    flowProtocol = flowProtocol,
    printf = dummyPrintf,
    getShortHostFormat = getShortHostFormat,
    getLongHostFormat = getLongHostFormat,
    binaryStringToNumber = binaryStringToNumber,
    getStringValue = getStringValue,
    reverseBinaryStringToNumber = reverseBinaryStringToNumber,
}

--host service tracker - OpenDPI has battlefield patterns that are run only when battlefield was previously 
--detected on the host.
local gHostServiceTracker = {}
--
--array defining ordering of gHostServiceTracker, sorted by creation time
local gHostServiceTrackerSorted = {}

 gHostServiceTrackerSize = 5000

local function addHostServiceTracker(ipAddress, hostData)
    local trackerKey = string.format("%.8x", ipAddress)

    --existing key
    if (gHostServiceTracker[trackerKey] ~= nil) then
        --print ("Collision for key value " .. trackerKey)
        gHostServiceTracker[trackerKey] = hostData
        return hostData
    end

    if (#gHostServiceTrackerSorted >= gHostServiceTrackerSize) then
        --print ("Purging deleted entries\n")

        for i,v in ipairs(gHostServiceTrackerSorted) do 
            if (gHostServiceTracker[v] == nil) then
                --print ("removing from sorted " .. v)
                table.remove(gHostServiceTrackerSorted,i)
            end
        end

        local hstDelete = table.remove(gHostServiceTrackerSorted,1)
        --print ("Dropping oldest entry " .. hstDelete)
        gHostServiceTracker[hstDelete] = nil
    end


    --print ("creating entry " .. trackerKey)
    gHostServiceTracker[trackerKey] = hostData
    table.insert(gHostServiceTrackerSorted, trackerKey)

    return hostData
end

local function getHostServiceTracker(ipAddress)
    local trackerKey = string.format("%.8x", ipAddress)
    return gHostServiceTracker[trackerKey]
end

local function delHostServiceTracker(ipAddress)
    local trackerKey = string.format("%.8x", ipAddress)
    --print ("deleting entry " .. trackerKey)
    gHostServiceTracker[trackerKey] = nil
end

local function printHostServiceTracker()
    local elementCount = 0
    for i,v in pairs(gHostServiceTracker) do
        print ("\tElements in Tracker " .. i )
        elementCount = elementCount+1
    end
    print (" gHostServiceTracker " .. elementCount .. " gHostServiceTrackerSorted " .. #gHostServiceTrackerSorted)
end

local function setHostServiceTrackerSize(size)
    gHostServiceTrackerSize = size
end

hostServiceTrackerModule = {
    addHostServiceTracker = addHostServiceTracker,
    getHostServiceTracker = getHostServiceTracker,
    delHostServiceTracker = delHostServiceTracker,
    printHostServiceTracker = printHostServiceTracker,
    setHostServiceTrackerSize = setHostServiceTrackerSize,
}

--[[Hash contains detector specific data related to a flow
gFlowTracker should be restricted to some size otherwise the table can be overrun by
terminating lots of flows before this detector can determine success or failure. Ideally,
each flow should have a reference time that gets updated everytime a packet from the flow
is processed, but calling os function everytime will likely be expensive. Instead, flow
create time is used to order flow. The oldest flow is purged to make space for new flows.
--]]

local gFlowTracker = {}

--array containing flowKey of active flows, sorted by creation time
local gFlowTrackerSorted = {}

local gFlowTrackerSize = 5000

local function addFlowTracker(flowKey, flowData)
    --existing key
    if (gFlowTracker[flowKey] ~= nil) then
        --print ("Collision for key value " .. flowKey)
        gFlowTracker[flowKey] = flowData
        return flowData
    end

    if (#gFlowTrackerSorted >= gFlowTrackerSize) then
        --DC.printf ("deleting rtf\n");
        --purge all deleted entries
        --print ("Purging deleted entries\n")
        for i,v in ipairs(gFlowTrackerSorted) do 
            if (gFlowTracker[v] == nil) then
                --print ("removing from sorted " .. v)
                table.remove(gFlowTrackerSorted,i)
            end
        end

        local rftDelete = table.remove(gFlowTrackerSorted,1)
        --print ("Dropping oldest entry " .. rftDelete)
        gFlowTracker[rftDelete] = nil
    end

    --print ("creating flowkey " .. flowKey)
    gFlowTracker[flowKey] = flowData
    table.insert(gFlowTrackerSorted, flowKey)

    return flowData
end

local function getFlowTracker(flowKey)
    return gFlowTracker[flowKey]
end

local function delFlowTracker(flowKey)
    --print ("deleting flowkey " .. flowKey)
    gFlowTracker[flowKey] = nil
end

local function printFlowTracker()
    local elementCount = 0
    for i,v in pairs(gFlowTracker) do
        print ("\tElements in Tracker " .. i )
        elementCount = elementCount+1
    end
    print (" gFlowTracker " .. elementCount .. " gFlowTrackerSorted " .. #gFlowTrackerSorted)
end

local function setFlowTrackerSize(size)
    gFlowTrackerSize = size
end

flowTrackerModule = {
    addFlowTracker = addFlowTracker,
    getFlowTracker = getFlowTracker,
    delFlowTracker = delFlowTracker,
    printFlowTracker = printFlowTracker,
    setFlowTrackerSize = setFlowTrackerSize
}

