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
detection_name: Payload Group "drambuie"
version: 4
description: Group of payload detectors.
bundle_description: $VAR1 = {
          'BlueStacks update' => 'Updates for the BlueStacks app player.',
          'JetBrains' => 'A collection of IDEs for different programming languages and frameworks.',
          'BlueStacks download' => 'Download of BlueStacks components.',
          'Periscope' => 'Mobile app for live video streaming.',
          'JetBrains plugins' => 'JetBrains IDE plugins.',
          'JetBrains update' => 'Updates for JetBrains IDE software.',
          'WhatsApp' => 'A cross-platform mobile messaging app which serves as a free alternative to SMS messages.',
          'ESPNcricinfo' => 'ESPN site focused on the game of Cricket.',
          'JetBrains feature' => 'JetBrains IDE cloud storage features.',
          'Amazon Instant Video' => 'Amazon video streaming site.',
          'Youdao Dictionary' => 'A chinese dictionary, available online and offline.',
          'BlueStacks apps' => 'Site for apps running on BlueStacks.',
          'Starsports' => 'Live streaming sports from India.',
          'F-secure' => 'Antivirus software.',
          'BlueStacks' => 'An app player that runs mobile apps on laptops and desktop machines.',
          'SUPERAntiSpyware' => 'Antivirus / antimalware application.',
          'Meerkat' => 'Mobile app for live video streaming.',
          'Malwarebytes' => 'Antimalware software.',
          'Microsoft Visual Studio' => 'Microsoft Integrated Developer Environment and toolchain designed to make it easier to develop software for Microsoft platforms.'
        };

--]]

require "DetectorCommon"


local DC = DetectorCommon

DetectorPackageInfo = {
    name =  "payload_group_drambuie",
    proto =  DC.ipproto.tcp,
    client = {
        init =  'DetectorInit',
        clean =  'DetectorClean',
        minimum_matches =  1
    }
}

gUrlPatternList = {

    -- starsports
    { 0, 0, 0, 1674, 13, "starsports.com", "/", "http:", "", 3977},

    -- espncricinfo
    { 0, 0, 0, 1675, 13, "espncricinfo.com", "/", "http:", "", 3978},

    -- Microsoft Visual Studio
    { 0, 0, 0, 1676, 11, "download.microsoft.com", "/VSUpdateTemplate.atom", "http:", 3979},
    { 0, 0, 0, 1676, 11, "code.msdn.microsoft.com", "/sample.svc", "http:", "http:", 3979},
    { 0, 0, 0, 1676, 11, "visualstudiogallary.msdn.microsoft.com", "/extension.svc", "http:", 3979},

    -- JetBrains
    { 0, 0, 0, 1678, 11, "jetbrains.com", "/", "http:", 3981},

    -- JetBrains update
    { 0, 0, 0, 1680, 11, "jetbrains.com", "/updates", "http:", 3983},

    -- JetBrains plugins
    { 0, 0, 0, 1681, 11, "jetbrains.com", "/plugins", "http:", 3984},

    -- JetBrains feature
    { 0, 0, 0, 1682, 11, "jetbrains.com", "/feature", "http:", 3985},

    -- YouDao Dictionary
    { 0, 0, 0, 1679, 11, "youdao.com", "/", "http:", 3982},    
     { 0, 0, 0, 1679, 11, "ydstatic.com", "/", "http:", 3982},

    -- BlueStacks
    { 0, 0, 0, 1677, 11, "bluestacks.com", "/", "http:", 3980},

    -- BlueStacks update
    { 0, 0, 0, 1683, 11, "cdn.bluestacks.com", "/updates/", "http:", 3986},

    -- BlueStacks download
    { 0, 0, 0, 1684, 11, "cdn.bluestacks.com", "/downloads/", "http:", 3987},

    -- BlueStacks apps
    { 0, 0, 0, 1685, 11, "opasanet.appspot.com", "/op/", "http:", 3988},

    -- F-secure
    { 0, 0, 0, 1686, 11, "f-secure.com", "/", "http:", "", 3989},

    -- Malwarebytes
    { 0, 0, 0, 1687, 11, "mbamupdates.com", "/", "http:", "", 3990},
    { 0, 0, 0, 1687, 11, "malwarebytes.org", "/", "http:", "", 3990},

    -- SUPERAntiSpyware
    { 0, 0, 0, 1688, 11, "superantispyware.com", "/", "http:", "", 3991},
    
    --WhatsApp
    { 0, 0, 0, 1689, 5, "whatsapp.com", "/", "http:", "", 1143},
    --Amazon Instant Video
    { 0, 0, 0, 1690, 5, "amazonmmd.loris.llnwd.net", "/", "http:", "", 3793},
}



function DetectorInit(detectorInstance)

    gDetector = detectorInstance;

    if gDetector.addAppUrl then
        for i,v in ipairs(gUrlPatternList) do
            gDetector:addAppUrl(v[1],v[2],v[3],v[4],v[5],v[6],v[7],v[8],v[9],v[10]);
        end
    end

    -- JetBrains
    gDetector:addHttpPattern(2, 5, 0, 475, 24, 0, 0, 'NSIS_Inetc', 3981, 1);

    -- YouDao Dictionary
    gDetector:addHttpPattern(2, 5, 0, 476, 24, 0, 0, 'Youdao Desktop Dict', 3982, 1);
    gDetector:addHttpPattern(2, 5, 0, 476, 24, 0, 0, 'youdaodict', 3982, 1);

    -- BlueStacks
    gDetector:addHttpPattern(2, 5, 0, 474, 24, 0, 0, 'BlueStacks', 3980, 1);

    -- F-secure
    gDetector:addHttpPattern(2, 5, 0, 477, 25, 0, 0, 'FsCcfDownload', 3989, 1);
    gDetector:addHttpPattern(2, 5, 0, 477, 25, 0, 0, 'FSORSP', 3989, 1);
    gDetector:addHttpPattern(2, 5, 0, 477, 25, 0, 0, 'CCF DNS', 3989, 1);    

    -- Malwarebytes
    gDetector:addHttpPattern(2, 5, 0, 478, 25, 0, 0, 'mbam -', 3990, 1);

    -- SUPERAntiSpyware
    gDetector:addHttpPattern(2, 5, 0, 479, 25, 0, 0, 'SASDef_GetDescriptor', 3991, 1);
    gDetector:addHttpPattern(2, 5, 0, 479, 25, 0, 0, 'SABUPDATE', 3991, 1);
    gDetector:addHttpPattern(2, 5, 0, 479, 25, 0, 0, 'SASDIAGNOSTICITEM', 3991, 1);
    gDetector:addHttpPattern(2, 5, 0, 479, 25, 0, 0, 'SAS_APP', 3991, 1);
    gDetector:addHttpPattern(2, 5, 0, 479, 25, 0, 0, 'SABACTIVATION', 3991, 1);
    gDetector:addHttpPattern(2, 5, 0, 479, 25, 0, 0, 'SASThreatMap', 3991, 1);
    
    --Periscope
    gDetector:addHttpPattern(2, 5, 0, 480, 16, 0, 0, 'Periscope', 3992, 1);
    gDetector:addHttpPattern(2, 5, 0, 480, 16, 0, 0, 'com.bountylabs.periscope', 3992, 1);

    -- Meerkat
    gDetector:addHttpPattern(1, 0, 0, 481, 16, 0, 0, 'meerkatapp.co', 3993 , 1);
    
    --Amazon Instant Video
    gDetector:addHttpPattern(2, 5, 0, 482, 16, 0, 0, 'Instant Video', 3793, 1);

    return gDetector;
end

function DetectorClean()
end

