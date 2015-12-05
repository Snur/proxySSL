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
detection_name: SSL Group "Oingo"
version: 14
description: Group of SSL Host detectors.
bundle_description: $VAR1 = {
          'Java Update' => 'Java update software service.',
          'SoftEther' => 'An open source VPN.',
          'SOS Online Backup' => 'Cloud-based backup service.',
          'Rotten Tomatoes' => 'Online information and reviews about new films.',
          'Minecraft' => 'Online game.',
          'Glympse' => 'Mobile App to share the location with others.',
          'Podio' => 'Project Management software.',
          'Google Fiber' => 'Internet service provider by Google.',
          'FiOS TV' => 'Verizon FiOS TV.',
          'Redbox' => 'Online movie rental and video streaming.',
          'Mailbox' => 'App for Email service.',
          'Vdio' => 'Watch video online.',
          'iBackup' => 'Cloud-based backup service.',
          'Pivotal Tracker' => 'Project management and collaborative software.',
          'LivePerson' => 'Online Marketing and Web analytics service provider.',
          'Chartbeat' => 'Realtime Website data for Collection.',
          'Rdio' => 'Music subscription service.',
          'Flipboard' => 'News aggregator Mobile application.',
          'Disney' => 'Official Disney website.',
          'TweetDeck' => 'Dashboard application to manage both Twitter and Facebook.',
          'KakaoTalk' => 'Mobile messaging for smartphones.',
          'H&R Block' => 'Tax service provider.',
          'Mention' => 'Site that will generate alerts and updates regarding topics you are interested in.',
          'Basecamp' => 'Web based project management tool.',
          'Microsoft' => 'Official Microsoft website.',
          'JustCloud' => 'Cloud-based backup service.',
          'Microsoft Update' => 'Microsoft software updates.',
          'Carbonite' => 'Cloud-based backup service.',
          'EdgeCast' => 'Content delivery network.',
          'jdistatic' => 'Cloud-based backup service.',
          'Wii Shop Channel' => 'Nintendo Wii store for games and DLC.',
          'MyPCBackup' => 'Cloud-based backup service.',
          'SugarSync' => 'Cloud-based backup service.',
          'Bing' => 'Microsoft\'s internet search engine.',
          'Xbox Live' => 'Microsoft online gaming service.',
          'ShareThis' => 'Social advertising widgets.',
          'Wordpress' => 'An online blogging community.',
          'Sourcefire.com' => 'Company website for Network security and Intrusion Detection engine.',
          'ESPN' => 'Online Sports news and show.',
          'Habbo' => 'Social networking site aimed at teenagers.',
          'Constant Contact' => 'Online marketing service.',
          'ZipCloud' => 'Cloud-based backup service.',
          'Backupgrid' => 'Reseller of cloud backup / storage solutions.'
        };

--]]

require "DetectorCommon"


local DC = DetectorCommon

DetectorPackageInfo = {
    name =  "ssl_host_group_Oingo",
    proto =  DC.ipproto.tcp,
    client = {
        init =  'DetectorInit',
        clean =  'DetectorClean',
        minimum_matches =  1
    }
}

--serviceId, clientId, ClientType, PayloadId, PayloadType, hostPattern, pathPattern, schemePattern, queryPattern
gSSLHostPatternList = {

    -- Java Update
    { 1, 1569, 'javadl-esd-secure.oracle.com' },
    { 1, 1569, 'www.java.com' },
    -- H&R Block
    { 0, 1792, 'hrblock.com' },
    -- Constant Contact
    { 0, 1793, 'constantcontact.com' },
    -- Pivotal Tracker 
    { 0, 1794, 'pivotaltracker.com' },
    -- Habbo
    { 0, 980, 'habbo.com' },
    { 0, 980, 'habboo-a.akamaihd.net' },
    -- Podio 
    { 0, 1796, 'podio.com' },
    -- Rdio 
    { 0, 1029, 'rdio-a.akamaihd.net' },
    { 0, 1029, 'rdio.com' },
    { 0, 1029, 'rd.io' },
    -- LiverPerson
    { 0, 1797, 'liveperson.net' },
    { 0, 1797, 'liveperson.com' },
    -- Mention
    { 1, 1798, 'mention.net' },
    -- Mailbox
    { 1, 1801, 'orcali.com' },
    -- Minecraft
    { 0, 1802, 'minecraft.net' },
    { 0, 1802, 'mojang.com' },
    -- SoftEther
    { 1, 3809, 'public.softether.com' },
    { 1, 3809, 'hub.softether.com' },
    { 1, 3809, 'softsether.org' },
    { 1, 3809, 'softether.org' },
    -- KakaoTalk
    { 1, 1405, 'kakao.com' },
    -- Bing
    { 0, 58, 'bing.com' },
    { 0, 58, 'bing.net' },
    -- Basecamp
    { 0, 563, 'basecamp.com' },
    -- Disney   
    { 0, 1515, 'disney.go.com' },
    -- Wordpress
    { 0, 506, 'wordpress.com' },
    { 0, 506, 'wp.com' },
    -- ShareThis
    { 0, 2635, 'sharethis.com' },
    -- Espn
    { 0, 1364, 'espn.go.com' },
    -- Flipboard 
    { 1, 1402, 'flipboard.com' },
    { 1, 1402, '*.flipboard.com' },
    -- TweetDeck 
    { 0, 1360, 'tweetdeck.com' },
    -- Chartbeat 
    { 0, 1460, 'chartbeat.net' },
    { 0, 1460, 'chartbeat.com' },
    -- Rotten Tomatoes
    { 0, 1803, 'rottentomatoes.com' },
    -- Xbox Live
    { 0, 921, 'xbox.com' },
    -- Microsoft
    { 0, 1423, 'microsoft.com' },
    -- Glympse
    { 1, 1808, 'glympse.com' },
    -- Microsoft Update
    { 0, 731, 'update.microsoft.com' },
    -- Backupgrid
    { 0, 1812, 'backupgrid.net' },
    -- Carbonite
    { 0, 1813, 'carbonite.com' },
    -- EdgeCast
    { 0, 1821, 'edgecastcdn.net' },
    -- iBackup
    { 0, 1814, 'ibackup.com' },
    -- jdistatic
    { 0, 1816, 'jdistatic.com' },
    -- JustCloud
    { 0, 1815, 'justcloud.com' },
    -- MyPCBackup
    { 0, 1817, 'mypcbackup.com' },
    -- SOS Online Backup
    { 0, 1818, 'sosonlinebackup.com' },
    -- SugarSync
    { 0, 1819, 'sugarsync.com' },
    -- zipcloud
    { 0, 1820, 'zipcloud.com' },
    -- Wii Shop Channel
    { 0, 1824, 'shop.wii.com' },
    -- Sourcefire
    { 0, 1398, 'sourcefire.com' },
    -- Vdio
    { 0, 1829, 'vdio.com' },
    { 0, 1829, 'vdio-a.akamaihd.net' },
    -- Redbox
    { 0, 1830, 'redbox.com' },
    { 0, 1830, 'redbox.ojrq.net' },
    { 0, 1830, 'redbox.tt.omtrdc.net' },
    -- Google Fiber
    { 0, 1831, 'fiber.google.com' },
    -- FIOS TV
    { 0, 1827, 'fiostv.verizon.net' },
}

function DetectorInit(detectorInstance)

    gDetector = detectorInstance;

    if gDetector.addSSLCertPattern then
        for i,v in ipairs(gSSLHostPatternList) do
            gDetector:addSSLCertPattern(v[1],v[2],v[3]);
        end
    end
    return gDetector;
end

function DetectorClean()
end

