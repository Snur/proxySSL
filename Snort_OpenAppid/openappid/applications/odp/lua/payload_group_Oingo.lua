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
detection_name: Payload Group "Oingo"
version: 9
description: Group of payload detectors.
bundle_description: $VAR1 = {
          'Eclipse' => 'Software Updates for Eclipse.',
          'SOS Online Backup' => 'Cloud-based backup service.',
          'Rotten Tomatoes' => 'Online information and reviews about new films.',
          'Cute Overload' => 'Pictures,videos and stories about Animals.',
          'Minecraft' => 'Online game.',
          'Glympse' => 'Mobile App to share the location with others.',
          'Podio' => 'Project Management software.',
          'Google Fiber' => 'Internet service provider by Google.',
          'Pop Salad' => 'Social gaming based on Celebrities.',
          'Redbox' => 'Online movie rental and video streaming.',
          'FiOS TV' => 'Verizon FiOS TV.',
          '2Leep' => 'Network for Bloggers.',
          'Vdio' => 'Watch video online.',
          'iBackup' => 'Cloud-based backup service.',
          'Pivotal Tracker' => 'Project management and collaborative software.',
          'LivePerson' => 'Online Marketing and Web analytics service provider.',
          'Feedly' => 'News Aggregator.',
          'PubNub' => 'Cloud-based system for apps that require data to be pushed in real time.',
          'People Of Walmart' => 'Website for Walmart customer posted photos.',
          'Bizrate' => 'Lists best deals for online shopping.',
          'H&R Block' => 'Tax service provider.',
          'Mention' => 'Site that will generate alerts and updates regarding topics you are interested in.',
          'TruuConfessions' => 'Online community for Confessions.',
          'JustCloud' => 'Cloud-based backup service.',
          'Carbonite' => 'Cloud-based backup service.',
          'King.com' => 'Web-based gaming.',
          'ZergNet' => 'Content aggregator for Sci-Fi Article.',
          'jdistatic' => 'Cloud-based backup service.',
          'Wii Shop Channel' => 'Nintendo Wii store for games and DLC.',
          'MyPCBackup' => 'Cloud-based backup service.',
          'Cheezburger' => 'Hang-out place for funny Photos and stories.',
          'SugarSync' => 'Cloud-based backup service.',
          'Amazon Ads System' => 'Amazon Ad services.',
          'MTv' => 'Official website for MTv.',
          'Mafiawars' => 'A multiplayer browser game created by Zynga.  It is on several social networking sites and on the iPhone.',
          'Constant Contact' => 'Online marketing service.',
          'WhereCoolThingsHappen' => 'Cool places and photos around the world.',
          'ZipCloud' => 'Cloud-based backup service.',
          'theCHIVE' => 'Funny photos and videos.',
          'Backupgrid' => 'Reseller of cloud backup / storage solutions.',
          'Nintendo WFC' => 'Nintendo Wi-Fi Connection, online multiplayer gaming service for Nintendo Wii and DS.',
          'Acrobat.com' => 'Adobe file transfer and PDF conversion site.'
        };

--]]

require "DetectorCommon"


local DC = DetectorCommon

DetectorPackageInfo = {
    name =  "payload_group_Oingo",
    proto =  DC.ipproto.tcp,
    client = {
        init =  'DetectorInit',
        clean =  'DetectorClean',
        minimum_matches =  1
    }
}

--serviceId, clientId, ClientType, PayloadId, PayloadType, hostPattern, pathPattern, schemePattern, queryPattern
gUrlPatternList = {

   --2Leep
    { 0, 0, 0, 889, 22, "2leep.com", "/", "http:", "", 1781},
   --Bizrate
    { 0, 0, 0, 890, 22, "bizrate.com", "/", "http:", "", 1782},
    { 0, 0, 0, 890, 22, "bizrate-images.com", "/", "http:", "", 1782},
   --People Of Walmart
    { 0, 0, 0, 891, 22, "peopleofwalmart.com", "/", "http:", "", 1783},
   --Cute Overload
    { 0, 0, 0, 892, 22, "cuteoverload.com", "/", "http:", "", 1784},
    { 0, 0, 0, 892, 22, "cuteoverload.files.wordpress.com", "/", "http:", "", 1784},
   --Cute Overload
    { 0, 0, 0, 893, 22, "cheezburger.com", "/", "http:", "", 1785},
    { 0, 0, 0, 893, 22, "cheezdev.com", "/", "http:", "", 1785},
    { 0, 0, 0, 893, 22, "chzbgr.com", "/", "http:", "", 1785},
   --Pop Salad
    { 0, 0, 0, 895, 22, "popsalad.com", "/", "http:", "", 1787},
   --theCHIVE
    { 0, 0, 0, 896, 22, "thechive.com", "/", "http:", "", 1788},
    { 0, 0, 0, 896, 22, "thethrottle.thechive.com", "/", "http:", "", 1788},
    { 0, 0, 0, 896, 22, "chivethethrottle.files.wordpress.com", "/", "http:", "", 1788},
    { 0, 0, 0, 896, 22, "shechive.files.wordpress.com", "/", "http:", "", 1788},
    { 0, 0, 0, 896, 22, "thebrigade.com", "/", "http:", "", 1788},
    { 0, 0, 0, 896, 22, "thebrigade.com", "/", "http:", "", 1788},
    { 0, 0, 0, 896, 22, "theberry.com", "/", "http:", "", 1788},
    { 0, 0, 0, 896, 22, "cdn.thechivemobile.com.edgesuite.net", "/", "http:", "", 1788},
   --TruuConfessions
    { 0, 0, 0, 897, 22, "truuconfessions.com", "/", "http:", "", 1789},
   --ZergNet
    { 0, 0, 0, 898, 22, "zergnet.com", "/", "http:", "", 1790},
   --WhereCoolThingsHappen
    { 0, 0, 0, 899, 22, "wherecoolthingshappen.com", "/", "http:", "", 1791},
   --H&R Block
    { 0, 0, 0, 900, 22, "hrblock.com", "/", "http:", "", 1792},
   --Constant Contact
    { 0, 0, 0, 901, 22, "constantcontact.com", "/", "http:", "", 1793},
   --Pivotal tracker 
    { 0, 0, 0, 902, 22, "pivotaltracker.com", "/", "http:", "", 1794},
   --Mafiawars
    { 0, 0, 0, 904, 22, "mafiawars.com", "/", "http:", "", 272},
    { 0, 0, 0, 904, 22, "mafiawars.zynga.com", "/", "http:", "", 272},
    { 0, 0, 0, 904, 22, "apps.facebook.com", "/inthemafia", "http:", "", 272},
   --Podio
    { 0, 0, 0, 905, 22, "podio.com", "/", "http:", "", 1796},
   --Acrobat.com
    { 0, 0, 0, 906, 22, "acrobat.com", "/", "http:", "", 1322},
   --Eclipse
    { 0, 0, 0, 907, 22, "eclipse.org", "/", "http:", "", 1413},
   --LivePerson
    { 0, 0, 0, 908, 22, "liveperson.com", "/", "http:", "", 1797},
    { 0, 0, 0, 908, 22, "liveperson.net", "/", "http:", "", 1797},
   --Mention
    { 0, 0, 0, 909, 22, "mention.net", "/", "http:", "", 1798},
   --Feedly 
    { 0, 0, 0, 910, 22, "feedly.com", "/", "http:", "", 1799},
   --Minecraft
    { 0, 0, 0, 911, 22, "minecraft.net", "/", "http:", "", 1802},
   --Rotten Tomatoes
    { 0, 0, 0, 912, 22, "rottentomatoes.com", "/", "http:", "", 1803},
    { 0, 0, 0, 912, 22, "rottentomatoescdn.com", "/", "http:", "", 1803},
   --Amazon Ads System
    { 0, 0, 0, 913, 22, "amazon-adsystem.com", "/", "http:", "", 1804},
   --MTv
    { 0, 0, 0, 914, 22, "mtv.com", "/", "http:", "", 1805},
    { 0, 0, 0, 914, 22, "mtvnimages.com", "/", "http:", "", 1805},
    { 0, 0, 0, 914, 22, "mtvnservices.com", "/", "http:", "", 1805},
    { 0, 0, 0, 914, 22, "mtvn.demdex.net", "/", "http:", "", 1805},
   --Glympse
    { 0, 0, 0, 916, 22, "glympse.com", "/", "http:", "", 1808},
    -- Backupgrid
    { 0, 0, 0, 919, 9, "backupgrid.net", "/", "http:", "", 1812},
    -- Carbonite
    { 0, 0, 0, 920, 9, "carbonite.com", "/", "http:", "", 1813},
    -- FIOS TV
    { 0, 0, 0, 932, 13, "fiostv.verizon.net", "/", "http:", "", 1827},
    -- iBackup
    { 0, 0, 0, 924, 9, "ibackup.com", "/", "http:", "", 1814},
    -- jdistatic
    { 0, 0, 0, 922, 9, "jdistatic.com", "/", "http:", "", 1816},
    -- JustCloud
    { 0, 0, 0, 921, 9, "justcloud.com", "/", "http:", "", 1815},
    -- MyPCBackup
    { 0, 0, 0, 923, 9, "mypcbackup.com", "/", "http:", "", 1817},
    -- PubNub
    { 0, 0, 0, 927, 16, "pubnub.com", "/", "http:", "", 1822},
    -- SOS Online Backup
    { 0, 0, 0, 936, 9, "sosonlinebackup.com", "/", "http:", "", 1818},
    -- SugarSync
    { 0, 0, 0, 925, 9, "sugarsync.com", "/", "http:", "", 1819},
    -- ZipCloud
    { 0, 0, 0, 926, 9, "zipcloud.com", "/", "http:", "", 1820},
    -- Wii Shop Channel
    { 0, 0, 0, 929, 5, "shop.wii.com", "/", "http:", "", 1824},
    -- Wii News Channel
--    { 0, 0, 0, 930, 5, "news.wapp.wii.com", "/", "http:", "", 1825},
    -- Mintendo WFC
    { 0, 0, 0, 931, 5, "nintendowifi.net", "/", "http:", "", 1826},
   --Vdio 
    { 0, 0, 0, 933, 22, "vdio.com", "/", "http:", "", 1829},
   --Redbox
    { 0, 0, 0, 934, 22, "redbox.com", "/", "http:", "", 1830},
    { 0, 0, 0, 934, 22, "redbox.tt.omtrdc.net", "/", "http:", "", 1830},
   --Google Fiber
    { 0, 0, 0, 935, 22, "fiber.google.com", "/", "http:", "", 1831},
   --Midasplayer 
    { 0, 0, 0, 937, 20, "midasplayer.com", "/", "http:", "", 1599},
    { 0, 0, 0, 937, 20, "king.com", "/", "http:", "", 1599},
}


function DetectorInit(detectorInstance)

    gDetector = detectorInstance;

    gDetector:addHttpPattern(2, 5, 0, 236, 21, 0, 0, 'CarboniteService', 1813, 1);
    gDetector:addHttpPattern(2, 5, 0, 238, 19, 0, 0, 'FiOS-Mercury', 1827); 
    --gDetector:addHttpPattern(2, 5, 0, 237, 19, 0, 0, 'WiiConnect24', 1823);
    gDetector:addHttpPattern(2, 5, 0, 296, 19, 0, 0, 'Chive/', 1788);

    if gDetector.addAppUrl then
        for i,v in ipairs(gUrlPatternList) do
            gDetector:addAppUrl(v[1],v[2],v[3],v[4],v[5],v[6],v[7],v[8],v[9],v[10]);
        end
    end

    return gDetector;
end

function DetectorClean()
end

