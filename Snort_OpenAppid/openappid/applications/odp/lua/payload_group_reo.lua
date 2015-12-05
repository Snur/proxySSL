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
detection_name: Payload Group "REO Speedwagon"
version: 14
description: Group of payload detectors.
bundle_description: $VAR1 = {
          'LiteCoin' => 'A cryptopgraphic currency similar to BitCoin which requires lighter-weight resources to mine.',
          'Wimbledon' => 'Tennis related website.',
          'Jetsetz' => 'Travel booking and price comparison site.',
          'Al Jazeera' => 'News network based in the Arab world.',
          'SmugMug' => 'Photo sharing website.',
          'Motorola' => 'Manufacturer of mobile devices and telephony equipment.',
          'Vlingo' => 'Voice recognition and processing app for smartphones.',
          'CheapOAir' => 'Travel booking and price comparison site.',
          'Liberty Mutual' => 'Insurance company.',
          'Telenav' => 'Smartphone GPS app.',
          'Red Hat' => 'Open-source software products.',
          'Gateway' => 'Manufacturer and retailer of PCs.',
          'Djpod' => 'A suite of tools for podcasting.',
          'The Onion' => 'Online humor and news satire site.',
          'The Daily Beast' => 'American news reporting and opinion website.',
          'Allstate' => 'Insurance company.',
          'Toshiba' => 'Manufacturer of computers and electronics.',
          'Show My Weather' => 'Weather forecast site.',
          'Microsoft AutoUpdate' => 'Automatic software updates for Microsoft products.',
          'MyOnlineArcade' => 'Free web based games.',
          'Bitbucket' => 'Source code hosting site.',
          'Nuance' => 'Airline services and travel planner.',
          'The Free Dictionary' => 'Online dictionary aggregator.',
          'Channel Intelligence' => 'Advertising platform.',
          'Detroit Free Press' => 'News local to Detroit metropolitan area.',
          'BackWeb' => 'Software that enables automatic background software downloads and installations.',
          'Ensighten' => 'Tag-based advertising platform.',
          'PerfectIBE' => 'An air travel booking consolidation engine.',
          'Reduxmedia' => 'Advertisement site.',
          'PNC Bank' => 'Banking and Financial services.',
          'Zombo.com' => 'Website where you can do anything.',
          'Progressive' => 'Insurance company.',
          'StudentUniverse' => 'Travel booking and price comparison site for students.',
          'jJcast' => 'Video management and streaming platform.',
          'Adblade' => 'Advertising platform.',
          'MLive' => 'News local to the American state of Michigan.',
          'wimp.com' => 'Site that provides links to viral videos.',
          'iFunny' => 'Aggregator of humorous and interesting memes.',
          'News Distribution Network' => 'News media content delivery network.',
          'BITS' => 'Background Intelligent Transfer Service. A file transfer protocol for Microsoft Updates.',
          'ooVoo' => 'Video chat and instant messaging.',
          'Zendesk' => 'Customer support web application.',
          'MobiTV' => 'A content aggregation company focusing on video.',
          'Yahoo! Calendar' => 'Yahoo! online calendar app.',
          'Crunchyroll' => 'Video streaming site specializing in Japanese animation.',
          'AMD' => 'A manufacturer or PC chipsets.',
          'Viki' => 'Watch and upload movies, TV shows and music online.',
          'NovaMov' => 'Watch and uploads videos online.',
          'Google App Engine' => 'Google App Engine lets you run your web applications using Google\'s infrastructure.',
          'NBA' => 'Official website for the National Basketball League, an American sports organization.',
          'Yammer' => 'Enterprise social networking site.',
          'Auditude' => 'Video advertising application.',
          'Geico' => 'Insurance company.',
          'State Farm' => 'Insurance company.',
          'Path' => 'Private instant messaging.',
          'KakaoTalk' => 'Mobile messaging for smartphones.',
          'Funny or Die' => 'Site that presents humorous videos and media.',
          'Media Hub' => 'Samsung video store.',
          'Putlocker' => 'Online file hosting service.',
          'Samsung' => 'Electronics retail site.',
          'beRecruited' => 'College athletic social networking site.',
          'Intel' => 'Computer chip builder.',
          'CollegeHumor' => 'Site that presents humorous videos and media.',
          'United Airlines' => 'Online Flight reservation from United Airlines.',
          'Blackberry sites' => 'Website for RIM\'s smartphone.',
          'TextNow' => 'Instant text and voice services.',
          'FedEx' => 'Courier delivery services.',
          'Eventbrite' => 'Event organization and invite site.',
          'Maxymiser' => 'Advertising and marketing platform.',
          'American Airlines' => 'Airline services and travel planner.',
          'Nvidia' => 'Video chipset manufacturer.',
          'TV Guide' => 'Listings and schedules for television programming.',
          'Michigan Radio' => 'Public radio serving the American state of Michigan.',
          'De Telegraaf' => 'Dutch daily newspaper site.',
          'Times Union' => 'News local to Albany, New York.',
          'WeatherLink' => 'Site for networking of internet-capable weather devices.',
          'Asus' => 'Manufacturer of PCs and PC components.',
          'USAA' => 'Insurance company.',
          'Acer' => 'Manufacturer of PCs and laptops.',
          'Microsoft download' => 'Software downloads from Microsoft.',
          'GVFS' => 'GNOME desktop virtual filesystem.'
        };

--]]

require "DetectorCommon"


local DC = DetectorCommon

DetectorPackageInfo = {
    name =  "payload_group_reo",
    proto =  DC.ipproto.tcp,
    client = {
        init =  'DetectorInit',
        clean =  'DetectorClean',
        minimum_matches =  1
    }
}

--serviceId, clientId, ClientType, PayloadId, PayloadType, hostPattern, pathPattern, schemePattern, queryPattern
gUrlPatternList = {

    -- Adblade
    { 0, 0, 0, 1027, 15, "adblade.com", "/", "http:", "", 2116},
    -- ATI Technologies
    -- { 0, 0, 0, 1028, 27, "ati.com", "/", "http:", "", 2117},
    -- BackWeb
    { 0, 0, 0, 1029, 6, "backweb.com", "/", "http:", "", 2118},
    -- Blackberry
    { 0, 0, 0, 1030, 27, "blackberry.com", "/", "http:", "", 2119},
    -- Djpod
    { 0, 0, 0, 1031, 3, "djpod.com", "/", "http:", "", 2120},
    -- Microsoft download
    { 0, 0, 0, 1032, 6, "download.microsoft.com", "/", "http:", "", 2121},
    { 0, 0, 0, 1032, 6, "microsoft.com", "/downloads", "http:", "", 2121},
    { 0, 0, 0, 1032, 6, "microsoft.com", "/en-us/downloads", "http:", "", 2121},
    -- MyOnlineArcade
    { 0, 0, 0, 1033, 20, "myonlinearcade.com", "/", "http:", "", 2123},
    -- Putlocker
    { 0 ,0, 0, 1034, 9, "putlocker.com", "/", "http:", "", 1224},
    -- SmugMug
    { 0, 0, 0, 1035, 9, "smugmug.com", "/", "http:", "", 2124},
    { 0, 0, 0, 1035, 9, "smugsmug.com", "/", "http:", "", 2124},
    -- Springpad
    -- { 0, 0, 0, 1036, 14, "springpad.com", "/", "http:", "", 2125}, 
    -- USAA
    { 0, 0, 0, 1037, 39, "usaa.com", "/", "http:", "", 2126},
    -- wimp.com
    { 0, 0, 0, 1038, 14, "wimp.com", "/", "http:", "", 2127},
    -- Zendesk
    { 0, 0, 0, 1039, 11, "zendesk.com", "/", "http:", "", 2128},
    -- Auditude
    { 0, 0, 0, 1040, 15, "auditude.com", "/", "http:", "", 2129},
    -- Show My Weather
    { 0, 0, 0, 1041, 33, "showmyweather.com", "/", "http:", "", 2130},
    -- MobiTV
    { 0, 0, 0, 1042, 13, "mobitv.com", "/", "http:", "", 2131},
    -- TV Guide
    { 0, 0, 0, 1043, 33, "tvguide.com", "/", "http:", "", 2132},
    -- iFunny
    { 0, 0, 0, 1044, 33, "ifunny.com", "/", "http:", "", 2133},
    -- Telenav
    { 0, 0, 0, 1045, 37, "telenav.com", "/", "http:", "", 2134},
    -- Samsung
    { 0, 0, 0, 1046, 27, "samsung.com", "/", "http:", "", 1357},
    { 0, 0, 0, 1046, 27, "samsungapps.com", "/", "http:", "", 1357},
    -- Vlingo
    { 0, 0, 0, 1047, 27, "vlingo.com", "/", "http:", "", 2135},
    -- Media Hub
    { 0, 0, 0, 1048, 13, "samsungmediahub.net", "/", "http:", "", 2136},
    -- CheapOAir
    { 0, 0, 0, 1049, 37, "cheapoair.com", "/", "http:", "", 2137},
    -- Crunchyroll
    { 0, 0, 0, 1050, 13, "crunchyroll.com", "/", "http:", "", 2138},
    -- Eventbrite
    { 0, 0, 0, 1051, 5, "eventbrite.com", "/", "http:", "", 2139},
    -- Google App Engine
    { 0, 0, 0, 1052, 19, "appengine.google.com", "/", "http:", "", 179},
    -- Path
    { 0, 0, 0, 1053, 10, "path.com", "/", "http:", "", 2142},
    -- Intel
    { 0, 0, 0, 1054, 27, "intel.com", "/", "http:", "", 2143},
    -- AMD
    { 0, 0, 0, 1055, 27, "amd.com", "/", "http:", "", 2144},
    -- Asus
    { 0, 0, 0, 1056, 27, "asus.com", "/", "http:", "", 2145},
    -- Acer
    { 0, 0, 0, 1057, 27, "acer.com", "/", "http:", "", 2146},
    -- gateway
    { 0, 0, 0, 1058, 27, "gateway.com", "/", "http:", "", 2147},
    -- Toshiba
    { 0, 0, 0, 1059, 27, "toshiba.com", "/", "http:", "", 2148},
    { 0, 0, 0, 1059, 27, "toshibadirect.com", "/", "http:", "", 2148},
    -- Motorola
    { 0, 0, 0, 1060, 27, "motorola.com", "/", "http:", "", 2149},
    -- Nvidia
    { 0, 0, 0, 1061, 27, "nvidia.com", "/", "http:", "", 2150},
    -- Channel Intellignce
    { 0, 0, 0, 1062, 15, "channelintelligence.com", "/", "http:", "", 2151},
    -- Progressive, Inc.
    { 0, 0, 0, 1063, 39, "progressive.com", "/", "http:", "", 2152},
    -- State Farm
    { 0, 0, 0, 1064, 39, "statefarm.com", "/", "http:", "", 2153},
    -- Allstate
    { 0, 0, 0, 1065, 39, "allstate.com", "/", "http:", "", 2154},
    -- Geico
    { 0, 0, 0, 1066, 39, "geico.com", "/", "http:", "", 2155},
    -- Liberty Mutual
    { 0, 0, 0, 1067, 39, "libertymutual.com", "/", "http:", "", 2156},    
    { 0, 0, 0, 1067, 39, "libertymutual-cdn.com", "/", "http:", "", 2156},
    -- Ensighten
    { 0, 0, 0, 1068, 15, "ensighten.com", "/", "http:", "", 2157},
    -- Maxymiser
    { 0, 0, 0, 1069, 15, "maxymiser.net", "/", "http:", "", 2158},
    -- News Distribution Network
    { 0, 0, 0, 1070, 13, "newsinc.com", "/", "http:", "", 2159},
    -- KakaoTalk
    { 0, 0, 0, 1071, 10, "kakao.com", "/", "http:", "", 1405},
    -- Jetsetz
    { 0, 0, 0, 1072, 37, "jetsetz.com", "/", "http:", "", 2160},
    -- StudentUniverse
    { 0, 0, 0, 1073, 37, "studentuniverse.com", "/", "http:", "", 2161},
    -- PerfectIBE
    { 0, 0, 0, 1074, 37, "perfectibe.com", "/", "http:", "", 2162},
    -- Funny or Die
    { 0, 0, 0, 1075, 33, "funnyordie.com", "/", "http:", "", 2163},
    { 0, 0, 0, 1075, 33, "ordienetworks.com", "/", "http:", "", 2163},
    { 0, 0, 0, 1075, 33, "fod4.com", "/", "http:", "", 2163},
    -- CollegeHumor
    { 0, 0, 0, 1076, 33, "collegehumor.com", "/", "http:", "", 2164},
    { 0, 0, 0, 1076, 33, "collegehumor.cvcdn.com", "/", "http:", "", 2164},
    -- Zombo.com
    { 0, 0, 0, 1077, 20, "zombo.com", "/", "http:", "", 2165},
   --NBA   
    { 0, 0, 0, 1078, 22, "cdn.turner.com", "/nba", "http:", "", 1939},
    { 0, 0, 0, 1078, 22, "nba.com", "/", "http:", "", 1939},
    { 0, 0, 0, 1078, 22, "nba.co.in", "/", "http:", "", 1939},
    { 0, 0, 0, 1078, 22, "nba.ca", "/", "http:", "", 1939},
   --NovaMov
    { 0, 0, 0, 1079, 22, "novamov.us", "/", "http:", "", 2170},
    { 0, 0, 0, 1079, 22, "novamov.com", "/", "http:", "", 2170},
   --Viki
    { 0, 0, 0, 1080, 22, "viki.com", "/", "http:", "", 2171},
    { 0, 0, 0, 1080, 22, "viki.io", "/", "http:", "", 2171},
    { 0, 0, 0, 1080, 22, "vikiassets.com", "/", "http:", "", 2171},
   --PNC Bank
    { 0, 0, 0, 1081, 22, "pnc.com", "/", "http:", "", 2172},
   --Red Hat
    { 0, 0, 0, 1082, 22, "redhat.com", "/", "http:", "", 2173},
   --Unite Airlines
    { 0, 0, 0, 1083, 22, "united.com", "/", "http:", "", 2174},
   --Sharebeast.com
    --{ 0, 0, 0, 1084, 22, "sharebeast.com", "/", "http:", "", 2175},
   --TextNow 
    { 0, 0, 0, 1085, 22, "textnow.com", "/", "http:", "", 2176},
   --FedEx 
    { 0, 0, 0, 1086, 22, "fedex.com", "/", "http:", "", 2177},
    { 0, 0, 0, 1086, 22, "fedex.tt.omtrdc.net", "/", "http:", "", 2177},
   --American Airlines
    { 0, 0, 0, 1087, 22, "aa.com", "/", "http:", "", 2178},
    { 0, 0, 0, 1087, 22, "aavacations.com", "/", "http:", "", 2178},
    { 0, 0, 0, 1087, 22, "aa.cruises.com", "/", "http:", "", 2178},
   --Nuance
    { 0, 0, 0, 1088, 22, "nuance.com", "/", "http:", "", 2179},
    { 0, 0, 0, 1088, 22, "nuance.sp1.convertro.com", "/", "http:", "", 2179},
    { 0, 0, 0, 1088, 22, "tiqcdn.com", "/utag/driv/nuance/ ", "http:", "", 2179},
   --LiteCoin
    { 0, 0, 0, 1008, 22, "ltc.kattare.com", "/", "http:", "", 2084},
    -- Al Jazeera
    { 0, 0, 0, 1089, 33, "aljazeera.com", "/", "http:", "", 2180},
    { 0, 0, 0, 1089, 33, "aljazeera.net", "/", "http:", "", 2180},
    -- Winbledon
    { 0, 0, 0, 1090, 29, "wimbledon.com", "/", "http:", "", 2181}, 
    -- Mlive
    { 0, 0, 0, 1091, 33, "mlive.com", "/", "http:", "", 2182},
    -- Times Union
    { 0, 0, 0, 1092, 33, "timesunion.com", "/", "http:", "", 2183},
    -- beRecruited
    { 0, 0, 0, 1093, 5, "berecruited.com", "/", "http:", "", 2184},
    -- Detroit Free Press
    { 0, 0, 0, 1095, 33, "freep.com", "/", "http:", "", 2186},
    -- jJcast
    { 0, 0, 0, 1096, 13, "jjcast.com", "/", "http:", "", 2187},
    -- Michigan Radio
    { 0, 0, 0, 1097, 33, "michiganradio.org", "/", "http:", "", 2188},
    -- De Telegraaf
    { 0, 0, 0, 1098, 33, "telegraaf.nl", "/", "http:", "", 2189},
    -- ooVoo
    { 0, 0, 0, 1099, 10, "oovoo.com", "/", "http:", "", 2190},
    -- The Daily Beast
    { 0, 0, 0, 1100, 33, "thedailybeast.com", "/", "http:", "", 2191},
    -- The Free Dictionary
    { 0, 0, 0, 1101, 12, "thefreedictionary.com", "/", "http:", "", 2192},
    -- The Onion
    { 0, 0, 0, 1102, 20, "theonion.com", "/", "http:", "", 2193},
    -- WeatherLink
    { 0, 0, 0, 1103, 16, "weatherlink.com", "/", "http:", "", 2195}, 
    -- Yahoo! Calendar
    { 0, 0, 0, 1104, 12, "calendar.yahoo.com", "/", "http:", "", 2196},
    -- Bitbucket
    { 0, 0, 0, 1094, 12, "bitbucket.org", "/", "http:", "", 2185},
    -- Yammer
    { 0, 0, 0, 1106, 5, "yammer.com", "/", "http:", "", 2198},
    -- Reduxmedia
    { 0, 0, 0, 1107, 15, "reduxmedia.com", "/", "http:", "", 1955},
    { 0, 0, 0, 1107, 15, "reduxmediagroup.com", "/", "http:", "", 1955},
}


function DetectorInit(detectorInstance)

    gDetector = detectorInstance;

    -- Microsoft AutoUpdater
    gDetector:addHttpPattern(2, 5, 0, 279, 23, 0, 0, 'Microsoft AutoUpdate', 2122);
    -- MS BITS
    gDetector:addHttpPattern(2, 5, 0, 280, 21, 0 ,0, 'Microsoft BITS', 60);
    -- GVFS
    gDetector:addHttpPattern(2, 5, 0, 281, 23, 0 ,0, 'gvfs', 2197);
    -- Yammer
    gDetector:addHttpPattern(2, 5, 0, 282, 24, 0, 0, 'Yammer', 2198);
    -- Google App Engine
    gDetector:addHttpPattern(2, 5, 0, 326, 23, 0, 0, 'AppEngine-Google', 179);

    if gDetector.addAppUrl then
        for i,v in ipairs(gUrlPatternList) do
            gDetector:addAppUrl(v[1],v[2],v[3],v[4],v[5],v[6],v[7],v[8],v[9],v[10]);
        end
    end

    return gDetector;
end

function DetectorClean()
end

