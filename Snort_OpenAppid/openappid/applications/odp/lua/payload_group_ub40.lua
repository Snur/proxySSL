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
detection_name: Payload Group "UB40"
version: 3
description: Group of payload detectors.
bundle_description: $VAR1 = {
          'Indiegogo' => 'Online Fund raiser for new ideas/products.',
          'Creative Commons' => 'Non-profit organization to share your creativity legally without losing the credits.',
          'TIME.com' => 'Webportal for TIME Magazine.',
          'Merriam-Webster' => 'Online dictionary and thesaurus.',
          'Picasa' => 'Google picasa is an image organizer and image viewer for organizing and editing digital photos, plus an integrated photo-sharing website.',
          'Joomla' => 'Content Management System for building web sites.',
          'XBMC' => 'Open source media player.',
          'Coursera' => 'Educational site connecting people, offer online courses from top universities.',
          'MovieTickets.com' => 'Webportal for advanced movie ticketing, reviews and celebrity interviews.',
          'MailChimp' => 'Email service provider.',
          'Bluehost' => 'Web hosting portal.',
          'Lycos' => 'Search engine also offers email, web hosting and social networking.',
          'Zbigz' => 'Online BitTorrent Client.',
          'BBB' => 'Better Business Bureau - non-profit organization providing reliable business review.',
          'KVOA.com' => 'NBC-affiliated news channel for Tucson, Arizona.',
          'Google Translate' => 'Google translation service.',
          'Viddler' => 'Online Video hosting service.',
          'Tvigle' => 'Russian Video syndication website.',
          'OverBlog' => 'Platform to create blogs.',
          'HugeDomains.com' => 'Domain hosting service.',
          'Nest Thermostat' => 'Manufactures of sensor driven Thermostats which are self-learning and programmable.',
          'Gazprom Media' => 'Russian media group comprises television, radio, advertising, movie theaters and etc.',
          'Xfire' => 'Instant Messenger for gamers.',
          'J.P. Morgan' => 'Financial services arm of J.P. Morgan Chase & Co.',
          'Stanford University' => 'Official website for Stanford University, Educational Institute.',
          'Jimdo' => 'Portal for to creating web site/blog.',
          'NAI' => 'Network Advertising Initiative - association comprises of 3rd party ad companies and educate consumers with online advertising.',
          'Bandcamp' => 'Explore online music posted by independendent artist.',
          'AddToAny' => 'Social bookmarking and sharing platform.',
          'SFGate' => 'Bay area news portal.',
          'Websense' => 'Company which produces Cyber security related products.',
          'Phoca' => 'Software components useful for web design.',
          'CTV' => 'Canadian Television network.',
          'European Union' => 'Official website for European Union.',
          'Amazon Cloud Player' => 'Media player by Amazon facilitates listening music from cloud or download on the device.',
          'Skype' => 'A software application that allows users to chat, make voice/video calls, and transfer files over the Internet.',
          'CTV News' => 'News channel by CTV.',
          'Comcast Mail' => 'Email service provided by Comcast.',
          'eRecht24' => 'Russian Web portal for all legal related information.',
          'Google APIs' => 'Google Application Programming Interfaces that support the development of web applications that leverage Google services.',
          'OwnerIQ' => 'Advertisement site.',
          'Zattoo' => 'Internet protocol television.',
          'Library of Congress' => 'Online collection of American history memories and culture.',
          'Zulily' => 'Online shopping aimed for Moms with childerns apparel and home decor items.',
          'bitly' => 'Web portal for bookmarking and sharing links.',
          'ConnMan' => 'Plug-in for managing internet connectivity in the linux based embedded devices.',
          'Harvard University' => 'Official website for Harvard University, Educational Institute.',
          'GNU Project' => 'Aggregates free software for Unix-compatible system.',
          'TinyURL' => 'Shortens the long URL.',
          'phpBB' => 'PHP based open source bulletin board software.',
          'Parallels' => 'Cloud services enablement and virtual access.'
        };

--]]

require "DetectorCommon"


local DC = DetectorCommon

DetectorPackageInfo = {
    name =  "payload_group_bitters",
    proto =  DC.ipproto.tcp,
    client = {
        init =  'DetectorInit',
        clean =  'DetectorClean',
        minimum_matches =  1
    }
}

--serviceId, clientId, ClientType, PayloadId, PayloadType, hostPattern, pathPattern, schemePattern, queryPattern
gUrlPatternList = {

    -- nest
    { 0, 0, 0, 1247, 22, "nest.com", "/", "http:", "", 2749},
    -- CTV
    { 0, 0, 0, 1248, 22, "ctv.ca", "/", "http:", "", 2750},
    -- CTV News
    { 0, 0, 0, 1249, 22, "ctvnews.ca", "/", "http:", "", 2751},
    { 0, 0, 0, 1249, 22, "ctvnews.cookieless.ca", "/", "http:", "", 2751},
    -- Indiegogo
    { 0, 0, 0, 1250, 22, "indiegogo.com", "/", "http:", "", 2752},
    -- KVOA
    { 0, 0, 0, 1251, 22, "kvoa.com", "/", "http:", "", 2753},
    { 0, 0, 0, 1251, 22, "kvoaweather.cordillera.tv", "/", "http:", "", 2753},
    -- MailChimp
    { 0, 0, 0, 1252, 22, "mailchimp.com", "/", "http:", "", 2754},
    -- MovieTickets.com
    { 0, 0, 0, 1253, 31, "movietickets.com", "/", "http:", "", 2755},
    { 0, 0, 0, 1253, 31, "movieticketscom.122.2o7.net", "/", "http:", "", 2755},
    -- Google APIs
    { 0, 0, 0, 1254, 22, "googleapis.com", "/", "http:", "", 178},
    -- Skype
    { 0, 0, 0, 1255, 22, "skype.com", "/", "http:", "", 832},
    -- Comcast Mail
    { 0, 0, 0, 1256, 22, "mail.comcast.net", "/", "http:", "", 2756},
    -- Coursera
    { 0, 0, 0, 1257, 22, "coursera.org", "/", "http:", "", 2757},
    { 0, 0, 0, 1257, 22, "coursera.com", "/", "http:", "", 2757},
    -- XBMC
    { 0, 0, 0, 1258, 22, "xbmc.org", "/", "http:", "", 2758},
    -- Gazprom Media
    { 0, 0, 0, 1259, 22, "gazprom-media.com", "/", "http:", "", 2760},
    -- Tvigle
    { 0, 0, 0, 1260, 22, "tvigle.ru", "/", "http:", "", 2761},
    { 0, 0, 0, 1260, 22, "tvigle.com", "/", "http:", "", 2761},
    --  J.P. Morgan
    { 0, 0, 0, 1261, 22, "jpmorgan.com", "/", "http:", "", 2140},
    { 0, 0, 0, 1261, 22, "jpmm.com", "/", "http:", "", 2140},
    --  Bandcamp
    { 0, 0, 0, 1262, 22, "bandcamp.com", "/", "http:", "", 2762},
    { 0, 0, 0, 1262, 22, "bcbits.com", "/", "http:", "", 2762},
    --  Bluehost
    { 0, 0, 0, 1264, 22, "bluehostforum.com", "/", "http:", "", 2764},
    { 0, 0, 0, 1264, 22, "bluehost.com", "/", "http:", "", 2764},
    { 0, 0, 0, 1264, 22, "bluehost-cdn.com", "/", "http:", "", 2764},
    --  SFGate 
    { 0, 0, 0, 1265, 33, "sfgate.com", "/", "http:", "", 2765},
    --  Library of Congress
    { 0, 0, 0, 1266, 22, "loc.gov", "/", "http:", "", 2766},
    --  OverBlog
    { 0, 0, 0, 1267, 22, "over-blog.com", "/", "http:", "", 2767},
    { 0, 0, 0, 1267, 22, "over-blog.net", "/", "http:", "", 2767},
    { 0, 0, 0, 1267, 22, "overblog.com", "/", "http:", "", 2767},
    { 0, 0, 0, 1267, 22, "over-blog-kiwi.com", "/", "http:", "", 2767},
    --  BBB
    { 0, 0, 0, 1268, 22, "bbb.org", "/", "http:", "", 2768},
    { 0, 0, 0, 1268, 22, "bbb.com", "/", "http:", "", 2768},
    --  AddToAny
    { 0, 0, 0, 1269, 22, "addtoany.com", "/", "http:", "", 2769},
    --  TIME.com
    { 0, 0, 0, 1270, 22, "time.com", "/", "http:", "", 2770},
    { 0, 0, 0, 1270, 22, "timeinc.net", "/", "http:", "", 2770},
    --  Phoca
    { 0, 0, 0, 1271, 22, "phoca.cz", "/", "http:", "", 2771},
    --  phpBB
    { 0, 0, 0, 1272, 22, "phpbb.com", "/", "http:", "", 2772},
    --  HugeDomains.com
    { 0, 0, 0, 1273, 22, "hugedomains.com", "/", "http:", "", 2773},
    --  GNU Project
    { 0, 0, 0, 1274, 22, "gnu.org", "/", "http:", "", 2774},
    --  Lycos
    { 0, 0, 0, 1275, 22, "lycos.com", "/", "http:", "", 2775},
    --  ConnMan
    { 0, 0, 0, 1276, 22, "connman.net", "/", "http:", "", 2776},
    --  Creative Commons
    { 0, 0, 0, 1277, 22, "creativecommons.org", "/", "http:", "", 2777},
    --  NAI
    { 0, 0, 0, 1278, 22, "networkadvertising.org", "/", "http:", "", 2778},
    -- Joomla
    { 0, 0, 0, 1279, 22, "joomla.org", "/", "http:", "", 2779},
    { 0, 0, 0, 1279, 22, "joomlacode.org", "/", "http:", "", 2779},
    -- TinyURL
    { 0, 0, 0, 1280, 22, "tinyurl.com", "/", "http:", "", 2780},
    -- Jimdo
    { 0, 0, 0, 1281, 22, "jimdo.com", "/", "http:", "", 2782},
    -- Stanford University
    { 0, 0, 0, 1282, 22, "stanford.edu", "/", "http:", "", 2783},
    { 0, 0, 0, 1282, 22, "gostanford.edu", "/", "http:", "", 2783},
    { 0, 0, 0, 1282, 22, "gostanford.com", "/", "http:", "", 2783},
    -- Harvard University
    { 0, 0, 0, 1283, 22, "harvard.edu", "/", "http:", "", 2784},
    -- eRecht24
    { 0, 0, 0, 1284, 22, "e-recht24.de", "/", "http:", "", 2785},
    -- European Union
    { 0, 0, 0, 1285, 22, "europa.eu", "/", "http:", "", 2786},
    -- bitly
    { 0, 0, 0, 1286, 22, "bitly.com", "/", "http:", "", 2787},
    -- Viddler 
    { 0, 0, 0, 1287, 1, "viddler.com", "/", "http:", "", 2788},
    -- Merriam-Webster
    { 0, 0, 0, 1288, 22, "merriam-webster.com", "/", "http:", "", 2789},
    -- Websense
    { 0, 0, 0, 1289, 22, "websense.com", "/", "http:", "", 2790},
    { 0, 0, 0, 1289, 22, "websense.tt.omtrdc.net", "/", "http:", "", 2790},
    -- ZbigZ
    { 0, 0, 0, 1290, 22, "zbigz.com", "/", "http:", "", 2791},
    -- Zulily
    { 0, 0, 0, 1291, 22, "zulily.com", "/", "http:", "", 2792},
    -- Zattoo
    { 0, 0, 0, 1292, 22, "zattoo.com", "/", "http:", "", 2793},
    -- Xfire 
    { 0, 0, 0, 1293, 22, "xfire.com", "/", "http:", "", 2794},
    -- Picasa
    { 0, 0, 0, 1294, 22, "picasa.google.com", "/", "http:", "", 785},
    { 0, 0, 0, 1294, 22, "picasa.com", "/", "http:", "", 785},
    { 0, 0, 0, 1294, 22, "picasaweb.com", "/", "http:", "", 785},
    -- Google Translate
    { 0, 0, 0, 1295, 22, "translate.google.com", "/", "http:", "", 185},
    -- Parallels
    { 0, 0, 0, 1296, 22, "parallels.com", "/", "http:", "", 2802},
    -- OwnerIQ
    { 0, 0, 0, 1297, 22, "owneriq.com", "/", "http:", "", 2495},

}


function DetectorInit(detectorInstance)
-- ClientType, DHPSequence,  serviceId, clientId, PayloadId,  hostPattern, pathPattern, schemePattern, queryPattern
    gDetector = detectorInstance;

    -- nest 
    gDetector:addHttpPattern(2, 5, 0, 427, 19, 0, 0, 'Nest/', 2749);
    gDetector:addHttpPattern(2, 5, 0, 427, 19, 0, 0, 'AddLightness/', 2749);
    -- XBMC 
    gDetector:addHttpPattern(2, 5, 0, 428, 19, 0, 0, 'XBMC/', 2758);
    -- ConnMan
    gDetector:addHttpPattern(2, 5, 0, 432, 23, 0, 0, 'ConnMan/', 2776);
    -- Amazon Cloud Player
    gDetector:addHttpPattern(2, 5, 0, 433, 18, 0, 0, 'AmazonCloudPlayer/', 2781);
    -- Zattoo
    gDetector:addHttpPattern(2, 5, 0, 434, 19, 0, 0, 'Zattoo/', 2793);
 
    if gDetector.addAppUrl then
        for i,v in ipairs(gUrlPatternList) do
            gDetector:addAppUrl(v[1],v[2],v[3],v[4],v[5],v[6],v[7],v[8],v[9],v[10]);
        end
    end

    return gDetector;
end

function DetectorClean()
end

