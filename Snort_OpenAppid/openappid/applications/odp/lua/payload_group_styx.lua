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
detection_name: Payload Group "Styx"
version: 12
description: Group of payload detectors.
bundle_description: $VAR1 = {
          'ksfetch' => 'Google update app. Runs in the background and checks latest version of installed Google apps.',
          'Kraken' => 'A web crawler.',
          'HLN' => 'CNN\'s Headline News website.',
          'GSA Crawler' => 'Google Search Appliance, a webcrawler.',
          'MS Office Protocol Discovery' => 'MS Office WebDAV detection.',
          'WordReference.com' => 'Online dictionaries, translator and word games.',
          'CNET' => 'Tech and gadget related news, reviews, and shopping.',
          'AudioDocumentary.org' => 'Online archive of public-domain audio and video documentaries.',
          'Postini' => 'A Google product that provides email security and archiving.',
          'simple-get' => 'Extension to the Chromium browser that downloads HTTP.',
          'Quick Look' => 'OSX file preview agent.',
          'The Hollywood Reporter' => 'News related to the entertainment industry.',
          'reCAPTCHA' => 'An improved captcha system.',
          'Googlebot' => 'Google\'s web crawler.',
          'Nike' => 'Shoe and sports apparel manufacturer.',
          'Microsoft Powerpoint' => 'Microsoft Powerpoint.',
          'Microsoft NCSI' => 'Microsoft Network Awareness component. Collects information about the PC\'s network connection for us by the operating system and applications.',
          'Malware Defense System' => 'Anti-virus software.',
          'Android Music' => 'Google play music streaming and downloads.',
          'ndgsa-crawler' => 'A web crawler.',
          'NVIDIA Update' => 'Software updates for NVIDIA chipsets.',
          'Abonti' => 'Web crawler.',
          'Microsoft WNS' => 'Windows push Notification Service, an API that allows for updates to be sent from cloud-based services.',
          'SymantecUpdates' => 'Software updates for Symantec.',
          'Adap.tv' => 'Video advertising service.',
          'WeTransfer' => 'Online file transferring platform.',
          'Googlebot Image Search' => 'Google\'s spider that searches the web for images.',
          'Moodlebot' => 'A bot used by Moodle, which is an opensource online education framework.',
          'Drugs.com' => 'Online pharmacy.',
          'Yandex Bot' => 'Web crawler of Yandex.',
          'Dropbox' => 'Cloud based file storage.',
          'Yahoo! Slurp' => 'Yahoo! web-crawler that obtains content for Yahoo! Search engine.',
          'MJ12 Bot' => 'Web crawler of Majestic-12.',
          'USA Today' => 'Website for newspaper USA Today.',
          'Oracle sites' => 'The website for Oracle.',
          'Microsoft Access' => 'Microsoft desktop database application.',
          'YouTube' => 'A video-sharing website on which users can upload, share, and view videos.',
          'AppleCoreMedia' => 'Application used by Mobile Safari to handle media streams.',
          'Microsoft CryptoAPI' => 'Crypto based API included with Windows Operating system.',
          'Blekko' => 'Search engine based on categories.',
          'iFunny' => 'Aggregator of humorous and interesting memes.',
          'Zootool' => 'Bookmarking app with visual images.',
          'Wood TV8' => 'Michigan TV news network.',
          'MS Office Existence Discovery' => 'MS Office HTTP download.',
          'Pandora' => 'Audio streaming.',
          'Microsoft Excel' => 'Microsoft online spreadsheet software.',
          'Okta' => 'An enterprise service that manages login credentials in the cloud.',
          'Libsyn' => 'Podcast hosting services.',
          'Apple Update' => 'Apple software updating tool.',
          'PSP Activity Agent' => 'PSP social networking client.',
          'Storify' => 'Collect media, create stories and publish on the any social network.',
          'Campfire' => 'Business-focused group messaging and enterprise social networking.',
          'Rainmeter WebParser' => 'Web page reading functionality of Rainmeter, a desktop customization tool.',
          'Collider' => 'Movie/Television news, reviews and trailers.',
          'WDT' => 'Weather Decision Technologies, a company that provides weather nowcasting apps.',
          'Readability' => 'A browser plugin and mobile app that converts articles to a cleaner format.',
          'Voilabot' => 'A web crawler.',
          'App.net' => 'A site with many apps for various platforms.',
          'Investopedia' => 'A wiki focused on information related to investments.',
          'FFFFOUND!' => 'Site for sharing found images from around the web.',
          'PubSubHubbub' => 'A distributed publish/subscribe protocol.',
          'Twitterrific' => 'Twitter client.',
          'Outlook' => 'Microsoft email service.',
          'Sogou web spider' => 'A web crawler, associated with Chinese web portal, Sogou.',
          'MagPie' => 'A web crawler.',
          'PSP Community Agent' => 'PSP social networking client.',
          'Zapier' => 'Automatically sync the web apps.',
          'Apple Mail' => 'Apple email client.',
          'Google Update' => 'A client that handles automated updates of Google apps.',
          'Windows Phone Browser' => 'Web browser for devices running Microsoft\'s Windows mobile OS.',
          'USPS' => 'US Postal Service website.',
          'QuickTime' => 'Apple\'s proprietary multimedia format.',
          'Sony' => 'Official website for Sony Corporation.',
          'The Seattle Times' => 'Newspaper with a focus on the Seattle metro area.',
          'CNET TV' => 'Videos on tech and gadget related website.',
          'PS3 Community Agent' => 'PS3 social networking client.',
          'JetSetMe' => 'A mobile application that allows tracking of the user\'s movements around the globe.',
          'Microsoft Word' => 'Microsoft Word.',
          'SpeedRunsLive' => 'Online gaming.',
          'Connexion client' => 'Desktop client for the OCLC.',
          'Feedfetcher' => 'Google app that grabs RSS and Atom feeds.'
        };

--]]

require "DetectorCommon"


local DC = DetectorCommon

DetectorPackageInfo = {
    name =  "payload_group_styx",
    proto =  DC.ipproto.tcp,
    client = {
        init =  'DetectorInit',
        clean =  'DetectorClean',
        minimum_matches =  1
    }
}

--serviceId, clientId, ClientType, PayloadId, PayloadType, hostPattern, pathPattern, schemePattern, queryPattern
gUrlPatternList = {

    -- USA Today
    { 0, 0, 0, 1108, 33, "usatoday.com", "/", "http:", "", 1335},
    -- WDT
    { 0, 0, 0, 1125, 16, "wdtinc.com", "/", "http:", "", 2240}, 
    -- Twitteriffic
    { 0, 0, 0, 1126, 5, "twitterrific.com", "/", "http:", "", 2241},
    -- usps
    { 0, 0, 0, 1127, 24, "usps.com", "/", "http:", "", 1601},
    { 0, 0, 0, 1127, 24, "uspspostalone.com", "/", "http:", "", 1601},
    -- The Seattle Times
    { 0, 0, 0, 1128, 33, "seattletimes.com", "/", "http:", "", 2242},
    -- Readability
    { 0, 0, 0, 1129, 7, "readability.com", "/", "http:", "", 2243},
    -- Postini
    { 0, 0, 0, 1130, 4, "postini.com", "/", "http:", "", 2244},
    -- Oracle sites
    { 0, 0, 0, 1131, 15, "oracle.com", "/", "http:", "", 2245},
    -- Okta
    { 0, 0, 0, 1132, 11, "okta.com", "/", "http:", "", 2246},
    -- Nike
    { 0, 0, 0, 1133, 29, "nike.com", "/", "http:", "", 2247},
    -- Libsyn
    { 0, 0, 0, 1134, 3, "libsyn.com", "/", "http:", "", 2248},
    -- JetSetMe
    { 0, 0, 0, 1135, 16, "jetsetme.com", "/", "http:", "", 2249},
    -- Investopedia
    { 0, 0, 0, 1136, 13, "investopedia.com", "/", "http:", "", 2250},
    -- The Hollywood Reporter
    { 0, 0, 0, 1137, 33, "hollywoodreporter.com", "/", "http:", "", 2251},
    -- HLN
    { 0, 0, 0, 1138, 33, "hlntv.com", "/", "http:", "", 2254},
    -- FFFFOUND!
    { 0, 0, 0, 1139, 14, "ffffound.com", "/", "http:", "", 2255},
    -- CNET 
    { 0, 0, 0, 1140, 27, "cnet.com", "/", "http:", "", 1170},
    -- CNET TV
    { 0, 0, 0, 1141, 27, "cnettv.cnet.com", "/", "http:", "", 2256},
    -- WordReference.com
    { 0, 0, 0, 1111, 7, "wordreference.com", "/", "http:", "", 2208},
    -- Zapier
    { 0, 0, 0, 1109, 22, "zapier.com", "/", "http:", "", 2206},
    -- Collider
    { 0, 0, 0, 1110, 22, "collider.com", "/", "http:", "", 2207},
    -- WordReference.com
    { 0, 0, 0, 1111, 22, "wordreference.com", "/", "http:", "", 2208},
    -- Blekko
    { 0, 0, 0, 1116, 22, "blekko.com", "/", "http:", "", 2223},
    -- Sony
    { 0, 0, 0, 1120, 22, "sony.com", "/", "http:", "", 2234},
    -- Zootool
    { 0, 0, 0, 1121, 22, "zootool.com", "/", "http:", "", 2235},
    -- WeTransfer
    { 0, 0, 0, 1122, 9, "wetransfer.com", "/", "http:", "", 2236},
    -- Storify 
    { 0, 0, 0, 1123, 9, "storify.com", "/", "http:", "", 2237},
    -- SpeedRunsLive
    { 0, 0, 0, 1124, 20, "speedrunslive.com", "/", "http:", "", 2238},
    -- Adap.tv
    { 0, 0, 0, 1142, 15, "adap.tv", "/", "http:", "", 2261},
    -- drugs.com
    { 0, 0, 0, 1143, 30, "drugs.com", "/", "http:", "", 2269},
    -- Campfire
    { 0, 0, 0, 1144, 5, "campfirenow.com", "/", "http:", "", 2270},
    -- audiodocumentary.org
    { 0, 0, 0, 1145, 13, "audiodocumentary.org", "/", "http:", "", 2271},
    -- Wood TV8
    { 0, 0, 0, 1146, 33, "woodtv.com", "/", "http:", "", 2285},
    -- App.net
    { 0, 0, 0, 1147, 5, "app.net", "/", "http:", "", 2286},
    -- Microsoft NCSI
    { 0, 0, 0, 1148, 11, "msftncsi.com", "/", "http:", "", 2289}, 
    -- Pandora
    { 0, 0, 0, 56, 13, "p-cdn.com", "/", "http:", "", 779},
    { 0, 0, 0, 56, 13, "pandora.com", "/", "http:", "", 779},
}


function DetectorInit(detectorInstance)

    gDetector = detectorInstance;

    -- ksfetch
    gDetector:addHttpPattern(2, 5, 0, 286, 24, 0, 0, 'ksfetch', 2202);
    -- Google Update
    gDetector:addHttpPattern(2, 5, 0, 287, 24, 0, 0, 'Google Update', 2203);
    -- Googlebot
    gDetector:addHttpPattern(2, 5, 0, 288, 23, 0, 0, 'Googlebot', 937);
    -- Googlebot Image Search
    gDetector:addHttpPattern(2, 5, 0, 289, 23, 0, 0, 'Googlebot-Image', 2204);
    -- Apple Update
    gDetector:addHttpPattern(2, 5, 0, 290, 23, 0, 0, 'softwareupdate', 32);
    -- Twitterrific
    gDetector:addHttpPattern(2, 5, 0, 325, 23, 0, 0, 'Twitterrific', 2241);
    -- Outlook
    gDetector:addHttpPattern(2, 5, 0, 2, 2, 0, 0, 'MacOutlook', 776);
    -- Windows Update
    gDetector:addHttpPattern(2, 5, 0, 328, 20, 0, 0, 'Windows-Update-Agent', 1105);
    -- AppleCoremedia
    gDetector:addHttpPattern(2, 5, 0, 330, 13, 0, 0, 'AppleCoreMedia', 2253);
    -- Abonti
    gDetector:addHttpPattern(2, 5, 0, 291, 23, 0, 0, 'Abonti/', 2205);
    -- Zapier
    gDetector:addHttpPattern(2, 5, 0, 292, 23, 0, 0, 'Zapier', 2206);
    -- SymantecUpdates
    gDetector:addHttpPattern(2, 5, 0, 293, 23, 0, 0, 'LiveUpdate', 1428);
    -- Microsoft Word
    gDetector:addHttpPattern(2, 5, 0, 294, 23, 0, 0, 'Microsoft Word', 2209);
    -- Microsoft Powerpoint
    gDetector:addHttpPattern(2, 5, 0, 295, 23, 0, 0, 'Microsoft PowerPoint', 2210);
    -- YouTube
    gDetector:addHttpPattern(2, 5, 0, 297, 23, 0, 0, 'youtube/', 929);
    gDetector:addHttpPattern(2, 5, 0, 297, 23, 0, 0, 'YouTube', 929);
    -- Pandora
    gDetector:addHttpPattern(2, 5, 0, 298, 23, 0, 0, 'Pandora', 779);
    --  Yandex Bot
    gDetector:addHttpPattern(2, 5, 0, 299, 23, 0, 0, 'YandexImages/', 2211);
    gDetector:addHttpPattern(2, 5, 0, 299, 23, 0, 0, 'YandexBot/', 2211);
    --  Dropbox
    gDetector:addHttpPattern(2, 5, 0, 300, 23, 0, 0, 'DropboxDesktopClient/', 125);
    --  iFunny
    gDetector:addHttpPattern(2, 5, 0, 301, 23, 0, 0, 'iFunny/', 2133);
    --  MJ12 Bot
    gDetector:addHttpPattern(2, 5, 0, 302, 23, 0, 0, 'MJ12bot/', 2212);
    --  Microsoft CryptoAPI
    gDetector:addHttpPattern(2, 5, 0, 303, 23, 0, 0, 'Microsoft-CryptoAPI/', 2213);
    --  QuickTime
    gDetector:addHttpPattern(2, 5, 0, 304, 23, 0, 0, 'QuickTime/', 387);
    --  Twitter
    gDetector:addHttpPattern(2, 5, 0, 305, 23, 0, 0, 'Twitter/', 882);
    --  Apple Mail
    gDetector:addHttpPattern(2, 5, 0, 7, 2, 0, 0, 'Mail/', 550);
    -- Android Music
    gDetector:addHttpPattern(2, 5, 0, 331, 18, 0, 0, 'Android-Music/', 2258);
    -- Feedfetcher
    gDetector:addHttpPattern(2, 5, 0, 332, 23, 0, 0, 'Feedfetcher-Google', 2262);
    -- GSA Crawler
    gDetector:addHttpPattern(2, 5, 0, 333, 23, 0, 0, 'gsa-crawler', 2263);
    -- Kraken
    gDetector:addHttpPattern(2, 5, 0, 334, 23, 0, 0, 'Kraken/', 2264);
    -- MagPie
    gDetector:addHttpPattern(2, 5, 0, 335, 23, 0, 0, 'magpie-crawler', 2265);
    -- Yahoo! Slurp
    gDetector:addHttpPattern(2, 5, 0, 337, 23, 0, 0, 'Slurp', 942); 
    -- Sogou web spider
    gDetector:addHttpPattern(2, 5, 0, 338, 23, 0, 0, 'Sogou web spider/', 2267);
    -- Voilabot
    gDetector:addHttpPattern(2, 5, 0, 339, 23, 0, 0, 'VoilaBot', 2268);
    gDetector:addHttpPattern(2, 5, 0, 339, 23, 0, 0, 'VoilaBot BETA', 2268);
    -- Quick Look
    gDetector:addHttpPattern(2, 5, 0, 341, 13, 0, 0, 'QuickLook', 2273);
    -- NVIDIA Update
    gDetector:addHttpPattern(2, 5, 0, 342, 18, 0, 0, 'NVIDIA Notifius', 2274);
    -- Connexion client
    gDetector:addHttpPattern(2, 5, 0, 343, 1, 0, 0, 'OCLC Connexion Client', 2275);
    -- PS3 Community Agent
    gDetector:addHttpPattern(2, 5, 0, 344, 19, 0, 0, 'PS3Community-agent/', 2276);
    -- PSP Activity Agent
    gDetector:addHttpPattern(2, 5, 0, 345, 19, 0, 0, 'PSP2Activity-agent/', 2277);
    -- PSP Community Agent
    gDetector:addHttpPattern(2, 5, 0, 346, 19, 0, 0, 'PSP2Community-agent/', 2278);
    -- MS Office Existence Discovery
    gDetector:addHttpPattern(2, 5, 0, 347, 1, 0, 0, 'Microsoft Office Existence Discovery', 2279);
    -- MS Office Protocol Discovery
    gDetector:addHttpPattern(2, 5, 0, 348, 1, 0, 0, 'Microsoft Office Protocol Discovery', 2280);
    -- Rainmeter WebParser
    gDetector:addHttpPattern(2, 5, 0, 350, 14, 0, 0, 'Rainmeter WebParser plugin', 2282);
    -- reCAPTCHA
    gDetector:addHttpPattern(2, 5, 0, 351, 23, 0, 0, 'reCAPTCHA/PHP', 2283);
    gDetector:addHttpPattern(2, 5, 0, 351, 23, 0, 0, 'reCAPTCHA', 2283);
    -- simple-get
    gDetector:addHttpPattern(2, 5, 0, 352, 1, 0, 0, 'SimpleGet', 2284);
    -- Wood TV8
    gDetector:addHttpPattern(2, 5, 0, 0, 0, 1146, 33, 'WOODTV/', 2285);
    -- Malware Defense System
    gDetector:addHttpPattern(2, 5, 0, 353, 25, 0, 0, 'MeDCore', 2287);
    -- Microsoft Excel
    gDetector:addHttpPattern(2, 5, 0, 354, 24, 0, 0, 'Microsoft Office Excel 2013', 2288);
    gDetector:addHttpPattern(2, 5, 0, 354, 24, 0, 0, 'Microsoft Office Excel', 2288); 
    -- Microsoft NCSI
    gDetector:addHttpPattern(2, 5, 0, 355, 23, 0, 0, 'Microsoft NCSI', 2289);
    -- Microsoft WNS
    gDetector:addHttpPattern(2, 5, 0, 356, 23, 0, 0, 'Microsoft-WNS/', 2290);
    -- Moodlebot
    gDetector:addHttpPattern(2, 5, 0, 357, 23, 0, 0, 'MoodleBot/', 2291);
    -- Windows Phone Browser
    gDetector:addHttpPattern(2, 5, 0, 358, 1, 0, 0, 'NativeHost', 2292);
    -- PubSubHubbub
    gDetector:addHttpPattern(2, 5, 0, 375, 23, 0, 0, 'PubSubHubbub-Publisher-PHP/', 2315);
    -- ndgsa-crawler
    gDetector:addHttpPattern(2, 5, 0, 376, 23, 0, 0, 'ndgsa-crawler', 2316);
    -- Microsoft Access
    gDetector:addHttpPattern(2, 5, 0, 377, 23, 0, 0, 'Microsoft Access ', 2317);

    if gDetector.addAppUrl then
        for i,v in ipairs(gUrlPatternList) do
            gDetector:addAppUrl(v[1],v[2],v[3],v[4],v[5],v[6],v[7],v[8],v[9],v[10]);
        end
    end

    return gDetector;
end

function DetectorClean()
end

