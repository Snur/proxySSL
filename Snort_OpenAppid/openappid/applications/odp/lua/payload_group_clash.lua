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
detection_name: Payload Group "Clash"
version: 19
description: Group of payload detectors.
bundle_description: $VAR1 = {
          'ShowClix' => 'A full-service ticketing company.',
          'Renren' => 'Chinese social networking site.',
          'Veoh' => 'Internet television and video sharing service.',
          'deviantART' => 'Online community focused around artwork.',
          'Mixx' => 'Social media and social bookmarking website meant to help users find content based on interests.',
          'imo.im' => 'Instant messenger service for various instant messaging protocols.',
          'Lord & Taylor' => 'Specialty-retail department store chain.',
          'Ace Hardware Corporation' => 'Home improvement goods and hardware retailer.',
          'Urban Outfitters' => 'Clothing and footwear retailer.',
          'Diigo' => 'Social bookmarking website for storing, sharing, and finding web bookmarks.',
          '6.pm' => 'Discount shoes and clothing retailer.',
          'Destructoid' => 'An independent blog focused on video games.',
          'Blip.tv' => 'Online video streaming site for web series.',
          'Bloomingdales' => 'Retail department store.',
          'GameSpy' => 'Video game news, reviews, and previews website.',
          'Netlog' => 'Social networking site geared towards European youth.',
          'GameTrailers' => 'Video game news, reviews, and previews website.',
          'Flickr' => 'An image hosting and video hosting website, web services suite, and online community.',
          'Barneys New York' => 'Luxury retail department store.',
          'TinyPic' => 'Photo and video sharing service.',
          'Rona' => 'Hardware, home improvement, and gardening products retailer based in Canada.',
          'PopUrls' => 'Website that aggregates headlines from various popular social news sites and portals.',
          'Addicting Games' => 'Website for flash games.',
          'Sports Authority' => 'Sporting goods retailer.',
          'TripAdvisor' => 'Travel services site for information and reviews regarding travel related content.',
          'Orbitz' => 'Internet based travel services company.',
          'Neiman Marcus' => 'Luxury retail department store.',
          'Joystiq' => 'Video gaming blog.',
          'Qzone' => 'Chinese social networking site.',
          'Macy\'s' => 'Department store chain.',
          'ShowDocument' => 'Web application that allows users to collaborate on and review documents in real time.',
          'NewsNow' => 'News aggregator website that links to thousands of publications.',
          'Shoplet' => 'Office products retailer.',
          'StubHub' => 'Website for buying and selling tickets for sports, concerts, and other events.',
          'Quill Corporation' => 'Mail-order office supply retailer.',
          'Delicious' => 'Social bookmarking website for storing, sharing, and finding web bookmarks.',
          'Game Informer' => 'Video game news, reviews, and previews website.',
          'REVOLVEclothing' => 'Designer clothing and accessories retailer.',
          'Zip.ca' => 'Online DVD rental company based in Canada.',
          'Swarovski' => 'Retailer for jewelry and other related luxury products.',
          'Atom.com' => 'Entertainment website focused on film and animation.',
          'Minus' => 'Website for file sharing.',
          'Dillards' => 'Retail department store.',
          'Imgur' => 'Image hosting website.',
          'Google Drive' => 'A free office suite and cloud storage system hosted by Google.',
          'Google News' => 'Automated news aggregator.',
          'Kongregate' => 'Website for hosting and playing games.',
          'TicketsNow' => 'Website for buying and selling tickets for sports, concerts, and other events.',
          'WiZiQ' => 'Online learning tool meant to provide a virtual classroom environment.',
          'Nordstrom' => 'Retail department store.',
          'Bluefly' => 'Online fashion retailer.',
          'Black & Decker Corporation' => 'Power tools, hardware, and home improvement products retailer.',
          'Haiku Learning Systems' => 'Online tool for teaching and learning.',
          'House of Fraser' => 'British department store.',
          'Voyages-sncf.com' => 'Travel agency website.',
          'David Jones' => 'High-end Australian department store.',
          'PopCap Games' => 'Online games website.',
          'Web Of Trust' => 'Community-based website reputation rating tool.',
          'Metacafe' => 'Online video entertainment website.',
          'Menards' => 'Home improvement goods retailer.',
          'ImageShack' => 'Image hosting website.',
          'Newsvine' => 'Community based collaborative news website.',
          'Saks Fifth Avenue' => 'Luxury, high-end specialty store.',
          'MediaFire' => 'File and image hosting site.',
          'Vimeo' => 'Website for viewing and sharing videos.',
          'Box' => 'File storage and transfer site.',
          'Quickflix' => 'DVD rental company based in Australia.',
          'ShopStyle' => 'Fashion search engine which links to various retailers.',
          'myUdutu' => 'Online course authoring tool.',
          'beWeeVee' => 'Collaborative real-time editor, allowing several people to edit a document at once.',
          'G4' => 'Video game news website to accompany its associated television channel.',
          'Blue Nile' => 'Online jewelry and diamonds retailer.',
          'OfficeMax' => 'Office supplies retailer.',
          'Tiffany & Co.' => 'Jewelry and silverware retailer.',
          'CheapTickets' => 'Travel services company focused on the leisure market.',
          'Collabedit' => 'Online collaborative code editor which allows multiple users to modify/view code together.',
          'LOVEFiLM' => 'Home video and video game rental service.',
          'City Sports' => 'Sporting goods and athletic apparel retailer.'
        };

--]]

require "DetectorCommon"

local DC = DetectorCommon

DetectorPackageInfo = {
    name =  "payload_group_clash",
    proto =  DC.ipproto.tcp,
    client = {
        init =  'DetectorInit',
        clean =  'DetectorClean',
        minimum_matches =  1
    }
}

--serviceId, clientId, ClientType, PayloadId, PayloadType, hostPattern, pathPattern, schemePattern, queryPattern
gUrlPatternList = {
	--6pm
	{ 0, 0, 0, 207, 32, "6pm.com", "/", "http:", "", 538},
	--ace hardware
	{ 0, 0, 0, 208, 44, "acehardware.com", "/", "http:", "", 539},
	--addictinggames
	{ 0, 0, 0, 209, 20, "addictinggames.com", "/", "http:", "", 540},
	--atom
	{ 0, 0, 0, 210, 13, "atom.com", "/", "http:", "", 556},
	--barneys
	{ 0, 0, 0, 211, 45, "barneys.com", "/", "http:", "", 562},
	--black and decker
	{ 0, 0, 0, 212, 44, "blackanddecker.com", "/", "http:", "", 572},
	--blip.tv
	{ 0, 0, 0, 213, 13, "blip.tv", "/", "http:", "", 574},
	--bloomingdales
	{ 0, 0, 0, 214, 45, "bloomingdales.com", "/", "http:", "", 577},
	--bluefly
	{ 0, 0, 0, 215, 32, "bluefly.com", "/", "http:", "", 579},
	--bluenile
	{ 0, 0, 0, 216, 26, "bluenile.com", "/", "http:", "", 578},
	--box.net
	{ 0, 0, 0, 217, 9, "box.net", "/", "http:", "", 1326},
	{ 0, 0, 0, 217, 9, "box.com", "/", "http:", "", 1326},
	{ 0, 0, 0, 217, 9, "box.org", "/", "http:", "", 1326},
	{ 0, 0, 0, 217, 9, "boxuniversity.litmos.com", "/", "http:", "", 1326},
	--cheaptickets
	{ 0, 0, 0, 218, 31, "cheaptickets.com", "/", "http:", "", 588},
	--citysports
	{ 0, 0, 0, 219, 29, "citysports.com", "/", "http:", "", 591},
	--davidjones
	{ 0, 0, 0, 220, 45, "davidjones.com.au", "/", "http:", "", 601},
	--delicious
	{ 0, 0, 0, 221, 14, "delicious.com", "/", "http:", "", 605},
	{ 0, 0, 0, 221, 14, "icio.us", "/", "http:", "", 605},
	--destructoid
	{ 0, 0, 0, 222, 34, "destructoid.com", "/", "http:", "", 607},
	--diigo
	{ 0, 0, 0, 223, 14, "diigo.com", "/", "http:", "", 612},
	--dillards
	{ 0, 0, 0, 224, 45, "dillards.com", "/", "http:", "", 613},
	--flickr 
	{ 0, 0, 0, 225, 5, "flickr.com", "/", "http:", "", 159},
    { 0, 0, 0, 225, 5, "staticflickr.com", "/", "http:", "", 159},
	--g4tv
	{ 0, 0, 0, 226, 34, "g4tv.com", "/", "http:", "", 646},
	--gameinformer 	
	{ 0, 0, 0, 227, 34, "gameinformer.com", "/", "http:", "", 647},
	--gamespy
	{ 0, 0, 0, 228, 34, "gamespy.com", "/", "http:", "", 649},
	--gametrailers
	{ 0, 0, 0, 229, 34, "gametrailers.com", "/", "http:", "", 651},
	--google news
	{ 0, 0, 0, 230, 33, "news.google.", "/", "http:", "", 663},
	--haikulearning
	{ 0, 0, 0, 231, 12, "haikulearning.com", "/", "http:", "", 669},
	--hotfile
	--{ 0, 0, 0, 232, 9, "hotfile.com", "/", "http:", "", 204},
	--houseoffraser
	{ 0, 0, 0, 233, 45, "houseoffraser.co.uk", "/", "http:", "", 674},
	--iloveim
	-- { 0, 0, 0, 234, 10, "iloveim.com", "/", "http:", "", 681},
	--imageshack 
	{ 0, 0, 0, 235, 9, "imageshack.us", "/", "http:", "", 682},
	{ 0, 0, 0, 235, 9, "imageshack.com", "/", "http:", "", 682},
	--imgur 
	{ 0, 0, 0, 236, 9, "imgur.com", "/", "http:", "", 684},
	--imo.im
	{ 0, 0, 0, 237, 10, "imo.im", "/", "http:", "", 685},
	--joystiq
	{ 0, 0, 0, 238, 34, "joystiq.com", "/", "http:", "", 696},
	--kongregate
	{ 0, 0, 0, 239, 20, "kongregate.com", "/", "http:", "", 705},
	--lord and taylor
	{ 0, 0, 0, 240, 45, "lordandtaylor.com", "/", "http:", "", 719},
	--lovefilm
	{ 0, 0, 0, 241, 38, "lovefilm.com", "/", "http:", "", 721},
	{ 0, 0, 0, 241, 38, "lovefilm.dk", "/", "http:", "", 721},
	{ 0, 0, 0, 241, 38, "lovefilm.de", "/", "http:", "", 721},
	{ 0, 0, 0, 241, 38, "lovefilm.se", "/", "http:", "", 721},
	{ 0, 0, 0, 241, 38, "lovefilm.no", "/", "http:", "", 721},
	--macys
	{ 0, 0, 0, 242, 45, "macys.com", "/", "http:", "", 952},
	--mediafire
	{ 0, 0, 0, 243, 9, "mediafire.com", "/", "http:", "", 285},
	--megavideo
	--{ 0, 0, 0, 244, 13, "megavideo.com", "/", "http:", "", 726},
	--menards
	{ 0, 0, 0, 245, 44, "menards.com", "/", "http:", "", 727},
	--metacafe
	{ 0, 0, 0, 246, 13, "metacafe.com", "/", "http:", "", 728},
	--min.us
    { 0, 0, 0, 247, 9, "minus.com", "/", "http:", "", 733},
	{ 0, 0, 0, 247, 9, "min.us", "/", "http:", "", 733},
	--mixx
	{ 0, 0, 0, 248, 14, "mixx.com", "/", "http:", "", 734},
	--neimanmarcus
	{ 0, 0, 0, 249, 45, "neimanmarcus.com", "/", "http:", "", 751},
	--newsnow
	{ 0, 0, 0, 250, 33, "newsnow.co.uk", "/", "http:", "", 760},
	--newsvine
	{ 0, 0, 0, 251, 14, "newsvine.com", "/", "http:", "", 761},
	--nordstrom
	{ 0, 0, 0, 252, 45, "nordstrom.com", "/", "http:", "", 764},
	{ 0, 0, 0, 252, 45, "nordstromimage.com", "/", "http:", "", 764},
	--officemax
	{ 0, 0, 0, 253, 24, "officemax.com", "/", "http:", "", 769},
	--orbitz
	{ 0, 0, 0, 254, 37, "orbitz.com", "/", "http:", "", 775},
	--popcap
	{ 0, 0, 0, 256, 20, "popcap.co", "/", "http:", "", 789},
	--popurls
	{ 0, 0, 0, 257, 33, "popurls.com", "/", "http:", "", 790},
	--quickflix
	{ 0, 0, 0, 259, 38, "quickflix.com.au", "/", "http:", "", 796},
	--quill
	{ 0, 0, 0, 260, 24, "quill.com", "/", "http:", "", 797},
	--revolve clothing
	{ 0, 0, 0, 261, 32, "revolveclothing.com", "/", "http:", "", 809},
	--rona
	{ 0, 0, 0, 262, 44, "rona.ca", "/", "http:", "", 810},
	--saksfifthavenue
	{ 0, 0, 0, 263, 45, "saksfifthavenue.com", "/", "http:", "", 816},
	--shoplet
	{ 0, 0, 0, 264, 24, "shoplet.com", "/", "http:", "", 825},
	--shopstyle
	{ 0, 0, 0, 265, 32, "shopstyle.co", "/", "http:", "", 828},
	{ 0, 0, 0, 265, 32, "shopstyle.fr", "/", "http:", "", 828},
	{ 0, 0, 0, 265, 32, "shopstyle.de", "/", "http:", "", 828},
	--showclix
	{ 0, 0, 0, 266, 31, "showclix.com", "/", "http:", "", 830},
	--sports authority
	{ 0, 0, 0, 267, 29, "sportsauthority.com", "/", "http:", "", 842},
	--stubhub
	{ 0, 0, 0, 268, 31, "stubhub.com", "/", "http:", "", 850},
	--swarovski
	{ 0, 0, 0, 269, 26, "swarovski.com", "/", "http:", "", 854},
	--ticketsnow
	{ 0, 0, 0, 270, 31, "ticketsnow.com", "/", "http:", "", 869},
	--tiffany and co
	{ 0, 0, 0, 271, 26, "tiffany.co", "/", "http:", "", 870},
	{ 0, 0, 0, 271, 26, "tiffany.ca", "/", "http:", "", 870},
	{ 0, 0, 0, 271, 26, "tiffany.cn", "/", "http:", "", 870},
	{ 0, 0, 0, 271, 26, "tiffany.kr", "/", "http:", "", 870},
	{ 0, 0, 0, 271, 26, "tiffany.at", "/", "http:", "", 870},
	{ 0, 0, 0, 271, 26, "tiffany.fr", "/", "http:", "", 870},
	{ 0, 0, 0, 271, 26, "tiffany.de", "/", "http:", "", 870},
	{ 0, 0, 0, 271, 26, "tiffany.it", "/", "http:", "", 870},
	{ 0, 0, 0, 271, 26, "tiffany.es", "/", "http:", "", 870},
	{ 0, 0, 0, 271, 26, "tiffany.com", "/", "http:", "", 870},
	--tinypic 
	{ 0, 0, 0, 272, 9, "tinypic.com", "/", "http:", "", 873},
	--tripadvisor
	{ 0, 0, 0, 273, 37, "tripadvisor.com", "/", "http:", "", 881},
	--udutu
	{ 0, 0, 0, 274, 12, "myudutu.com", "/", "http:", "", 748},
	--urban outfitters
	{ 0, 0, 0, 275, 32, "urbanoutfitters.co", "/", "http:", "", 883},
	--veoh
	{ 0, 0, 0, 276, 13, "veoh.co", "/", "http:", "", 889},
	--vimeo
	{ 0, 0, 0, 277, 13, "vimeo.com", "/", "http:", "", 893},
	{ 0, 0, 0, 277, 13, "vimeocdn.com", "/", "http:", "", 893},
	--voyages-sncf
	{ 0, 0, 0, 278, 37, "voyages-sncf.com", "/", "http:", "", 899},
	--weboftrust
	{ 0, 0, 0, 279, 18, "mywot.com", "/", "http:", "", 903},
	--wiziq
	{ 0, 0, 0, 280, 12, "wiziq.com", "/", "http:", "", 914},
	--zip.ca
	{ 0, 0, 0, 281, 38, "zip.ca", "/", "http:", "", 932},
	--zooomr 
	--{ 0, 0, 0, 282, 9, "zooomr.com", "/", "http:", "", 933},
	--beweevee
	{ 0, 0, 0, 283, 8, "beweevee.com", "/", "http:", "", 568},
	--showdocument
	{ 0, 0, 0, 284, 8, "showdocument.com", "/", "http:", "", 831},
	--google drive
	{ 0, 0, 0, 285, 11, "docs.google.com", "/", "http:", "", 180},
    { 0, 0, 0, 285, 11, "drive.google.com", "/", "http:", "", 180},
	--collabedit
	{ 0, 0, 0, 286, 8, "collabedit.com", "/", "http:", "", 592},
	--deviantart
	{ 0, 0, 0, 287, 5, "deviantart.com", "/", "http:", "", 608},
	--qzone
	{ 0, 0, 0, 288, 5, "qzone.qq.com", "/", "http:", "", 799},
	--renren
	{ 0, 0, 0, 289, 5, "renren.com", "/", "http:", "", 808},
	--netlog
	{ 0, 0, 0, 290, 5, "netlog.com", "/", "http:", "", 757},
}
function DetectorInit(detectorInstance)

    gDetector = detectorInstance;

    if gDetector.addAppUrl then
        for i,v in ipairs(gUrlPatternList) do
            gDetector:addAppUrl(v[1],v[2],v[3],v[4],v[5],v[6],v[7],v[8],v[9],v[10]);
        end
    end
    return gDetector;
end

function DetectorClean()
end

