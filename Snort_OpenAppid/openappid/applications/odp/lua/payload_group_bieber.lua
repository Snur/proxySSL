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
detection_name: Payload Group "Bieber"
version: 14
description: Group of payload detectors.
bundle_description: $VAR1 = {
          'Citi' => 'Financial services company.',
          'Car and Driver' => 'American automotive enthusiast news site.',
          'Victoria\'s Secret' => 'Woman\'s wear, lingerie, and beauty product retailer.',
          'Zappos' => 'Online shoe and apparel retailer.',
          'Zales' => 'Jewelry retailer.',
          'Home Depot' => 'Retailer for home improvement and construction goods/products.',
          'Fry\'s Electronics' => 'Computer and electronics retailer.',
          'Staples' => 'Office supply retailer.',
          'Target' => 'Discount retailer.',
          'Neckermann' => 'General goods online retailer.',
          'GoToMeeting' => 'Online meeting and desktop sharing service.',
          'The Gap' => 'Clothing and accessories retailer, encompassing Gap, Old Navy, Banana Republic, Piperlime, and Athleta.',
          'Fnac' => 'International retail chain focused on cultural and electronic products.',
          'Morgan Stanley' => 'Global financial services firm.',
          'REI' => 'Outdoor sporting clothing and gear retailer.',
          'Dell' => 'Computer and related technologies retailer.',
          'Office Depot' => 'Office supply retailer.',
          'CDiscount' => 'French online retailer.',
          'Ticketmaster' => 'Ticket sales and distribution website for concerts, sports events, etc.',
          'Trac' => 'Web based bug tracking and project management tool.',
          'Kotaku' => 'Video game focused blog.',
          'IGN' => 'News/reviews website focused primarily on video games.',
          'The Sharper Image' => 'General electronics and gifts retailer.',
          'oo.com.au' => 'Australian and New Zealand online department store.',
          'Walmart' => 'Discount department store.',
          'Newegg' => 'Computer hardware and software retailer.',
          'Edmunds.com' => 'General automotive information website.',
          'Tchibo' => 'German retailer with weekly changing products.',
          'GameSpot' => 'Video game previews/reviews/news website.',
          'J.C. Penney' => 'Clothing and accessory retailer.',
          'HP Home & Home Office Store' => 'HP\'s online store for computers and related products.',
          'Zynga' => 'Social network game developer.',
          'ThinkGeek' => 'Clothing, electronics, and gadget retailer tailored towards technology and computer enthusiasts.',
          'Bing' => 'Microsoft\'s internet search engine.',
          'Fidelity' => 'Mutual fund and financial services company.',
          'HSBC' => 'Global banking and financial services company.',
          'Wachovia' => 'Financial services company.',
          'TD Ameritrade' => 'Online stock brokerage service.',
          'Woot' => 'Online retailer that sells one discount product a day.',
          'Deals Direct' => 'Australian discount retailer.',
          'E*TRADE' => 'Financial services company with a focus on online stock brokerage.',
          'CamerasDirect.com.au' => 'Australian camera and photography gear retailer.',
          'Livemeeting' => 'Microsoft\'s commercial web-conferencing service.',
          'JIRA' => 'Web based bug tracking and project management tool.',
          'Netflix' => 'Rental and on-demand internet television and movie streaming website.',
          'Lowe\'s' => 'Home improvement and appliance retailer.',
          'Google Product Search' => 'Google e-commerce site.',
          'Overstock.com' => 'Online discount retailer.',
          'Jalopnik' => 'Automotive news and information blog.',
          'ShopNBC' => 'General shopping website in association with it\'s related televised shopNBC broadcasts.',
          'Crutchfield' => 'Electronics retailer.',
          'Expedia' => 'Travel reservation website.',
          'ProFlowers' => 'United States\' flower retailer.',
          'Capital One' => 'U.S. based bank holding company.',
          'Vanguard' => 'Investment management company.',
          'Autoblog' => 'Automobile news and information site.',
          'T. Rowe Price' => 'Public investment firm.',
          'Salesforce.com' => 'Enterprise cloud computing company.',
          'vente-privee.com' => 'Private online shopping club focused on fashion and lifestyle products.',
          'Travelocity' => 'Online travel agency.',
          'Discover' => 'Financial services company.',
          'FTD' => 'Floral retailer.',
          'Top Gear' => 'Website for the related British TV series focused on cars.',
          'Wikipedia' => 'Collaborative, user-written online encyclopedia.',
          'Tickets.com' => 'Ticket sales and distribution website for concerts, sports events, etc.',
          'Kay Jewelers' => 'Retail jeweller.',
          'Bank of America' => 'Global financial services company.',
          'AutoTrader.com' => 'Used car listings by owner or dealer.',
          'Backblaze' => 'Online backup tool for Windows and Mac users.',
          'Drugstore.com' => 'Online retailer for health, beauty, and wellness products.',
          'Craigslist' => 'Popular online classifieds.',
          'Schwab' => 'Brokerage and banking company.',
          'CarMax' => 'New and used car retailer.',
          'FogBugz' => 'Web-based project management and bug tracking system.',
          'Redmine' => 'Web based bug tracking and project management tool.',
          'Basecamp' => 'Web based project management tool.',
          'Kohl\'s' => 'Department store/retailer.',
          'Chase' => 'Consumer and commercial banking company.',
          'Blockbuster' => 'Movie and video game rental/streaming website.',
          'Wells Fargo' => 'Global financial services company.',
          'Kogan Technologies' => 'Australian retailer of consumer electronic devices.',
          'Launchpad' => 'Web based bug tracking and project management tool.',
          'Windows Live SkyDrive' => 'Cloud based file hosting service.',
          'Vehix' => 'New and used car information and sales website.',
          'QVC' => 'General shopping website in association with its related televised QVC broadcasts.',
          'RitzCamera.com' => 'Photography goods and electronics retailer.',
          'Scottrade' => 'Discount brokerage service.',
          'Sears' => 'Department store retailer.',
          'American Express' => 'Financial services company.',
          'Tiger Direct' => 'Online computer and electronics retailer.',
          'GameStop' => 'Video game retailer.',
          'Dick\'s Sporting Goods' => 'Retailer focused on sporting goods.',
          'Gawker' => 'Online blog based around media news and gossip.',
          'J&R' => 'Computer and electronics retailer.',
          'Sam\'s Club' => 'Warehouse club\'s online retail site.',
          'Costco' => 'Warehouse club\'s online retail website.',
          'Kmart' => 'Discount department store/retailer.'
        };

--]]

require "DetectorCommon"

local DC = DetectorCommon

DetectorPackageInfo = {
    name =  "payload_group_bieber",
    proto =  DC.ipproto.tcp,
    client = {
        init =  'DetectorInit',
        clean =  'DetectorClean',
        minimum_matches =  1
    }
}

--serviceId, clientId, ClientType, PayloadId, PayloadType, hostPattern, pathPattern, schemePattern, queryPattern
gUrlPatternList = {
	--americanexpress
	{ 0, 0, 0, 110, 39, "americanexpress.co", "/", "http:", "", 544}, 
	{ 0, 0, 0, 110, 39, "americanexpress.ch", "/", "http:", "", 544},
	{ 0, 0, 0, 110, 39, "americanexpress.kz", "/", "http:", "", 544},
	{ 0, 0, 0, 110, 39, "americanexpress.be", "/", "http:", "", 544},
	{ 0, 0, 0, 110, 39, "americanexpress.ae", "/", "http:", "", 544},
	--ameritrade
	{ 0, 0, 0, 111, 41, "tdameritrade.com", "/", "http:", "", 860},
	{ 0, 0, 0, 111, 41, "amtd.com", "/", "http:", "", 860}, 
    { 0, 0, 0, 111, 41, "tdameritrade-st.streamer.com", "/", "http:", "", 860},
	--backblaze	
	{ 0, 0, 0, 112, 9, "backblaze.com", "/", "http:", "", 47},
	--bankofamerica
	{ 0, 0, 0, 113, 39, "bankofamerica.co", "/", "http:", "", 560},
	--bing
	{ 0, 0, 0, 114, 22, "bing.com", "/", "http:", "", 58},
	{ 0, 0, 0, 114, 22, "bing.net", "/", "http:", "", 58},
	--capitalone 
	{ 0, 0, 0, 115, 39, "capitalone.co", "/", "http:", "", 582}, 
	{ 0, 0, 0, 115, 39, "capitalone.ca", "/", "http:", "", 582},
	--citi
	{ 0, 0, 0, 116, 39, "citi.com", "/", "http:", "", 590}, 
	{ 0, 0, 0, 116, 40, "citibank.com", "/", "http:", "", 590},
	--discover
	{ 0, 0, 0, 117, 42, "discovercard.com", "/", "http:", "", 615},
	{ 0, 0, 0, 117, 40, "discoverbank.com", "/", "http:", "", 615},
	--etrade
	{ 0, 0, 0, 118, 41, "etrade.com", "/", "http:", "", 621},
	--fidelity
    { 0, 0, 0, 119, 39, "fidelity.com", "/", "http:", "", 636},
	{ 0, 0, 0, 119, 39, "fidelity.at", "/", "http:", "", 636},
	{ 0, 0, 0, 119, 39, "fidelity.au", "/", "http:", "", 636},
	{ 0, 0, 0, 119, 39, "fidelity.fr", "/", "http:", "", 636},
	{ 0, 0, 0, 119, 39, "fidelity.de", "/", "http:", "", 636},
	{ 0, 0, 0, 119, 39, "fidelity-italia.it", "/", "http:", "", 636}, 
	{ 0, 0, 0, 119, 39, "fidelity.nl", "/", "http:", "", 636},
	{ 0, 0, 0, 119, 39, "fondosfidelity.es", "/", "http:", "", 636}, 
	{ 0, 0, 0, 119, 39, "fidelity.se", "/", "http:", "", 636},
	{ 0, 0, 0, 119, 39, "fidelity.co", "/", "http:", "", 636}, 
	{ 0, 0, 0, 119, 39, "fidelity-international.com", "/", "http:", "", 636}, 
	--fogbugz 
	{ 0, 0, 0, 120, 43, "fogbugz.com", "/", "http:", "", 161}, 
    { 0, 0, 0, 120, 43, "fogcreek.com", "/", "http:", "", 161},
	--gamespot
	{ 0, 0, 0, 121, 34, "gamespot.co", "/", "http:", "", 648},
	--gamestop
	{ 0, 0, 0, 122, 28, "gamestop.com", "/", "http:", "", 650},
	{ 0, 0, 0, 122, 28, "gamestop.ca", "/", "http:", "", 650},
	{ 0, 0, 0, 122, 28, "gamestop.fi", "/", "http:", "", 650},
	{ 0, 0, 0, 122, 28, "gamestop.de", "/", "http:", "", 650},
	{ 0, 0, 0, 122, 28, "gamestop.it", "/", "http:", "", 650},
	{ 0, 0, 0, 122, 28, "gamestop.no", "/", "http:", "", 650},
	{ 0, 0, 0, 122, 28, "gamestop.es", "/", "http:", "", 650},
	{ 0, 0, 0, 122, 28, "gamestop.dk", "/", "http:", "", 650},
	{ 0, 0, 0, 122, 28, "gamestop.ie", "/", "http:", "", 650},
	{ 0, 0, 0, 122, 28, "gamestop.pt", "/", "http:", "", 650},
	{ 0, 0, 0, 122, 28, "gamestop.se", "/", "http:", "", 650},	
	--gawker
	{ 0, 0, 0, 123, 33, "gawker.com", "/", "http:", "", 652},
	--gotomeeting		
	{ 0, 0, 0, 124, 21, "gotomeeting.co", "/", "http:", "", 265},
	{ 0, 0, 0, 124, 21, "gotomeeting.in", "/", "http:", "", 265},
	{ 0, 0, 0, 124, 21, "gotomeeting.at", "/", "http:", "", 265},
	{ 0, 0, 0, 124, 21, "gotomeeting.be", "/", "http:", "", 265},
	{ 0, 0, 0, 124, 21, "gotomeeting.dk", "/", "http:", "", 265},
	{ 0, 0, 0, 124, 21, "gotomeeting.fr", "/", "http:", "", 265},
	{ 0, 0, 0, 124, 21, "gotomeeting.de", "/", "http:", "", 265},
	{ 0, 0, 0, 124, 21, "gotomeeting.ie", "/", "http:", "", 265},
	{ 0, 0, 0, 124, 21, "gotomeeting.se", "/", "http:", "", 265},
	{ 0, 0, 0, 124, 21, "gotomeeting.ch", "/", "http:", "", 265},
	--hsbc	
	{ 0, 0, 0, 125, 39, "hsbc.co", "/", "http:", "", 675},
	{ 0, 0, 0, 125, 39, "hsbc.am", "/", "http:", "", 675},
	{ 0, 0, 0, 125, 39, "hsbc.bm", "/", "http:", "", 675},
	{ 0, 0, 0, 125, 39, "hsbc.ca", "/", "http:", "", 675},
	{ 0, 0, 0, 125, 39, "hsbc.ky", "/", "http:", "", 675},
	{ 0, 0, 0, 125, 39, "hsbc.cz", "/", "http:", "", 675},
	{ 0, 0, 0, 125, 39, "hsbc.ky", "/", "http:", "", 675},
	{ 0, 0, 0, 125, 39, "hsbc.fr", "/", "http:", "", 675},
	{ 0, 0, 0, 125, 39, "hsbctrinkaus.de", "/", "http:", "", 675},
	{ 0, 0, 0, 125, 39, "hsbc.ge", "/", "http:", "", 675},
	{ 0, 0, 0, 125, 39, "hsbc.gr", "/", "http:", "", 675},
	{ 0, 0, 0, 125, 39, "hsbc.ie", "/", "http:", "", 675},
	{ 0, 0, 0, 125, 39, "hsbc.kz", "/", "http:", "", 675},
	{ 0, 0, 0, 125, 39, "hsbc.pl", "/", "http:", "", 675},
	{ 0, 0, 0, 125, 39, "hsbc.ru", "/", "http:", "", 675},
	{ 0, 0, 0, 125, 39, "hsbc.es", "/", "http:", "", 675},
	{ 0, 0, 0, 125, 39, "hsbc.lk", "/", "http:", "", 675},
	{ 0, 0, 0, 125, 39, "hsbc.ae", "/", "http:", "", 675},
	{ 0, 0, 0, 125, 39, "hsbc.es", "/", "http:", "", 675},
	{ 0, 0, 0, 125, 39, "hsbc.es", "/", "http:", "", 675},
	--ign
	{ 0, 0, 0, 126, 34, "ign.com", "/", "http:", "", 680}, 
	--lbps
	--{ 0, 0, 0, 127, 39, "lbps.com", "/", "http:", "", 709},
	--morganstanley
	{ 0, 0, 0, 128, 39, "morganstanley.co", "/", "http:", "", 738}, 
	--salesforce
	{ 0, 0, 0, 129, 11, "salesforce.com", "/", "http:", "", 950}, 
	--schwab
	{ 0, 0, 0, 130, 39, "schwab.com", "/", "http:", "", 819},
	--scottrade	
	{ 0, 0, 0, 131, 41, "scottrade.com", "/", "http:", "", 820},
	--skydrive 
	{ 0, 0, 0, 132, 9, "skydrive.live.com", "/", "http:", "", 911},
	--troweprice
	{ 0, 0, 0, 133, 39, "troweprice.com", "/", "http:", "", 855},
	--vanguard 
	{ 0, 0, 0, 134, 39, "vanguard.co", "/", "http:", "", 885},
	{ 0, 0, 0, 134, 39, "vanguardinvestments.dk", "/", "http:", "", 885},
	{ 0, 0, 0, 134, 39, "vanguardinvestments.fr", "/", "http:", "", 885},
	{ 0, 0, 0, 134, 39, "vanguardinvestments.de", "/", "http:", "", 885},
	{ 0, 0, 0, 134, 39, "vanguardjapan.co", "/", "http:", "", 885},
	{ 0, 0, 0, 134, 39, "vanguardinvestments.nl", "/", "http:", "", 885},
	{ 0, 0, 0, 134, 39, "vanguardinvestments.se", "/", "http:", "", 885},
	{ 0, 0, 0, 134, 39, "vanguardinvestments.ch", "/", "http:", "", 885},
	{ 0, 0, 0, 134, 39, "vanguardjapan.co", "/", "http:", "", 885},
	--wachovia
	{ 0, 0, 0, 135, 39, "wachovia.com", "/", "http:", "", 900},
	--wellsfargo
	{ 0, 0, 0, 136, 39, "wellsfargo.com", "/", "http:", "", 907}, 
	--zynga
	{ 0, 0, 0, 137, 20, "zynga.com", "/", "http:", "", 533},
	--camerasdirect
	{ 0, 0, 0, 138, 27, "camerasdirect.com.au", "/", "http:", "", 581},
	--carmax
	{ 0, 0, 0, 139, 36, "carmax.com", "/", "http:", "", 584},
	--cdiscount
	{ 0, 0, 0, 140, 45, "cdiscount.com", "/", "http:", "", 585},
	--costco
	{ 0, 0, 0, 141, 30, "costco.co", "/", "http:", "", 593},
	{ 0, 0, 0, 141, 30, "costco.ca", "/", "http:", "", 593},
	--crutchfield
	{ 0, 0, 0, 142, 27, "crutchfield.com", "/", "http:", "", 595},
	{ 0, 0, 0, 142, 27, "crutchfield.ca", "/", "http:", "", 595},
	--dealsdirect
	{ 0, 0, 0, 143, 30, "dealsdirect.com.au", "/", "http:", "", 604},
	--dell
	{ 0, 0, 0, 144, 27, "dell.com", "/", "http:", "", 606},
	--drugstore 
	{ 0, 0, 0, 145, 45, "drugstore.com", "/", "http:", "", 620},
	--edmunds 
	{ 0, 0, 0, 146, 36, "edmunds.com", "/", "http:", "", 622},
	--expedia
	{ 0, 0, 0, 147, 37, "expedia.co", "/", "http:", "", 628},
	{ 0, 0, 0, 147, 37, "expedia.at", "/", "http:", "", 628},
	{ 0, 0, 0, 147, 37, "expedia.be", "/", "http:", "", 628},
	{ 0, 0, 0, 147, 37, "expedia.ca", "/", "http:", "", 628},
	{ 0, 0, 0, 147, 37, "expedia.dk", "/", "http:", "", 628},
	{ 0, 0, 0, 147, 37, "expedia.fr", "/", "http:", "", 628},
	{ 0, 0, 0, 147, 37, "expedia.de", "/", "http:", "", 628},
	{ 0, 0, 0, 147, 37, "expedia.ie", "/", "http:", "", 628},
	{ 0, 0, 0, 147, 37, "expedia.it", "/", "http:", "", 628},
	{ 0, 0, 0, 147, 37, "expedia.nl", "/", "http:", "", 628},
	{ 0, 0, 0, 147, 37, "expedia.no", "/", "http:", "", 628},
	{ 0, 0, 0, 147, 37, "expedia.es", "/", "http:", "", 628},
	{ 0, 0, 0, 147, 37, "expedia.se", "/", "http:", "", 628},
	--fnac
	{ 0, 0, 0, 148, 45, "fnac.com", "/", "http:", "", 640},
	{ 0, 0, 0, 148, 45, "fnac.gr", "/", "http:", "", 640},
	{ 0, 0, 0, 148, 45, "fnac.it", "/", "http:", "", 640},
	{ 0, 0, 0, 148, 45, "fnac.pt", "/", "http:", "", 640},
	{ 0, 0, 0, 148, 45, "fnac.es", "/", "http:", "", 640},
	{ 0, 0, 0, 148, 45, "fnac.ch", "/", "http:", "", 640},
	--frys
	{ 0, 0, 0, 149, 27, "frys.com", "/", "http:", "", 643},
	--ftd
	{ 0, 0, 0, 150, 25, "ftd.com", "/", "http:", "", 644},
	--google shopping
	{ 0, 0, 0, 151, 22, "shopping.google.co", "/", "http:", "", 664},
	--homedepot
	{ 0, 0, 0, 152, 44, "homedepot.com", "/", "http:", "", 670},
	{ 0, 0, 0, 152, 44, "homedepot.ca", "/", "http:", "", 670},
	--shopping.hp.com
	{ 0, 0, 0, 153, 27, "shopping.hp.com", "/", "http:", "", 827},
	{ 0, 0, 0, 153, 27, "store.hp.com", "/", "http:", "", 827},
	--jcpenny
	{ 0, 0, 0, 154, 45, "jcpenney.com", "/", "http:", "", 690},
	--jr
	{ 0, 0, 0, 155, 27, "jr.com", "/", "http:", "", 691},
	--kay
	{ 0, 0, 0, 156, 26, "kay.com", "/", "http:", "", 698},
	--kmart
	{ 0, 0, 0, 157, 30, "kmart.com", "/", "http:", "", 702},
	--kogan
	{ 0, 0, 0, 158, 27, "kogan.com.au", "/", "http:", "", 703},
	{ 0, 0, 0, 158, 27, "kogan.co.uk", "/", "http:", "", 703},
	--kohls
	{ 0, 0, 0, 159, 45, "kohls.com", "/", "http:", "", 704},
	--lowes
	{ 0, 0, 0, 160, 44, "lowes.com", "/", "http:", "", 722},
	{ 0, 0, 0, 160, 44, "lowes.ca", "/", "http:", "", 722},
	--neckermann
	{ 0, 0, 0, 161, 45, "neckermann.de", "/", "http:", "", 750},
	{ 0, 0, 0, 161, 45, "neckermann.at", "/", "http:", "", 750},
	{ 0, 0, 0, 161, 45, "neckermann.ch", "/", "http:", "", 750},
	{ 0, 0, 0, 161, 45, "neckermann.cz", "/", "http:", "", 750},
	{ 0, 0, 0, 161, 45, "neckermann.sk", "/", "http:", "", 750},
	{ 0, 0, 0, 161, 45, "neckermann.ua", "/", "http:", "", 750},
	{ 0, 0, 0, 161, 45, "neckermann.si", "/", "http:", "", 750},
	{ 0, 0, 0, 161, 45, "neckermann.hr", "/", "http:", "", 750},
	{ 0, 0, 0, 161, 45, "neckermann.com.pl", "/", "http:", "", 750},
	{ 0, 0, 0, 161, 45, "neck.nl", "/", "http:", "", 750},
	{ 0, 0, 0, 161, 45, "neck.be", "/", "http:", "", 750},
	--netflix
	{ 0, 0, 0, 162, 38, "netflix.com", "/", "http:", "", 756},
	{ 0, 0, 0, 162, 38, "nflximg.net", "/", "http:", "", 756},
        { 0, 0, 0, 162, 38, "nflximg.com", "/", "http:", "", 756},
	--newegg
	{ 0, 0, 0, 163, 27, "newegg.com", "/", "http:", "", 759},
	{ 0, 0, 0, 163, 27, "newegg.ca", "/", "http:", "", 759},
	{ 0, 0, 0, 163, 27, "newegg.cn", "/", "http:", "", 759},
	{ 0, 0, 0, 163, 27, "newegg.com.tw", "/", "http:", "", 759},
	{ 0, 0, 0, 163, 27, "neweggflash.com", "/", "http:", "", 759},
	{ 0, 0, 0, 163, 27, "neweggbusiness.com", "/", "http:", "", 759},
	--officedepot 
	{ 0, 0, 0, 164, 24, "officedepot.co", "/", "http:", "", 768},
	{ 0, 0, 0, 164, 24, "officedepot.at", "/", "http:", "", 768},
	{ 0, 0, 0, 164, 24, "officedepot.be", "/", "http:", "", 768},
	{ 0, 0, 0, 164, 24, "officedepot.ca", "/", "http:", "", 768},
	{ 0, 0, 0, 164, 24, "officedepot.cn", "/", "http:", "", 768},
	{ 0, 0, 0, 164, 24, "officedepot.cz", "/", "http:", "", 768},
	{ 0, 0, 0, 164, 24, "officedepot.eu", "/", "http:", "", 768},
	{ 0, 0, 0, 164, 24, "officedepot.fr", "/", "http:", "", 768},
	{ 0, 0, 0, 164, 24, "officedepot.de", "/", "http:", "", 768},
	{ 0, 0, 0, 164, 24, "officedepot.hu", "/", "http:", "", 768},
	{ 0, 0, 0, 164, 24, "officedepot.ie", "/", "http:", "", 768},
	{ 0, 0, 0, 164, 24, "officedepot.lu", "/", "http:", "", 768},
	{ 0, 0, 0, 164, 24, "officedepot.pl", "/", "http:", "", 768},
	{ 0, 0, 0, 164, 24, "officedepot.sk", "/", "http:", "", 768},
	{ 0, 0, 0, 164, 24, "officedepot.es", "/", "http:", "", 768},
	{ 0, 0, 0, 164, 24, "officedepot.ch", "/", "http:", "", 768},
	{ 0, 0, 0, 164, 24, "officedepot.it", "/", "http:", "", 768},
	{ 0, 0, 0, 164, 24, "office-depot.be", "/", "http:", "", 768},
	{ 0, 0, 0, 164, 24, "office-depot.fr", "/", "http:", "", 768},
	{ 0, 0, 0, 164, 24, "office-depot.ch", "/", "http:", "", 768},
	--oo.com.au
	{ 0, 0, 0, 165, 30, "oo.com.au", "/", "http:", "", 770},
	--overstock
	{ 0, 0, 0, 166, 30, "overstock.com", "/", "http:", "", 778},
	--proflowers
	{ 0, 0, 0, 167, 25, "proflowers.com", "/", "http:", "", 793},
	--qvc
	{ 0, 0, 0, 168, 45, "qvc.com", "/", "http:", "", 798},
	{ 0, 0, 0, 168, 45, "qvc.de", "/", "http:", "", 798},
	{ 0, 0, 0, 168, 45, "qvc.it", "/", "http:", "", 798},
	{ 0, 0, 0, 168, 45, "qvc.jp", "/", "http:", "", 798},
	{ 0, 0, 0, 168, 45, "qvcuk.com", "/", "http:", "", 798},
	--rei
	{ 0, 0, 0, 169, 29, "rei.com", "/", "http:", "", 806},
	--ritzcamera
	{ 0, 0, 0, 170, 27, "ritzcamera.com", "/", "http:", "", 951},
	--samsclub
	{ 0, 0, 0, 171, 30, "samsclub.com", "/", "http:", "", 817},
	{ 0, 0, 0, 171, 30, "sams.com.mx", "/", "http:", "", 817},
	{ 0, 0, 0, 171, 30, "samsclubpr.com", "/", "http:", "", 817},
	--Sears
	{ 0, 0, 0, 172, 45, "sears.com", "/", "http:", "", 821},
	{ 0, 0, 0, 172, 45, "sears.ca", "/", "http:", "", 821},
	{ 0, 0, 0, 172, 45, "searspartsdirect.com", "/", "http:", "", 821},
	{ 0, 0, 0, 172, 45, "searshomeservices.com", "/", "http:", "", 821},
	{ 0, 0, 0, 172, 45, "searsoutlet.com", "/", "http:", "", 821},
	{ 0, 0, 0, 172, 45, "searscommerceservices.com", "/", "http:", "", 821},
	{ 0, 0, 0, 172, 45, "searsflowers.com", "/", "http:", "", 821},
	{ 0, 0, 0, 172, 45, "searsgaragedoors.com", "/", "http:", "", 821},
	{ 0, 0, 0, 172, 45, "searshomeapplianceshowroom.com", "/", "http:", "", 821},
	{ 0, 0, 0, 172, 45, "searshomepro.com", "/", "http:", "", 821},
	{ 0, 0, 0, 172, 45, "searshometownstores.com", "/", "http:", "", 821},
	{ 0, 0, 0, 172, 45, "searsoptical.com", "/", "http:", "", 821},
	{ 0, 0, 0, 172, 45, "searsoutlet.com", "/", "http:", "", 821},
	{ 0, 0, 0, 172, 45, "searsdrivingschools.com", "/", "http:", "", 821},
	{ 0, 0, 0, 172, 45, "searsvacations.com", "/", "http:", "", 821},
	{ 0, 0, 0, 172, 45, "searshardwarestores.com", "/", "http:", "", 821},
	{ 0, 0, 0, 172, 45, "searscommercial.com", "/", "http:", "", 821},
	{ 0, 0, 0, 172, 45, "searsvehicleprotectionplan.com", "/", "http:", "", 821},
	--sharperimage
	{ 0, 0, 0, 173, 27, "sharperimage.com", "/", "http:", "", 864},
	--shopnbc
	{ 0, 0, 0, 174, 45, "shopnbc.com", "/", "http:", "", 826},
	--staples
	{ 0, 0, 0, 175, 24, "staples.co", "/", "http:", "", 848},
	{ 0, 0, 0, 175, 24, "staples.ca", "/", "http:", "", 848},
	{ 0, 0, 0, 175, 24, "staples.pt", "/", "http:", "", 848},
	{ 0, 0, 0, 175, 24, "staples.de", "/", "http:", "", 848},
	--target
	{ 0, 0, 0, 176, 30, "target.com", "/", "http:", "", 858},
	--tchibo
	{ 0, 0, 0, 177, 45, "tchibo.de", "/", "http:", "", 859},
	{ 0, 0, 0, 177, 45, "tchibo.ch", "/", "http:", "", 859},
	{ 0, 0, 0, 177, 45, "tchibo.pl", "/", "http:", "", 859},
	{ 0, 0, 0, 177, 45, "tchibo.cz", "/", "http:", "", 859},
	{ 0, 0, 0, 177, 45, "tchibo.com.tr", "/", "http:", "", 859},
	{ 0, 0, 0, 177, 45, "eduscho.at", "/", "http:", "", 859},
	--thinkgeek
	{ 0, 0, 0, 178, 45, "thinkgeek.com", "/", "http:", "", 865},
	--ticketmaster
	{ 0, 0, 0, 179, 31, "ticketmaster.com", "/", "http:", "", 867},
	{ 0, 0, 0, 179, 31, "ticketmaster.ca", "/", "http:", "", 867},
	--tickets
	{ 0, 0, 0, 180, 31, "tickets.com", "/", "http:", "", 868},
	--tigerdirect
	{ 0, 0, 0, 181, 27, "tigerdirect.com", "/", "http:", "", 871},
	{ 0, 0, 0, 181, 27, "tigerdirect.ca", "/", "http:", "", 871},
	--travelocity
	{ 0, 0, 0, 182, 37, "travelocity.co", "/", "http:", "", 880},
	{ 0, 0, 0, 182, 37, "travelocity.ca", "/", "http:", "", 880},
	{ 0, 0, 0, 182, 37, "travelocity.co.uk", "/", "http:", "", 880},
	{ 0, 0, 0, 182, 37, "travelocity.com", "/", "http:", "", 880},
	{ 0, 0, 0, 182, 37, "tvlcdn.com", "/", "http:", "", 880},
	--vehix
	{ 0, 0, 0, 183, 36, "vehix.com", "/", "http:", "", 887},
	--venteprivee
	{ 0, 0, 0, 184, 32, "vente-privee.com", "/", "http:", "", 888},
	--victoriassecret
	{ 0, 0, 0, 185, 32, "victoriassecret.com", "/", "http:", "", 892},
	--walmart
	{ 0, 0, 0, 186, 30, "walmart.com", "/", "http:", "", 901},
	{ 0, 0, 0, 186, 30, "walmart.ca", "/", "http:", "", 901},
	--wikipedia
	{ 0, 0, 0, 187, 8, "wikipedia.org", "/", "http:", "", 501},
	--woot
	{ 0, 0, 0, 188, 30, "woot.com", "/", "http:", "", 917},
	--zales
	{ 0, 0, 0, 189, 26, "zales.com", "/", "http:", "", 930},
	--zappos
	{ 0, 0, 0, 190, 32, "zappos.com", "/", "http:", "", 931},
	--chase
	{ 0, 0, 0, 191, 39, "chase.com", "/", "http:", "", 587},
	--blockbuster
	{ 0, 0, 0, 192, 38, "blockbuster.co", "/", "http:", "", 575},
	{ 0, 0, 0, 192, 38, "blockbuster.ca", "/", "http:", "", 575},
	{ 0, 0, 0, 192, 38, "blockbusteronline.com.br", "/", "http:", "", 575},
	--dicks sporting goods	
	{ 0, 0, 0, 193, 29, "dickssportinggoods.com", "/", "http:", "", 611},
	--autotrader
	{ 0, 0, 0, 194, 36, "autotrader.com", "/", "http:", "", 558},
	--car&driver
	{ 0, 0, 0, 195, 35, "caranddriver.com", "/", "http:", "", 583},
	--jalopnik
	{ 0, 0, 0, 196, 35, "jalopnik.com", "/", "http:", "", 693},
	--autoblog
	{ 0, 0, 0, 197, 35, "autoblog.com", "/", "http:", "", 557},
	--topgear
	{ 0, 0, 0, 198, 35, "topgear.com", "/", "http:", "", 877},
	--kotaku
	{ 0, 0, 0, 199, 34, "kotaku.com", "/", "http:", "", 707},
	--redmine
	{ 0, 0, 0, 200, 43, "redmine.org", "/", "http:", "", 805},
	--JIRA
	{ 0, 0, 0, 201, 43, "onjira.com", "/", "http:", "", 695},
	--trac
	{ 0, 0, 0, 202, 43, "trac.edgewall.org", "/", "http:", "", 878},
	--launchpad 
	{ 0, 0, 0, 203, 43, "launchpad.net", "/", "http:", "", 708},
	--basecamp
	{ 0, 0, 0, 204, 43, "basecamphq.com", "/", "http:", "", 563},
	{ 0, 0, 0, 204, 43, "basecamp.com", "/", "http:", "", 563},
	--gap.inc
	{ 0, 0, 0, 205, 32, "gap.com", "/", "http:", "", 863},
	{ 0, 0, 0, 205, 32, "gapcanada.ca", "/", "http:", "", 863},
	{ 0, 0, 0, 205, 32, "gap.cn", "/", "http:", "", 863},
	{ 0, 0, 0, 205, 32, "gap.eu", "/", "http:", "", 863},
	{ 0, 0, 0, 205, 32, "gap.co.jp", "/", "http:", "", 863},
	--craigslist
	{ 0, 0, 0, 206, 15, "craigslist.org", "/", "http:", "", 594},
	{ 0, 0, 0, 206, 15, "craigslist.co", "/", "http:", "", 594},
	{ 0, 0, 0, 206, 15, "craigslist.ca", "/", "http:", "", 594},
	{ 0, 0, 0, 206, 15, "craigslist.de", "/", "http:", "", 594},
	{ 0, 0, 0, 206, 15, "craigslist.gr", "/", "http:", "", 594},
	{ 0, 0, 0, 206, 15, "craigslist.it", "/", "http:", "", 594},
	{ 0, 0, 0, 206, 15, "craigslist.pl", "/", "http:", "", 594},
	{ 0, 0, 0, 206, 15, "craigslist.pt", "/", "http:", "", 594},
	{ 0, 0, 0, 206, 15, "craigslist.es", "/", "http:", "", 594},
	{ 0, 0, 0, 206, 15, "craigslist.se", "/", "http:", "", 594},
	{ 0, 0, 0, 206, 15, "craigslist.ch", "/", "http:", "", 594},
	{ 0, 0, 0, 206, 15, "craigslist.hk", "/", "http:", "", 594},
	{ 0, 0, 0, 206, 15, "craigslist.jp", "/", "http:", "", 594},
}
function DetectorInit(detectorInstance)

    gDetector = detectorInstance;

    gDetector:addHttpPattern(2, 5, 0, 327, 24, 0, 0, 'TDA/Flex_Application', 860);
    gDetector:addHttpPattern(2, 5, 0, 327, 24, 0, 0, 'TDA/Flex_Aapplication', 860);

    if gDetector.addAppUrl then
        for i,v in ipairs(gUrlPatternList) do
            gDetector:addAppUrl(v[1],v[2],v[3],v[4],v[5],v[6],v[7],v[8],v[9],v[10]);
        end
    end
    return gDetector;
end

function DetectorClean()
end

