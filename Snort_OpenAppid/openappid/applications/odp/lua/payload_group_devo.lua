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
detection_name: Payload Group "Devo"
version: 26
description: Group of payload detectors.
bundle_description: $VAR1 = {
          'xda-developers' => 'Large online community of smartphone and tablet enthusiasts and developers.',
          'MyDownloader' => 'Service for downloading files from numerous file hosting sites such as Rapidshare.',
          'Justin.tv' => 'Live streaming video platform.',
          'Daum' => 'Popular South Korean web portal.',
          'TwitchTV' => 'Justin.tv gaming specific livestreaming platform.',
          'Issuu' => 'Web based document posting and sharing service.',
          'Weibo' => 'Chinese microblogging site produced by Sina.',
          'FilmOn' => 'Subscription based video on demand and TV streaming service.',
          '51.com' => 'Chinese social networking site.',
          'MOG' => 'Paid subscription online music service with streaming capability.',
          'FileDropper' => 'File hosting and sharing service.',
          'Schmedley' => 'Personalized web portal.',
          'Megashares' => 'File hosting and sharing service. Distinct from Megashare.',
          'Tudou' => 'Popular Chinese video sharing website.',
          'Writeboard' => 'Collaborative web based text editor.',
          'DepositFiles' => 'International file hosting and sharing service.',
          'Badoo' => 'Social networking service.',
          '4chan' => 'Website that hosts found images and discussions on them.',
          'iHeartRadio' => 'Website that provides streaming access to local and digital-only radio stations.',
          'Evony' => 'Browser-based online multiplayer game.',
          'Easy-Share' => 'File hosting and sharing service.',
          'folkd' => 'Social bookmarking and social news website.',
          'FileServe' => 'File hosting and sharing service.',
          'TransferBigFiles.com' => 'File hosting and sharing service.',
          '56.com' => 'Large Chinese video sharing site.',
          'Scribd' => 'Web based document posting and sharing service.',
          'dl.free.fr' => 'French based file hosting service.',
          'Deezer' => 'Music streaming service based in Paris.',
          'Mister Wong' => 'European social bookmarking service.',
          'Crackle' => 'Digital network providing streaming video content.',
          'Balatarin' => 'Social bookmarking and community website aimed at an Iranian audience.',
          'Kaixin001' => 'Chinese based social networking service.',
          'Me2day' => 'South Korean based social networking service.',
          'FORA.tv' => 'Website hosting videos of live events, lectures, and debates.',
          'ProxEasy' => 'Anonymous web based proxy service.',
          'The Hype Machine' => 'MP3 blog aggregator.',
          'Jubii' => 'Web portal providing search engine, e-mail, and file sharing services.',
          'DivShare' => 'File hosting and sharing service.',
          'Tinychat' => 'Web chat service with both instant messaging and video chat.',
          'Chatroulette' => 'Service that pairs random strangers for video chat.',
          'Livestream' => 'Live streaming video platform.',
          'WooMe' => 'Online service in which users meet and interact through video chat.',
          'Babelgum' => 'Internet TV service.',
          'Youku' => 'Chinese video hosting and sharing service.',
          'Tagged' => 'Social networking site based in California.',
          'Jango' => 'Internet radio and social networking service.',
          'Movieclips' => 'Streaming video site for movie clips.',
          'Skyrock' => 'Social networking site popular in France.',
          'MegaMeeting' => 'Web based conferencing platform.',
          'Gaia Online' => 'Anime themed social networking and forums website.',
          'ifile.it' => 'File storage service.',
          'hi5' => 'Social networking and social gaming platform.',
          'CloudMe' => 'Web desktop service.',
          'Filemail' => 'File hosting and sharing service.',
          'Livemocha' => 'Language learning community and platform offering free and paid language courses.',
          'BigUpload' => 'File hosting and sharing service.',
          'Avoidr' => 'Web based proxy compatible with many popular social networking sites.',
          'Octopz' => 'Web based collaboration tool.',
          'VKontakte' => 'Russian social networking service.',
          'Webshots' => 'Service for uploading and sharing photos and videos.',
          'GOGOBOX' => 'Chinese based web portal.',
          'Tesco.com' => 'General E-commerce website.',
          'Dangdang' => 'Chinese general E-commerce company.',
          'we7' => 'Music streaming service.',
          'RuTube' => 'Russian online video sharing service.',
          'PC Connection' => 'Computer and electronic products retailer.',
          'TotoExpress' => 'Platform for sending and receiving large files.',
          'Phanfare' => 'Subscription based photo and video sharing service.',
          'CiteULike' => 'Social bookmarking-esque site for scholarly papers and references.',
          'Hushmail' => 'Web mail service providing encrypted and virus scanned e-mail.',
          'Rhapsody' => 'Online streaming music service.',
          'RuneScape' => 'Browser based fantasy role-playing game.',
          'Songza' => 'Web radio and music streaming service.',
          'SoundCloud' => 'Music platform for artists to upload and promote their music.',
          'VTunnel' => 'Web based proxy service.',
          'Douban' => 'Chinese social networking service.',
          'Megashare' => 'File hosting and sharing service. Distinct from Megashares.',
          'Rdio' => 'Music subscription service.',
          'Surrogafier' => 'Free proxy service.',
          'Clarizen' => 'Work management and project management system.',
          'Tuenti' => 'Invite only social networking website based in Spain.',
          'AutoZone' => 'Automotive parts and accessories retailer.',
          'Suresome' => 'Web based encrypted proxy service.',
          'PC Mall' => 'Computer and electronic products retailer.',
          'Licorize' => 'Social bookmarking service.',
          'Afreeca' => 'Video streaming service based in South Korea.',
          'yfrog' => 'Site for posting and sharing photos and videos on twitter.',
          'Neopets' => 'Virtual pet website.',
          'GMX Mail' => 'German based webmail service.',
          'Odnoklassniki' => 'Russian social networking service.',
          'MyHeritage' => 'Family oriented social networking service.',
          '7digital' => 'Digital music and video delivery company.',
          'Webhard' => 'Online storage service available in Korean and English.',
          'BigBlueButton' => 'Web conferencing system.',
          'Habbo' => 'Social networking site aimed at teenagers.',
          'Mibbit' => 'Web based chat client that supports IRC and Twitter.',
          'Slacker' => 'Internet radio service.',
          'Omegle' => 'Online chat service that pairs together strangers.',
          'TurboUpload' => 'File hosting and sharing service.',
          'Cyworld' => 'South Korean social networking service.',
          'Qriocity' => 'Streaming music and video on demand service from Sony.',
          'NeoGAF' => 'Internet forum based around video games.',
          'TwitPic' => 'Site for posting and sharing photos and videos on twitter.',
          'Jamendo' => 'Website that allows for the streaming, downloading, and uploading of free music.'
        };

--]]

require "DetectorCommon"

local DC = DetectorCommon

DetectorPackageInfo = {
    name =  "payload_group_devo",
    proto =  DC.ipproto.tcp,
    client = {
        init =  'DetectorInit',
        clean =  'DetectorClean',
        minimum_matches =  1
    }
}

--serviceId, clientId, ClientType, PayloadId, PayloadType, hostPattern, pathPattern, schemePattern, queryPattern
gUrlPatternList = {
	--7digital
	{ 0, 0, 0, 291, 15, "7digital.com", "/", "http:", "", 959},
	--avoidr
	{ 0, 0, 0, 292, 46, "avoidr.com", "/", "http:", "", 960},
	--badongo
	-- { 0, 0, 0, 293, 9, "badongo.com", "/", "http:", "", 961},
	--chatroulette
	{ 0, 0, 0, 294, 10, "chatroulette.com", "/", "http:", "", 962},
	--cyworld
	{ 0, 0, 0, 295, 5, "cyworld.co", "/", "http:", "", 963},
	{ 0, 0, 0, 295, 5, "cyworld.vn", "/", "http:", "", 963},
	--daum
	{ 0, 0, 0, 296, 22, "daum.net", "/", "http:", "", 964},
	--deezer
	{ 0, 0, 0, 297, 13, "deezer.com", "/", "http:", "", 965},
	--divshare
	{ 0, 0, 0, 298, 9, "divshare.com", "/", "http:", "", 966},
	--dl.free.fr
	{ 0, 0, 0, 299, 9, "dl.free.fr", "/", "http:", "", 967},
	--gowalla
	-- { 0, 0, 0, 300, 5, "gowalla.com", "/", "http:", "", 968},
	--evony
	{ 0, 0, 0, 302, 20, "evony.com", "/", "http:", "", 970},
	--filedropper
	{ 0, 0, 0, 303, 9, "filedropper.com", "/", "http:", "", 971},
	--filemail 
	{ 0, 0, 0, 304, 9, "filemail.com", "/", "http:", "", 972},
	--fileserve
	{ 0, 0, 0, 305, 9, "fileserve.com", "/", "http:", "", 973},
	--licorize
	{ 0, 0, 0, 306, 14, "licorize.com", "/", "http:", "", 974},
	--folkd
	{ 0, 0, 0, 307, 14, "folkd.com", "/", "http:", "", 975},
	--fora.tv
	{ 0, 0, 0, 308, 1, "fora.tv", "/", "http:", "", 976},
	--gmx mail
	{ 0, 0, 0, 309, 4, "gmx.co", "/", "http:", "", 977},
	{ 0, 0, 0, 309, 4, "gmx.net", "/", "http:", "", 977},
	--gogobox
	{ 0, 0, 0, 310, 22, "gogobox.com", "/", "http:", "", 978},
	--citeulike
	{ 0, 0, 0, 311, 14, "citeulike.org", "/", "http:", "", 979},
	--habbo
	{ 0, 0, 0, 312, 5, "habbo.co", "/", "http:", "", 980},
	{ 0, 0, 0, 312, 5, "habbo.at", "/", "http:", "", 980},
	{ 0, 0, 0, 312, 5, "habbo.be", "/", "http:", "", 980},
	{ 0, 0, 0, 312, 5, "habbo.cl", "/", "http:", "", 980},
	{ 0, 0, 0, 312, 5, "habbo.cn", "/", "http:", "", 980},
	{ 0, 0, 0, 312, 5, "habbo.dk", "/", "http:", "", 980},
	{ 0, 0, 0, 312, 5, "habbo.fi", "/", "http:", "", 980},
	{ 0, 0, 0, 312, 5, "habbo.fr", "/", "http:", "", 980},
	{ 0, 0, 0, 312, 5, "habbo.de", "/", "http:", "", 980},
	{ 0, 0, 0, 312, 5, "habbo.it", "/", "http:", "", 980},
	{ 0, 0, 0, 312, 5, "habbo.jp", "/", "http:", "", 980},
	{ 0, 0, 0, 312, 5, "habbo.com", "/", "http:", "", 980},
	--hushmail
	{ 0, 0, 0, 313, 4, "hushmail.com", "/", "http:", "", 981},
	--hypemachine
	{ 0, 0, 0, 314, 13, "hypem.com", "/", "http:", "", 982},
	--ifile.it
	{ 0, 0, 0, 315, 9, "ifile.it", "/", "http:", "", 983},
	--iheartradio
	{ 0, 0, 0, 316, 13, "iheartradio.com", "/", "http:", "", 984},
	{ 0, 0, 0, 316, 13, "iheart.com", "/", "http:", "", 984},
	--issuu
	{ 0, 0, 0, 317, 9, "issuu.co", "/", "http:", "", 985},
	--jamendo
	{ 0, 0, 0, 318, 13, "jamendo.com", "/", "http:", "", 986},
	--jango
	{ 0, 0, 0, 319, 13, "jango.com", "/", "http:", "", 987},
	--justin.tv
	{ 0, 0, 0, 320, 13, "justin.tv", "/", "http:", "", 988},
	--kaixin001
	{ 0, 0, 0, 321, 5, "kaixin001.com", "/", "http:", "", 989},
	--kickload
	--{ 0, 0, 0, 322, 9, "kickload.com", "/", "http:", "", 990},
	--livestream
	{ 0, 0, 0, 323, 13, "livestream.com", "/", "http:", "", 991},
	--me2day
	{ 0, 0, 0, 324, 5, "me2day.net", "/", "http:", "", 992},
	--megashare
	{ 0, 0, 0, 325, 9, "megashare.com", "/", "http:", "", 993},
	--megashares
	{ 0, 0, 0, 326, 9, "megashares.co", "/", "http:", "", 994},
	{ 0, 0, 0, 326, 9, "megashares.com", "/", "http:", "", 994},
	--mydownloader
	{ 0, 0, 0, 327, 9, "mydownloader.net", "/", "http:", "", 995},
	--neopets
	{ 0, 0, 0, 328, 20, "neopets.com", "/", "http:", "", 996},
	--omegle
	{ 0, 0, 0, 329, 10, "omegle.com", "/", "http:", "", 997},
	--misterwong
	{ 0, 0, 0, 331, 14, "mister-wong.com", "/", "http:", "", 999},
	{ 0, 0, 0, 331, 14, "mister-wong.de", "/", "http:", "", 999},
	{ 0, 0, 0, 331, 14, "mister-wong.fr", "/", "http:", "", 999},
	{ 0, 0, 0, 331, 14, "mister-wong.es", "/", "http:", "", 999},
	{ 0, 0, 0, 331, 14, "mister-wong.ru", "/", "http:", "", 999},
	{ 0, 0, 0, 331, 14, "mister-wong.cn", "/", "http:", "", 999},
	--privax
	--{ 0, 0, 0, 332, 46, "privax.us", "/", "http:", "", 1000},
	--proxeasy
	{ 0, 0, 0, 333, 46, "proxeasy.com", "/", "http:", "", 1001},
	--qriocity
	{ 0, 0, 0, 334, 13, "qriocity.com", "/", "http:", "", 1002},
	--runescape
	{ 0, 0, 0, 335, 20, "runescape.com", "/", "http:", "", 1003},
	--schmedley
	{ 0, 0, 0, 336, 22, "schmedley.com", "/", "http:", "", 1004},
	--scribd
	{ 0, 0, 0, 337, 9, "scribd.com", "/", "http:", "", 1005},
	--songza
	{ 0, 0, 0, 338, 13, "songza.com", "/", "http:", "", 1006},
	--soundcloud
	{ 0, 0, 0, 339, 9, "soundcloud.com", "/", "http:", "", 1007},
	{ 0, 0, 0, 339, 9, "soundcloud.us", "/", "http:", "", 1007},
	--steekr
	-- { 0, 0, 0, 340, 9, "steekr.com", "/", "http:", "", 1008},
	--stickam
	--{ 0, 0, 0, 341, 13, "stickam.com", "/", "http:", "", 1009},
	--suresome
	{ 0, 0, 0, 342, 46, "suresome.com", "/", "http:", "", 1010},
	--surrogafier
	{ 0, 0, 0, 343, 46, "surrogafier.info", "/", "http:", "", 1011},
	--tagoo
	-- { 0, 0, 0, 344, 22, "tagoo.ru", "/", "http:", "", 1012},
	--tinychat
	{ 0, 0, 0, 345, 10, "tinychat.com", "/", "http:", "", 1013},
	--tudou
	{ 0, 0, 0, 346, 13, "tudou.com", "/", "http:", "", 1014},
	--transferbigfiles
	{ 0, 0, 0, 347, 9, "transferbigfiles.com", "/", "http:", "", 1015},
	--tuenti
	{ 0, 0, 0, 348, 5, "tuenti.com", "/", "http:", "", 1016},
	--turboupload
	{ 0, 0, 0, 349, 9, "turboupload.com", "/", "http:", "", 1017},
	--vkontakte
	{ 0, 0, 0, 350, 5, "vkontakte.ru", "/", "http:", "", 1018},
	{ 0, 0, 0, 350, 5, "vk.com", "/", "http:", "", 1018},
	--vtunnel
	{ 0, 0, 0, 351, 46, "vtunnel.com", "/", "http:", "", 1019},
	--webhard
	{ 0, 0, 0, 352, 9, "webhard.net", "/", "http:", "", 1020},
	{ 0, 0, 0, 352, 9, "webhard.co.kr", "/", "http:", "", 1020},
	--webshots
	{ 0, 0, 0, 353, 9, "webshots.com", "/", "http:", "", 1021},
	--weibo
	{ 0, 0, 0, 354, 5, "weibo.com", "/", "http:", "", 1022},
	--wixi (Deprecated)
	--{ 0, 0, 0, 355, 9, "wixi.com", "/", "http:", "", 1023},
	--woofiles
	--{ 0, 0, 0, 356, 9, "woofiles.com", "/", "http:", "", 1024},
	--woome
	{ 0, 0, 0, 357, 5, "woome.com", "/", "http:", "", 1025},
	--writeboard
	{ 0, 0, 0, 358, 11, "writeboard.com", "/", "http:", "", 1026},
	--bigupload
	{ 0, 0, 0, 359, 9, "bigupload.com", "/", "http:", "", 1027},
	{ 0, 0, 0, 359, 9, "bigupload.net", "/", "http:", "", 1027},
	--clarizen
	{ 0, 0, 0, 360, 43, "clarizen.com", "/", "http:", "", 1028},
	{ 0, 0, 0, 360, 43, "clarizen.jp", "/", "http:", "", 1028},
	--rdio
	{ 0, 0, 0, 361, 13, "rdio.com", "/", "http:", "", 1029},
	--ubetoo
	--{ 0, 0, 0, 362, 13, "ubetoo.com", "/", "http:", "", 1030},
	--56.com
	{ 0, 0, 0, 363, 13, "56.com", "/", "http:", "", 1031},
	--51.com
	{ 0, 0, 0, 364, 5, "51.com", "/", "http:", "", 1032},
	--youku
	{ 0, 0, 0, 365, 13, "youku.com", "/", "http:", "", 1033},
	--crackle
	{ 0, 0, 0, 366, 13, "crackle.com", "/", "http:", "", 1034},
	--rutube
	{ 0, 0, 0, 367, 13, "rutube.ru", "/", "http:", "", 1035},
	--joost
	--{ 0, 0, 0, 368, 13, "joost.com", "/", "http:", "", 1036},
	--afreeca
	{ 0, 0, 0, 369, 13, "afreeca.com", "/", "http:", "", 1037},
	{ 0, 0, 0, 369, 13, "bizafreeca.com", "/", "http:", "", 1037},
	{ 0, 0, 0, 369, 13, "afreecatv.com", "/", "http:", "", 1037},
	--babelgum
	{ 0, 0, 0, 370, 13, "babelgum.com", "/", "http:", "", 1038},
	--filesonic
	--{ 0, 0, 0, 371, 9, "filesonic.com", "/", "http:", "", 1039},
	--octopz
	{ 0, 0, 0, 372, 8, "octopz.com", "/", "http:", "", 1040},
	--mog
	{ 0, 0, 0, 373, 13, "mog.com", "/", "http:", "", 1041},
	--multiply
	-- { 0, 0, 0, 375, 5, "multiply.com", "/", "http:", "", 1043},
	--sevenload
	--{ 0, 0, 0, 376, 13, "sevenload.com", "/", "http:", "", 1044},
	--revver
	--{ 0, 0, 0, 377, 13, "revver.com", "/", "http:", "", 1045},
	--phanfare
	{ 0, 0, 0, 378, 9, "phanfare.com", "/", "http:", "", 1046},
	--we7
	{ 0, 0, 0, 379, 13, "we7.com", "/", "http:", "", 1047},
	{ 0, 0, 0, 379, 13, "we7.be", "/", "http:", "", 1047},
	--filmon
	{ 0, 0, 0, 380, 13, "filmon.com", "/", "http:", "", 1048},
	--mibbit
	{ 0, 0, 0, 381, 10, "mibbit.com", "/", "http:", "", 1049},
	{ 0, 0, 0, 381, 10, "mibbit.fr", "/", "http:", "", 1049},
	{ 0, 0, 0, 381, 10, "mibbitchat.de", "/", "http:", "", 1049},
	--bigbluebutton
	{ 0, 0, 0, 382, 21, "bigbluebutton.org", "/", "http:", "", 1050},
	--twitchtv
	{ 0, 0, 0, 383, 13, "twitch.tv", "/", "http:", "", 1051},
	--megameeting
	{ 0, 0, 0, 384, 21, "megameeting.co", "/", "http:", "", 1052},
	--badoo
	{ 0, 0, 0, 385, 5, "badoo.com", "/", "http:", "", 1053},
	--depositfiles
	{ 0, 0, 0, 386, 9, "depositfiles.com", "/", "http:", "", 1054},
	--cloudme
	{ 0, 0, 0, 387, 22, "cloudme.com", "/", "http:", "", 1055},
	--esnips
	--{ 0, 0, 0, 388, 9, "esnips.com", "/", "http:", "", 1056},
	--skyrock
	{ 0, 0, 0, 389, 5, "skyrock.com", "/", "http:", "", 1057},
	--files.to
	--{ 0, 0, 0, 390, 9, "files.to", "/", "http:", "", 1058},
	--fufox
	--{ 0, 0, 0, 391, 9, "fufox.net", "/", "http:", "", 1059},
	--jubii
	{ 0, 0, 0, 392, 22, "jubii.dk", "/", "http:", "", 1060},
	--totoexpress
	{ 0, 0, 0, 393, 9, "totoexpress.com", "/", "http:", "", 1061},
	--easy-share
	{ 0, 0, 0, 394, 9, "easy-share.com", "/", "http:", "", 1062},
	--twitpic
	{ 0, 0, 0, 395, 9, "twitpic.com", "/", "http:", "", 1063},
	--yfrog
	{ 0, 0, 0, 396, 9, "yfrog.com", "/", "http:", "", 1064},
	--tagged
	{ 0, 0, 0, 397, 5, "tagged.com", "/", "http:", "", 1065},
	--hi5
	{ 0, 0, 0, 398, 5, "hi5.com", "/", "http:", "", 1066},
	--livemocha
	{ 0, 0, 0, 399, 12, "livemocha.com", "/", "http:", "", 1067},
	--slacker
	{ 0, 0, 0, 400, 13, "slacker.com", "/", "http:", "", 1068},
	--douban
	{ 0, 0, 0, 401, 5, "douban.com", "/", "http:", "", 1069},
	--odnoklassniki
	{ 0, 0, 0, 402, 5, "odnoklassniki.ru", "/", "http:", "", 1070},
	--gaia online
	{ 0, 0, 0, 403, 5, "gaiaonline.com", "/", "http:", "", 1071},
	--myheritage
	{ 0, 0, 0, 404, 5, "myheritage.", "/", "http:", "", 1072},
	--autozone
	{ 0, 0, 0, 405, 36, "autozone.com", "/", "http:", "", 1073},
	--dangdang
	{ 0, 0, 0, 406, 45, "dangdang.com", "/", "http:", "", 1074},
	--pcmall
	{ 0, 0, 0, 407, 27, "pcmall.com", "/", "http:", "", 1075},
	--pcconnection
	{ 0, 0, 0, 408, 27, "pcconnection.com", "/", "http:", "", 1109},
	--tesco
	{ 0, 0, 0, 409, 45, "tesco.com", "/", "http:", "", 1077},
	--xda-developers
	{ 0, 0, 0, 410, 23, "xda-developers.com", "/", "http:", "", 1078},
	--4chan
	{ 0, 0, 0, 411, 23, "4chan.org", "/", "http:", "", 1079},
	--neogaf
	{ 0, 0, 0, 412, 23, "neogaf.com", "/", "http:", "", 1080},
	--rhapsody
	{ 0, 0, 0, 413, 13, "rhapsody.com", "/", "http:", "", 1081},
	--balatarin
	{ 0, 0, 0, 414, 14, "balatarin.com", "/", "http:", "", 1082},
	--oneview
	--{ 0, 0, 0, 415, 14, "oneview.com", "/", "http:", "", 1083},
	--{ 0, 0, 0, 415, 14, "oneview.de", "/", "http:", "", 1083},
	--movieclips
	{ 0, 0, 0, 416, 13, "movieclips.com", "/", "http:", "", 1084},

}

function DetectorInit(detectorInstance)

    gDetector = detectorInstance;

    gDetector:addHttpPattern(2, 5, 0, 414, 19, 0, 0, 'iHeartRadio/', 984);

    if gDetector.addAppUrl then
        for i,v in ipairs(gUrlPatternList) do
            gDetector:addAppUrl(v[1],v[2],v[3],v[4],v[5],v[6],v[7],v[8],v[9],v[10]);
        end
    end
    return gDetector;
end

function DetectorClean()
end

