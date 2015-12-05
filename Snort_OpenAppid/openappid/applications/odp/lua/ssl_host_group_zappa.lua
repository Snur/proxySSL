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
detection_name: SSL Group "Zappa"
version: 5
description: Group of SSL Host detectors.
bundle_description: $VAR1 = {
          'AOL Ads' => 'AOL advertisement site.',
          'Datei.to' => 'German file sharing service.',
          'AD-X Tracking' => 'Data analysis and monitor ad related traffic tarfette for mobile application.',
          'Chango' => 'Advertisement site.',
          '12306.cn' => 'China Railway online customer service.',
          'Connexity' => 'Advertisement site.',
          'CloudFlare' => 'Advertisement site.',
          'AdRoll' => 'Online advertising and Retargetting website vistor.',
          'Commvault' => 'Enterprise data backup and storage management software.',
          'Aggregate Knowledge' => 'Advertisement site.',
          'Shareman' => 'Traffic generated from chat and file transfer service by Shareman client.',
          'Bazaarvoice' => 'Online service that provides data and analystics to brands/customer.',
          'TISTORY' => 'Korean Blog publishing service.',
          'DataLogicx' => 'Advertisement site.',
          'Apple sites' => 'Apple corporate websites.',
          'Aliyun' => 'Chinese web portal.',
          'Allegro.pl' => 'Polish auction website.',
          'Classmates' => 'Social networking site that allows schoolmates to connect via yearbook photograph.',
          'Mendeley' => 'A tool for sharing, storing, and organizing reference material such as PDFs.',
          'LogMeIn Rescue' => 'A remote desktop support tool.',
          'eFax' => 'Internet fax service.',
          '4shared' => 'File sharing and storage service.',
          'ClickBooth' => 'Advertisement site.',
          'Admeld' => 'Ad delivery company servicing online publishers.',
          'Compuware' => 'Advertisement site.',
          'Adtegrity' => 'Advertisement site.',
          'Concur' => 'Business travel site.',
          'Astraweb' => 'A Usenet/newsgroup service provider.',
          'Bing' => 'Microsoft\'s internet search engine.',
          'Alibaba' => 'International trade site.',
          'Dropbox' => 'Cloud based file storage.',
          'Criteo' => 'Advertisement site.',
          'ADMETA' => 'Advertisement site.',
          'cXense' => 'Advertisement site.',
          'AdF.ly' => 'URL shortening service.',
          'Adometry' => 'Advertisement site.',
          'AdXpose' => 'Advertisement site.',
          'ADrive' => 'Online file storage and backup.',
          'AdReady' => 'Advertisement site.',
          'Compete' => 'Data-driven marketing and advertising platform.',
          'Blogger' => 'A blog publishing service owned by Google, formerly known as blogspot.',
          'Acrobat.com' => 'Adobe file transfer and PDF conversion site.',
          'AudienceScience' => 'Online marketing.',
          'AdGear' => 'Advertisement site.',
          'CBS' => 'CBS news website.',
          'ClickTale' => 'Advertisement site.',
          'Bizo' => 'Advertisement site.',
          'Bild.de' => 'Online edition of German tabloid.',
          'AppNexus' => 'Real-time advertising services.',
          'Brightroll' => 'Advertisement site.',
          'Backblaze' => 'Online backup tool for Windows and Mac users.',
          'Egloos' => 'Korean blog host.',
          'Casale' => 'Advertisement site.',
          'CBS Interactive' => 'Division of CBS Corporation which coordinates ad sales and television programs together.',
          'Amazon' => 'Online retailer of books and most other goods.',
          'Atlas Advertiser Suite' => 'Tools for online advertising.',
          'Conduit' => 'Online website to create community toolbar.',
          'ezhelp' => 'Allows remote access.',
          'BlueKai' => 'Data-driven online marketing.',
          'Onehub' => 'A cloud storage provider.',
          'Barnes and Noble' => 'Online retailer of books and other goods.',
          'Brighttalk' => 'Online webinar and video provider.',
          'AdJuggler' => 'Advertisement site.',
          'Booking.com' => 'Online travel reservation site.',
          'Adconion Media Group' => 'Multi-channel ad delivery company.',
          'DioDeo' => 'Korean Entertainment news.',
          'Answers.com' => 'A site that provides original answers to questions.',
          'Bloomberg' => 'Financial news and research.',
          'Crowd Science' => 'Advertisement site.',
          'Bet365' => 'Online gambling website.',
          'Boxcar.io' => 'Social media and RSS aggregator. Different site than boxcar.com.',
          'Connextra' => 'Advertisement site.',
          '17173.com' => 'Chinese social networking site.',
          'Cognitive Match' => 'Advertisement site.'
        };

--]]

require "DetectorCommon"


local DC = DetectorCommon

DetectorPackageInfo = {
    name =  "ssl_host_group_zappa",
    proto =  DC.ipproto.tcp,
    client = {
        init =  'DetectorInit',
        clean =  'DetectorClean',
        minimum_matches =  1
    }
}

--detectorType(0-> Web, 1->Client),  AppId, SSLPattern
gSSLHostPatternList = {

    -- LogMeIn Rescue 
    { 0, 3784, 'secure.logmeinrescue.com' },
    -- Mendeley
    { 0, 3785, 'mendeley.com' },
    { 0, 3785, 'mix.mendeley.com' },
    { 0, 3785, 'www.mendeley.com' },
    -- Onehub
    { 0, 3786, 'onehub.com' },
    -- Bazaarvoice
    { 0, 2938, 'bazaarvoice.com' },
    -- Shareman
    { 0, 2918, 'shareman.tv' },
    -- 12306.cn
    { 0, 1205, '12306.cn' },
    -- 4shared
    { 0, 948, '4shared.com' },
    -- Acrobat.com
    { 0, 1322, 'acrobat.com' },
    -- AD-X Tracking
    { 0, 2850, 'adxtracking.com' },
    { 0, 2850, 'ad-x.co.uk' },
    -- AdF.ly
    { 0, 1257, 'adf.ly' },
    -- AdGear
    { 0, 2500, 'adgear.com' },
    -- AdJuggler
    { 0, 2575, 'adjuggler.com' },
    -- ADMETA
    { 0, 2569, 'admeta.com' },
    -- Adometry
    { 0, 2556, 'adometry.com' },
    { 0, 2556, 'clickforensics.com' },
    -- AdReady
    { 0, 2497, 'adready.com' },
    -- ADrive
    { 0, 17, 'adrive.com' },
    -- AdRoll
    { 0, 2848, 'adroll.com' },
    -- AdXpose
    { 0, 2538, 'adxpose.com' },
    -- Aggregate Knowledge
    { 0, 2547, 'aggregateknowledge.com' },
    -- Alibaba
    { 0, 2386, 'alibaba.com' },
    -- Aliyun
    { 0, 2389, 'aliyun.com' },
    -- Allegro.pl
    { 0, 2851, 'allegro.pl' },
    -- Amazon
    { 0, 24, 'amazon.com' },
    { 0, 24, 'amazon.jobs' },
    { 0, 24, 'amazon.in' },
    { 0, 24, 'amazon.es' },
    { 0, 24, 'amazon.de' },
    { 0, 24, 'amazon.co.uk' },
    { 0, 24, 'amazon.co.jp' },
    { 0, 24, 'amazon.ca' },
    -- Answers.com
    { 0, 1168, 'answers.com' },
    -- Bild.de
    { 0, 1196, 'bild.de' },
    -- Bing
    { 0, 58, 'bing.com' },
    { 0, 58, 'bing.net' },
    -- Bizo
    { 0, 2557, 'bizo.com' },
    { 0, 2557, 'bizographics.com' },
    -- Blogger
    { 0, 576, 'blogger.com' },
    { 0, 576, 'blogspot.com' },
    -- Booking.com
    { 0, 2600, 'booking.com' },
    { 0, 2600, 'workingatbooking.com' },
    -- BlueKai
    { 0, 2452, 'bluekai.com' },
    -- Bloomberg
    { 0, 1259, 'bloomberg.com' },
    { 0, 1259, 'bloomberg.net' },
    { 0, 1259, 'bna.com' },
    { 0, 1259, 'bgov.com' },
    { 0, 1259, 'bloombergview.com' },
    { 0, 1259, 'businessweek.com' },
    { 0, 1259, 'bloombergtradebook.com' },
    { 0, 1259, 'bloombergbriefs.com' },
    { 0, 1259, 'bloombergindexes.com' },
    { 0, 1259, 'bloombergsef.com' },
    { 0, 1259, 'bloomberglaw.com' },
    { 0, 1259, 'bloomberglink.com' },
    { 0, 1259, 'bloombergsports.com' },
    -- eFax
    { 0, 3789, 'efax.com' },
    -- Adconion Media Group
    { 0, 2414, 'adconion.com' },
    -- AOL Ads
    { 0, 2578, 'advertising.aol.com' },
    -- Admeld
    { 0, 2454, 'admeld.com' },
    -- Apple sites
    { 0, 1185, 'apple.com' },
    { 0, 1185, 'apple-darwin.net' },
    { 0, 1185, 'applereach.net' },
    { 0, 1185, 'calendarserver.org' },
    { 0, 1185, 'cups.org' },
    { 0, 1185, 'desktopmovie.net' },
    { 0, 1185, 'dvdstudiopro.info' },
    { 0, 1185, 'dvdstudiopro.net' },
    { 0, 1185, 'imac-apple.com' },
    { 0, 1185, 'iwork.com' },
    { 0, 1185, 'myapple.net' },
    { 0, 1185, 'playquicktime.com' },
    { 0, 1185, 'publishing-research.org' },
    { 0, 1185, 'publishingsurvey.org' },
    { 0, 1185, 'quicktime.cc' },
    { 0, 1185, 'rip-mix-burn.com' },
    { 0, 1185, 'ripmixburn.com' },
    { 0, 1185, 'thinkdifferent.com' },
    { 0, 1185, 'xserve.com' },
    -- 17173.com
    { 0, 2385, '17173.com' },
    -- AppNexus
    { 0, 2413, 'appnexus.com' },
    { 0, 2413, 'alenty.com' },
    -- Astraweb
    { 0, 38, 'astraweb.com' },
    -- Atlas Advertiser Suite
    { 0, 2456, 'atlassolutions.com' },
    -- AudienceScience
    { 0, 2467, 'audiencescience.com' },
    -- Backblaze
    { 0, 47, 'backblaze.com' },
    -- Barnes and Noble
    { 0, 561, 'barnesandnoble.com' },
    -- Bet365
    { 0, 1209, 'bet365.com' },
    { 0, 1209, 'bet365careers.com' },
    -- Adtegrity
    { 0, 2577, 'adtegrity.com' },
    -- Boxcar.io
    { 0, 2605, 'boxcar.io' },
    -- Brightroll
    { 0, 2558, 'brightroll.com' },
    -- Brighttalk
    { 0, 1211, 'brighttalk.com' },
    -- Casale
    { 0, 2512, 'indexexchange.com' },
    { 0, 2512, 'medianet.com' },
    -- CBS
    { 0, 1332, 'cbsnews.com' },
    -- CBS Interactive
    { 0, 2354, 'cbspressexpress.com' },
    { 0, 2354, 'cbsi.secure.force.com' },
    -- Chango
    { 0, 2513, 'chango.com' },
    -- Classmates
    { 0, 1169, 'classmates.com' },
    -- ClickBooth
    { 0, 2585, 'clickbooth.com' },
    -- ClickTale
    { 0, 2502, 'clicktale.com' },
    -- CloudFlare
    { 0, 2535, 'cloudflare.com' },
    -- Cognitive Match
    { 0, 2528, 'cognitivematch.com' },
    -- Compete
    { 0, 2458, 'compete.com' },
    -- Compuware
    { 0, 2579, 'compuware.com' },
    -- Commvault
    { 0, 96, 'commvault.com' },
    -- Concur
    { 0, 2601, 'concur.com' },
    { 0, 2601, 'concur.de' },
    { 0, 2601, 'concur.ca' },
    { 0, 2601, 'concur.nl' },
    { 0, 2601, 'concur.fr' },
    { 0, 2601, 'concur.co.uk' },
    { 0, 2601, 'concur.co.in' },
    { 0, 2601, 'concur.co.jp' },
    -- Conduit
    { 0, 1375, 'conduit.com' },
    { 0, 1375, 'como.com' },
    -- Connexity
    { 0, 2555, 'connexity.com' },
    -- Connextra
    { 0, 2529, 'connextra.com' },
    -- Criteo
    { 0, 2514, 'criteo.com' },
    -- Crowd Science
    { 0, 2591, 'yumenetworks.com' },
    -- cXense
    { 0, 2572, 'cxense.com' },
    -- DataLogicx
    { 0, 2542, 'datalogix.com' },
    -- Datei.to
    { 0, 1260, 'datei.to' },
    -- TISTORY
    { 0, 3798, 'tistory.com' },
    -- DioDeo 
    { 0, 3799, 'diodeo.com' },
    -- Egloos
    { 0, 3800, 'egloos.com' },
    -- ezhelp
    { 0, 3803, 'ezhelp.co.kr' },
    -- Dropbox
    { 0, 125, 'dropbox.com' },
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

