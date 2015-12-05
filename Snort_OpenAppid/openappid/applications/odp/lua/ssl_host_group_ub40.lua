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
detection_name: SSL Group "UB40"
version: 2
description: Group of SSL Host detectors.
bundle_description: $VAR1 = {
          'The Pirate Bay' => 'BitTorrent index and search engine.',
          'Indiegogo' => 'Online Fund raiser for new ideas/products.',
          'Creative Commons' => 'Non-profit organization to share your creativity legally without losing the credits.',
          'TIME.com' => 'Webportal for TIME Magazine.',
          'Coursera' => 'Educational site connecting people, offer online courses from top universities.',
          'MovieTickets.com' => 'Webportal for advanced movie ticketing, reviews and celebrity interviews.',
          'MailChimp' => 'Email service provider.',
          'Bluehost' => 'Web hosting portal.',
          'Lycos' => 'Search engine also offers email, web hosting and social networking.',
          'Zbigz' => 'Online BitTorrent Client.',
          'AT&T' => 'Telecom and Internet provider.',
          'BBB' => 'Better Business Bureau - non-profit organization providing reliable business review.',
          'iHeartRadio' => 'Website that provides streaming access to local and digital-only radio stations.',
          'Google Translate' => 'Google translation service.',
          'Viddler' => 'Online Video hosting service.',
          'OverBlog' => 'Platform to create blogs.',
          'HugeDomains.com' => 'Domain hosting service.',
          'Nest Thermostat' => 'Manufactures of sensor driven Thermostats which are self-learning and programmable.',
          'Xfire' => 'Instant Messenger for gamers.',
          'Stanford University' => 'Official website for Stanford University, Educational Institute.',
          'Jimdo' => 'Portal for to creating web site/blog.',
          'NAI' => 'Network Advertising Initiative - association comprises of 3rd party ad companies and educate consumers with online advertising.',
          'Bandcamp' => 'Explore online music posted by independendent artist.',
          'Websense' => 'Company which produces Cyber security related products.',
          'Comcast Mail' => 'Email service provided by Comcast.',
          'Hopster' => 'A couponing site.',
          'Zattoo' => 'Internet protocol television.',
          'Zulily' => 'Online shopping aimed for Moms with childerns apparel and home decor items.',
          'ConnMan' => 'Plug-in for managing internet connectivity in the linux based embedded devices.',
          'bitly' => 'Web portal for bookmarking and sharing links.',
          'Harvard University' => 'Official website for Harvard University, Educational Institute.',
          'GNU Project' => 'Aggregates free software for Unix-compatible system.',
          'Oracle sites' => 'The website for Oracle.',
          'TinyURL' => 'Shortens the long URL.',
          'phpBB' => 'PHP based open source bulletin board software.',
          'Parallels' => 'Cloud services enablement and virtual access.'
        };

--]]

require "DetectorCommon"


local DC = DetectorCommon

DetectorPackageInfo = {
    name =  "ssl_host_group_bitters",
    proto =  DC.ipproto.tcp,
    client = {
        init =  'DetectorInit',
        clean =  'DetectorClean',
        minimum_matches =  1
    }
}

--detectorType(0-> Web, 1->Client),  AppId, SSLPattern
gSSLHostPatternList = {

    -- AT&T
    { 0, 1380, 'att.com' },
    { 0, 1380, 'att.net' },
    { 0, 1380, 'attccc.com' },
    -- Oracle
    { 0, 2245, 'oracle.com' },
    -- iHeart 
    { 0, 984, 'iheart.com' },
    -- nest 
    { 0, 2749, 'nest.com' },
    -- Indiegogo
    { 0, 2752, 'indiegogo.com' },
    -- MailChimp
    { 0, 2754, 'mailchimp.com' },
    -- MovieTickets.com
    { 0, 2755, 'movietickets.com' },
    -- Comcast Mail
    { 0, 2756, 'mail.comcast.net' },
    -- Coursera
    { 0, 2757, 'coursera.org' },
    { 0, 2757, 'coursera.com' },
    { 0, 2757, 'coursera-course-photos.s3.amazonaws.com' },
    { 0, 2757, 'coursera-instructor-photos.s3.amazonaws.com' },
    { 0, 2757, 'coursera-university-assets.s3.amazonaws.com' },
    -- The Pirate Bay
    { 0, 1136, 'thepiratebay.se' },
    { 0, 1136, 'thepiratebay.sx' },
    -- Bandcamp
    { 0, 2762, 'bandcamp.com' },
    -- Bluehost 
    { 0, 2764, 'bluehost-cdn.com' },
    { 0, 2764, 'bluehost.com' },
    -- OverBlog 
    { 0, 2767, 'over-blog.com' },
    -- BBB
    { 0, 2768, 'bbb.org' },
    { 0, 2768, 'bbb.com' },
    -- TIME.com
    { 0, 2770, 'time.com' },
    -- Hopster
    { 0, 202, 'www.hopster.com' },
    -- phpBB
    { 0, 2772, 'phpbb.com' },
    -- HugeDomain.com
    { 0, 2773, 'hugedomains.com' },
    -- GNU Project
    { 0, 2774, 'gnu.org' },
    -- Lycos
    { 0, 2775, 'lycos.com' },
    -- ConnMan
    { 0, 2776, 'connman.net' },
    -- Creative Commons
    { 0, 2777, 'creativecommons.org' },
    { 0, 2777, 'creativecommons.net' },
    -- NAI
    { 0, 2778, 'networkadvertising.org' },
    -- Tiny
    { 0, 2780, 'tinyurl.com' },
    -- Jimdo
    { 0, 2782, 'jimdo.com' },
    { 0, 2782, 'jimdo.sslcs.cdngc.net' },
    -- Stanford University
    { 0, 2783, 'stanford.edu' },
    -- Harvard University
    { 0, 2784, 'harvard.edu' },
    -- bitly
    { 0, 2787, 'bitly.com' },
    { 0, 2787, 'bit.ly' },
    -- Viddler
    { 0, 2788, 'viddler.com' },
    -- Websense
    { 0, 2790, 'websense.com' },
    { 0, 2790, 'websense.tt.omtrdc.net' },
    -- Zbigz
    { 0, 2791, 'zbigz.com' },
    -- Zulily 
    { 0, 2792, 'zulily.com' },
    -- Zattoo 
    { 0, 2793, 'zattoo.com' },
    -- Xfire  
    { 0, 2794, 'xfire.com' },
    -- Parallels
    { 1, 2802, 'myparallels.com' },
    { 1, 2802, 'parallels.com' },
    -- Google Translate
    { 0, 185, 'translate.google.com' },
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

