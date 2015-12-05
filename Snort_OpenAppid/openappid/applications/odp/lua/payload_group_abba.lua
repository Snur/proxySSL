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
detection_name: Payload Group "ABBA"
version: 12
description: Group of payload detectors.
bundle_description: $VAR1 = {
          'LinkedIn Job Search' => 'The job search facility on LinkedIn.',
          'StayFriends' => 'German school focused social network.',
          'Premier Football' => 'Facebook fantasy football game.',
          'Facebook Send Email' => 'An action to send email on Facebook\'s integrated personal message system.',
          'Facebook Chat' => 'Facebook\'s integrated chat client.',
          'Apple Store' => 'Official online retailer of Apple products.',
          'Adorama' => 'Online camera retailer.',
          'Facebook Comment' => 'A comment made to another user\'s status update on Facebook.',
          'spin.de' => 'German social network and dating site.',
          'Facebook Read Email' => 'An action to read email on Facebook\'s integrated personal message system.',
          'Facebook Status Update' => 'A short update sent to Facebook friends.',
          '2channel' => 'Japan based Internet forum.',
          'Dropbox' => 'Cloud based file storage.',
          'XING' => 'Business focused social network.',
          'studiVZ' => 'German online classroom / social network.',
          'Best Buy' => 'Website and online retailer for national chain of electronics stores.',
          'Barnes and Noble' => 'Online retailer of books and other goods.',
          'Viadeo' => 'Business focused social network.',
          '1-800-Flowers' => 'Online retailer of flowers and other gifts.',
          'schuelerVZ' => 'German online classroom / social network.',
          'Netvibes' => 'Web portal.',
          'Lokalisten' => 'German social network site focused on local events.',
          'B&H Photo Video' => 'Online retailer of cameras.',
          'wer-kennt-wen' => 'German social network.',
          'Argos' => 'British online retailer of appliances, hardware, and other goods.',
          'Amazon' => 'Online retailer of books and most other goods.'
        };

--]]

require "DetectorCommon"

local DC = DetectorCommon

DetectorPackageInfo = {
    name =  "payload_group_abba",
    proto =  DC.ipproto.tcp,
    client = {
        init =  'DetectorInit',
        clean =  'DetectorClean',
        minimum_matches =  1
    }
}

--serviceId, clientId, ClientType, PayloadId, PayloadType, hostPattern, pathPattern, schemePattern, queryPattern
gUrlPatternList = {
    --facebook.chat
    { 0, 0, 0, 82, 10, "facebook.com", "ajax/chat/", "http:", "", 630},
    { 0, 0, 0, 82, 10, "facebook.com", "ajax/presence/", "http:", "", 630},
    { 0, 0, 0, 82, 10, "facebook.com", "ajax/mercury/", "http:", "", 630},
    --facebook.comment
    { 0, 0, 0, 83, 5, "facebook.com", "ajax/ufi/modify", "http:", "", 631},
    --facebook.statusUpdate
    { 0, 0, 0, 84, 5, "facebook.com", "ajax/updatestatus", "http:", "", 635},
    { 0, 0, 0, 84, 5, "facebook.com", "/ajax/metacomposer/attachment/timeline/wallpost", "http:", "", 635},
    --facebool.read-email
    { 0, 0, 0, 85, 5, "facebook.com", "ReadThread", "http:", "", 633},
    { 0, 0, 0, 85, 5, "facebook.com", "ajax/home/inbox", "http:", "", 633},
    --facebook.send-email
    { 0, 0, 0, 86, 5, "facebook.com", "MessageComposerEndpoint", "http:", "", 634},
    { 0, 0, 0, 86, 5, "facebook.com", "ajax/messaging/send", "http:", "", 634},
    --linked-in.job-search
    { 0, 0, 0, 87, 5, "linkedin.com", "jsearch", "http:", "", 714},
    { 0, 0, 0, 87, 5, "linkedin.com", "jobs", "http:", "", 714},
    { 0, 0, 0, 87, 5, "linkedin.com", "jobs_seeking", "http:", "", 714},
    { 0, 0, 0, 87, 5, "linkedin.com", "jobs_seeking_view_job", "http:", "", 714},
    --800-flowers
    { 0, 0, 0, 88, 15, "1800flowers.com", "/", "http:", "", 535},
    --adorama
    { 0, 0, 0, 89, 15, "adorama.com", "/", "http:", "", 542},
    --amazon
    { 0, 0, 0, 90, 15, "amazon.com", "/", "http:", "", 24},
    { 0, 0, 0, 90, 15, "amazon.jobs", "/", "http:", "", 24},
    { 0, 0, 0, 90, 15, "amazon.in", "/", "http:", "", 24},
    { 0, 0, 0, 90, 15, "amazon.es", "/", "http:", "", 24},
    { 0, 0, 0, 90, 15, "amazon.de", "/", "http:", "", 24},
    { 0, 0, 0, 90, 15, "amazon.co.uk", "/", "http:", "", 24},
    { 0, 0, 0, 90, 15, "amazon.co.jp", "/", "http:", "", 24},
    { 0, 0, 0, 90, 15, "amazon-presse.de", "/", "http:", "", 24},
    { 0, 0, 0, 90, 15, "amazon.ca", "/", "http:", "", 24},
    --Apple Store
    { 0, 0, 0, 91, 15, "store.apple.com", "/", "http:", "", 551},
    { 0, 0, 0, 91, 15, "shop-different.com", "/", "http:", "", 551},
    { 0, 0, 0, 91, 15, "shop-different.org", "/", "http:", "", 551},
    { 0, 0, 0, 91, 15, "buyaple.com", "/", "http:", "", 551},
    { 0, 0, 0, 91, 15, "macprices.com", "/", "http:", "", 551},
    { 0, 0, 0, 91, 15, "ipodprices.com", "/", "http:", "", 551},
    { 0, 0, 0, 91, 15, "theapplestore.eu", "/", "http:", "", 551},
    { 0, 0, 0, 91, 15, "applestore.com", "/", "http:", "", 551},
    { 0, 0, 0, 91, 15, "applestore.co", "/", "http:", "", 551},
    --argos
    { 0, 0, 0, 92, 15, "argos.co.uk", "/", "http:", "", 554},
    --barnesandnoble
    { 0, 0, 0, 94, 15, "barnesandnoble.com", "/", "http:", "", 561},
    --bestbuy
    { 0, 0, 0, 95, 15, "bestbuy.com", "/", "http:", "", 567},
    --b&h Photo
    { 0, 0, 0, 96, 15, "bhphotovideo.com", "/", "http:", "", 559},
    --facebook.apps.games.premierFootball
    { 0, 0, 0, 97, 5, "apps.facebook.com", "/premierfootball/PlayMatches.asp", "http:", "", 632},
    --Dropbox
    { 0, 0, 0, 98, 9, "dropbox.com", "/", "http:", "", 125},
    --Meebo
    --{ 0, 0, 0, 99, 10, "meebo.com", "/", "http:", "", 286},
    --XING
    { 0, 0, 0, 100, 5, "xing.com", "/", "http:", "", 922},
    --StayFriends
    { 0, 0, 0, 101, 5, "stayfriends.de", "/", "http:", "", 849},
    --wer-kennt-wen
    { 0, 0, 0, 102, 5, "wer-kennt-wen.de", "/", "http:", "", 908},
    --studiVZ
    { 0, 0, 0, 103, 12, "studivz.net", "/", "http:", "", 851},
    --schuelerVZ
    { 0, 0, 0, 104, 12, "schuelervz.net", "/", "http:", "", 818},
    --spin
    { 0, 0, 0, 105, 5, "spin.de", "/", "http:", "", 841},
    --Lokalisten
    { 0, 0, 0, 106, 5, "lokalisten.de", "/", "http:", "", 718},
    { 0, 0, 0, 106, 5, "lokalisten.at", "/", "http:", "", 718},
    --Netvibes
    { 0, 0, 0, 107, 22, "netvibes.com", "/", "http:", "", 758},
    --Viadeo
    { 0, 0, 0, 108, 5, "viadeo.com", "/", "http:", "", 891},
    --2Channel
    { 0, 0, 0, 109, 23, "2ch.net", "/", "http:", "", 537}, 
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

