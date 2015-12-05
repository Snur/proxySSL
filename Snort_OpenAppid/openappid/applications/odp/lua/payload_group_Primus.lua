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
detection_name: Payload Group "Primus"
version: 8
description: Group of payload detectors.
bundle_description: $VAR1 = {
          'Presto' => 'Printable emails and photos.',
          'Newser' => 'Online new portal.',
          'SockShare' => 'Provides online File sharing.',
          'NHL.com' => 'The National Hockey League official website.',
          'I Waste So Much Time' => 'Funny photos and videos around the world.',
          'Atlassian' => 'Project Control and Management Software.',
          'Windows Help client' => 'Windows client for help and support services.',
          'IFTTT' => 'Service to connect channels.',
          'Roku' => 'Device that streams internet video and audio to a TV.',
          'E! Online' => 'Online entertainment news.',
          'Cabal Online' => 'Online multiplayer games.',
          'Biography.com' => 'Stories, biographies about people.',
          'Adweek' => 'Marketing, Media and advertising news.',
          'The Week Magazine' => 'Online new magazine.',
          'GNOME' => 'Official website for GNOME, a desktop environment and graphical UI.',
          'PixelMags' => 'Content delivery network for digital versions of magazine.',
          'Ubuntu' => 'Official website of Ubuntu.',
          'Apple iForgot' => 'Password reset portal for Apple.',
          'BitGravity' => 'Content delivery network.',
          'TopTenREVIEWS' => 'Information, Reviews and recommendation about the product.',
          'Slate Magazine' => 'Online daily magazine.',
          'Wired.com' => 'Online magazine.',
          'Simpli.fi' => 'Ad portal.',
          'RedOrbit' => 'Provides information about Science, Space, Technology and health related news.',
          'NBC' => 'Official website for NBC\'s Television network.',
          'Zmags' => 'Digital publisher for branded products to customer.',
          'Brightcove' => 'Video hosting platform.',
          'Prezi' => 'Presentation tool.',
          'ESTsoft' => 'Provides software tools and online games.',
          'Google Checkout' => 'Online Payment service by Google.',
          'Redbox Instant' => 'Rental and online movie/game.',
          'Space.com' => 'Provides news related to Space and Astronomy.',
          'Comedy Central' => 'Official website of Comedy Central, Television channel.',
          'GIFSoup.com' => 'Create animated GIF from videos.',
          'Google Code project hosting' => 'Google site that hosts software projects.',
          'ALTools' => 'Software tools by ESTsoft.'
        };

--]]

require "DetectorCommon"


local DC = DetectorCommon

DetectorPackageInfo = {
    name =  "payload_group_Primus",
    proto =  DC.ipproto.tcp,
    client = {
        init =  'DetectorInit',
        clean =  'DetectorClean',
        minimum_matches =  1
    }
}

--serviceId, clientId, ClientType, PayloadId, PayloadType, hostPattern, pathPattern, schemePattern, queryPattern
gUrlPatternList = {

   --NBC   
    { 0, 0, 0, 938, 22, "nbc.com", "/", "http:", "", 1988},
    { 0, 0, 0, 938, 22, "nbcuni.com", "/", "http:", "", 1988},
    { 0, 0, 0, 938, 22, "nbcuniversalstore.com", "/", "http:", "", 1988},
    { 0, 0, 0, 938, 22, "nbcuniversalstore.resultspage.com", "/", "http:", "", 1988},
    { 0, 0, 0, 938, 22, "nbcustr.netmng.com", "/", "http:", "", 1988},
    { 0, 0, 0, 938, 22, "nbcudigitaladops.com", "/", "http:", "", 1988},
    { 0, 0, 0, 938, 22, "nbcdotcom-f.akamaihd.net", "/", "http:", "", 1988},
    { 0, 0, 0, 938, 22, "nbcvod-i.akamaihd.net", "/", "http:", "", 1988},
   --RedOrbit
    { 0, 0, 0, 939, 22, "redorbit.com", "/", "http:", "", 1989},
   --Space.com
    { 0, 0, 0, 940, 22, "space.com", "/", "http:", "", 1990},
    { 0, 0, 0, 940, 22, "hermanstreet.com", "/", "http:", "", 1990},
   --SockShare
    { 0, 0, 0, 941, 9, "sockshare.com", "/", "http:", "", 1991},
   --BitGravity
    { 0, 0, 0, 942, 19, "bitgravity.com", "/", "http:", "", 1992},
   --PixelMags
    { 0, 0, 0, 943, 22, "pixelmags.com", "/", "http:", "", 1993},
   --Zmags 
    { 0, 0, 0, 944, 22, "zmags.com", "/", "http:", "", 1994},
    { 0, 0, 0, 944, 22, "zmags.app4.hubspot.com", "/", "http:", "", 1994},
   --GNOME 
    { 0, 0, 0, 945, 22, "gnome.org", "/", "http:", "", 1995},
   --ESTsoft
    { 0, 0, 0, 946, 22, "estsoft.com", "/", "http:", "", 1996},
    { 0, 0, 0, 946, 22, "estgames.com", "/", "http:", "", 1996},
   --Cabal Online
    { 0, 0, 0, 947, 20, "cabalonline.com", "/", "http:", "", 1997},
    { 0, 0, 0, 947, 20, "cabal.zzima.com", "/", "http:", "", 1997},
    { 0, 0, 0, 947, 20, "cabal.com", "/", "http:", "", 1997},
    { 0, 0, 0, 947, 20, "cabal.estgames.com", "/", "http:", "", 1997},
    { 0, 0, 0, 947, 20, "cabalsea.com", "/", "http:", "", 1997},
    { 0, 0, 0, 947, 20, "cabal.e-games.com.ph", "/", "http:", "", 1997},
   --ALTools
    { 0, 0, 0, 948, 22, "altools.com", "/", "http:", "", 1998},
    { 0, 0, 0, 948, 22, "altools.co.kr", "/", "http:", "", 1998},
    { 0, 0, 0, 948, 22, "altools.jp", "/", "http:", "", 1998},
   --GIFSoup.com
    { 0, 0, 0, 949, 22, "gifsoup.com", "/", "http:", "", 1999},
   --Slate Magazine
    { 0, 0, 0, 950, 33, "slate.com", "/", "http:", "", 2000},
    { 0, 0, 0, 950, 33, "slatev.com", "/", "http:", "", 2000},
   -- I Waste So Much Time
    { 0, 0, 0, 951, 33, "iwastesomuchtime.com", "/", "http:", "", 2001},
    { 0, 0, 0, 951, 33, "iwsmt.disqus.com","/", "http:", "", 2001},
    { 0, 0, 0, 951, 33, "dropdash.com","/", "http:", "iwsmt", 2001},
   -- Biography.com
    { 0, 0, 0, 952, 22, "biography.disqus.com", "/", "http:", "", 2002},
    { 0, 0, 0, 952, 22, "biography.com", "/", "http:", "", 2002},
    { 0, 0, 0, 952, 22, "shop.history.com", "/", "http:", "biography", 2002},
   -- Ubuntu
    { 0, 0, 0, 953, 22, "ubuntu.com", "/", "http:", "", 2003},
   -- Comedy Central
    { 0, 0, 0, 954, 22, "comedycentral.com", "/", "http:", "", 2004},
    { 0, 0, 0, 954, 22, "thedailyshow.com", "/", "http:", "", 2004},
    { 0, 0, 0, 954, 22, "colbertnation.com", "/", "http:", "", 2004},
    { 0, 0, 0, 954, 22, "jokes.com", "/", "http:", "", 2004},
    { 0, 0, 0, 954, 22, "viacomedycentral.112.2o7.net", "/", "http:", "", 2004},
    { 0, 0, 0, 954, 22, "mtvn.112.2o7.net", "/", "http:", "comedycentral", 2004},
    { 0, 0, 0, 954, 22, "mtvnservices.com", "/", "http:", "comedycentral", 2004},
    { 0, 0, 0, 954, 22, "jokes.mtvnimages.com", "/", "http:", "", 2004},
    { 0, 0, 0, 954, 22, "thedailyshow.mtvnimages.com", "/", "http:", "", 2004},
    { 0, 0, 0, 954, 22, "colbertnation.mtvnimages.com", "/", "http:", "", 2004},
    { 0, 0, 0, 954, 22, "comedycentrl.com", "/", "http:", "", 2004},
   -- Wired.com
    { 0, 0, 0, 955, 22, "wired.com", "/", "http:", "", 2005},
    { 0, 0, 0, 955, 22, "wiredopinion.disqus.com", "/", "http:", "", 2005},
    { 0, 0, 0, 955, 22, "wiredinsider.com", "/", "http:", "", 2005},
    { 0, 0, 0, 955, 22, "wiredinsider.tumblr.com", "/", "http:", "", 2005},
   -- E! Online
    { 0, 0, 0, 956, 33, "eonline.com", "/", "http:", "", 2006},
   -- NHL.com
    { 0, 0, 0, 957, 33, "nhl.112.2o7.net", "/", "http:", "", 2007},
    { 0, 0, 0, 957, 33, "nhl.com", "/", "http:", "", 2007},
    { 0, 0, 0, 957, 33, "nhle.com", "/", "http:", "", 2007},
    { 0, 0, 0, 957, 33, "nhl.cdnllnwnl.neulion.net", "/", "http:", "", 2007},
    --Presto 
    { 0, 0, 0, 958, 2, "presto.com", "/", "http:", "", 2008},
   -- Redbox Instant
    { 0, 0, 0, 963, 38, "redboxinstant.com", "/", "http:", "", 2015},
   -- TopTenREVIEWS 
    { 0, 0, 0, 964, 22, "toptenreviews.com", "/", "http:", "", 2016},
   -- Adweek
    { 0, 0, 0, 965, 22, "adweek.com", "/", "http:", "", 2017},
    { 0, 0, 0, 965, 22, "adweekmedia.disqus.com", "/", "http:", "", 2017},
   -- The Week Magazine
    { 0, 0, 0, 966, 22, "theweek.com", "/", "http:", "", 2018},
    { 0, 0, 0, 966, 22, "theweekus.disqus.com", "/", "http:", "", 2018},
    { 0, 0, 0, 966, 22, "nrelate.com", "/", "http:", "theweek.com", 2018},
   -- Brightcove 
    { 0, 0, 0, 967, 22, "brightcove.com", "/", "http:", "", 2019},
   -- Newser 
    { 0, 0, 0, 968, 22, "newser.com", "/", "http:", "", 2020},
   -- Simpli.fi
    { 0, 0, 0, 969, 22, "simpli.fi", "/", "http:", "", 2021},
   -- nrelate
    -- { 0, 0, 0, 970, 22, "nrelate.com", "/", "http:", "", 2022},
    -- Google Code project hosting
    { 0, 0, 0, 971, 43, "googlecode.com", "/", "http:", "", 2032},
    -- Roku
    { 0, 0, 0, 972, 38, "roku.com", "/", "http:", "", 2034}, 
    -- Atlassian
    { 0, 0, 0, 973, 22, "atlassian.com", "/", "http:", "", 2038}, 
    -- Prezi
    { 0, 0, 0, 974, 22, "prezi.com", "/", "http:", "", 2040}, 
    { 0, 0, 0, 974, 22, "prezi-a.akamaihd.net", "/", "http:", "", 2040}, 
    -- IFTTT
    { 0, 0, 0, 975, 22, "ifttt.com", "/", "http:", "", 2041}, 
    -- Apple iForgot 
    { 0, 0, 0, 976, 22, "iforgot.apple.com", "/", "http:", "", 2045}, 
}


function DetectorInit(detectorInstance)

    gDetector = detectorInstance;

    gDetector:addHttpPattern(2, 5, 0, 252, 24, 0, 0, 'HelpSupportServices', 2033);
    gDetector:addHttpPattern(2, 5, 0, 253, 19, 0, 0, 'Roku', 2034);

    if gDetector.addAppUrl then
        for i,v in ipairs(gUrlPatternList) do
            gDetector:addAppUrl(v[1],v[2],v[3],v[4],v[5],v[6],v[7],v[8],v[9],v[10]);
        end
    end

    return gDetector;
end

function DetectorClean()
end

