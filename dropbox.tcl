# dropbox.tcl
# Dropbox API SDK for TCL
#
# To use this you need an API key and secret. You can get one by registering with Dropbox:
#   https://dropbox.com/developers/apps
#
#############################################################################
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the Licence, or
# (at your option) any later version.
# 
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
#
# Product name : Dropbox TCL SDK
# Author(s): Damien Lesgourgues <damien@lesgourgues.fr>
#
##############################################################################

package require http
package require json
package require tls
::http::register https 443 ::tls::socket

package provide dropbox 0.1

### Define namespace and some variables
namespace eval dropbox {
  namespace export url-encode url-decode
  variable version 0.1

  variable api "https://api.dropbox.com/1"
  variable apic "https://api-content.dropbox.com/1"
  variable locale "fr"
  variable tok; variable apikey; variable apisecret

  variable agent "Mozilla/5.0 (Windows; U; Windows NT 5.1; ru; rv:1.9.0.1) Gecko/2008070208 Firefox/3.0.1"
  variable timeout 30000
}

###
### Some procs for url encoding/decoding
###
proc ::dropbox::url-encode {string} {
  variable map
  variable alphanumeric a-zA-Z0-9
  for {set i 0} {$i <= 256} {incr i} {
    set c [format %c $i]
    if {![string match \[$alphanumeric\] $c]} {
      set map($c) %[format %.2x $i]
    }
  }
  # These are handled specially
  array set map { " " "%20" \n %0d%0a }
  # start of encoding
  regsub -all \[^$alphanumeric\] $string {$map(&)} string
  # This quotes cases like $map([) or $map($) => $map(\[) ...
  regsub -all {[][{})\\]\)} $string {\\&} string
  return [subst -nocommand $string]
}

proc ::dropbox::url-decode {string} {
  # rewrite "%20" back to space and protect \ from quoting another '\'
  set string [string map [list "%20" { } "\\" "\\\\"] $string]
  # prepare to process all %-escapes
  regsub -all -- {%([A-Fa-f0-9][A-Fa-f0-9])} $string {\\u00\1} str
  # process \u unicode mapped chars
  return [subst -novar -nocommand $string]
}

###
### Dropbox OAuth v2
###

proc ::dropbox::init { apikey apisecret } {
  # TODO : Check apikey and apisecret if they are good
  # TODO : 15 alphanum lower case
  variable apikey $apikey
  variable apisecret $apisecret
  return
}

proc ::dropbox::request_token { } {
  # Example of code
    #puts "Please go to [::dropbox::request_token $apikey]"
    #puts "authentify to your dropbox, authorize the app $APPNAME and enter here the auth code"
    #puts "Authorization code : "
    #set code [gets stdin]
    #::dropbox::authorize $code $::dropbox::apikey $::dropbox::apisecret
  return "https://www.dropbox.com/1/oauth2/authorize?response_type=code&client_id=$apikey"
}

proc ::dropbox::authorize { token apikey apisecret } {
  # This will call the Dropbox API to authorize the token and get the access token.
  # It will return the user Dropbox uid if all is OK.
  set url "$::dropbox::api/oauth2/token"
  set params [::http::formatQuery code $token grant_type authorization_code client_id $apikey client_secret $apisecret ]
  set t [::http::config -useragent $agent]
  set t [::http::geturl $url -query $params -timeout $timeout]
  set httpc [::http::ncode $t]
  set dataj [::http::data $t]
  ::http::cleanup $t
  set data [::json::json2dict $dataj]
  if { $httpc > 399 } {
    return -code error "HTTP Error $httpc"
  } elseif { [dict exists $data error] } {
    return -code error "Dropbox Error [dict get $data error] : [dict get $data error_description]"
  } else {
    variable tok [dict get $data access_token]
    return [dict get $data uid]
  }
}


###
### Dropbox subroutines
### 
proc ::dropbox::tokcheck {} {
  # Return an error if we don't have an access token
  if {[string match [info exists tok] 0]} {
    return -code error
  } else {
    return
  }
}

###
### Dropbox Account
###
# This will get informations about the account.
# info will return a dict with all informations.
# uid will return only the Dropbox user uid
# country will return only the Dropbox user country
# referral will return the referral link of the Dropbox user
# name will return the full name of the Dropbox user
# quota will return a list with the quota information of the Dropbox account (normal, shared and allocated)

proc ::dropbox::account_info {  } {
  if {[tokcheck]} { continue } else { return -code error "App is not authorized or no token exist." }
  set url "$api/account/info?access_token=$tok&locale=$locale"
  set t [::http::config -useragent $agent]
  set t [::http::geturl $url -timeout $timeout]
  set dataj [::http::data $t]
  set httpc [::http::ncode $t]
  set dataj [::http::data $t]
  ::http::cleanup $t
  set data [::json::json2dict $dataj]
  if { $httpc > 399 } {
    return -code error "HTTP Error $httpc"
  } elseif { [dict exists $data error] } {
    return -code error "Dropbox Error [dict get $data error] : [dict get $data error_description]"
  } else {
    return $data
  }
}
proc ::dropbox::account_uid { } { return [dict get [account_info] uid] }
proc ::dropbox::account_country { } { return [dict get [account_info] country] }
proc ::dropbox::account_referral { } { return [dict get [account_info] referral_link] }
proc ::dropbox::account_name { } { return [dict get [account_info] display_name] }
proc ::dropbox::account_quota { } { return [dict get [account_info] quota_info] }

###
### Dropbox Files and Metadata
###

proc ::dropbox::shares { path {shorturl true} {root dropbox} } {
  # Get a public link to share a folder/file.
  #  path is the path to the folder/file relative to $root
  #  shorturl is a boolean to use or not the url shortener of dropbox (db.tt)
  #  root is the selected root : dropbox or sandbox
  if {[tokcheck]} { continue } else { return -code error "Token is not authorized or no token exist." }
  set url "$api/shares/$root/[url-encode $path]"
  set params [::http::formatQuery access_token $tok locale $locale short_url $shorturl]
  set t [::http::config -useragent $agent]
  set t [::http::geturl $url -query $params -timeout $timeout]
  set dataj [::http::data $t]
  set httpc [::http::ncode $t]
  set dataj [::http::data $t]
  ::http::cleanup $t
  set data [::json::json2dict $dataj]
  if { $httpc > 399 } {
    return -code error "HTTP Error $httpc"
  } elseif { [dict exists $data error] } {
    return -code error "Dropbox Error [dict get $data error] : [dict get $data error_description]"
  } else {
    return [dict get $data url]
  }
}




###
### Skeleton for GET and POST
###
proc ::dropbox::skelG { } {
  if {[tokcheck]} { continue } else { return -code error "Token is not authorized or no token exist." }
  set url "$api/?access_token=$tok&locale=$locale"
  set t [::http::config -useragent $agent]
  set t [::http::geturl $url -timeout $timeout]
  set dataj [::http::data $t]
  set httpc [::http::ncode $t]
  set dataj [::http::data $t]
  ::http::cleanup $t
  set data [::json::json2dict $dataj]
  if { $httpc > 399 } {
    return -code error "HTTP Error $httpc"
  } elseif { [dict exists $data error] } {
    return -code error "Dropbox Error [dict get $data error] : [dict get $data error_description]"
  } else {
    return $data
  }
}
proc ::dropbox::skelP { } {
  if {[tokcheck]} { continue } else { return -code error "Token is not authorized or no token exist." }
  set url "$api/"
  set params [::http::formatQuery access_token $tok locale $locale]
  set t [::http::config -useragent $agent]
  set t [::http::geturl $url -query $params -timeout $timeout]
  set dataj [::http::data $t]
  set httpc [::http::ncode $t]
  set dataj [::http::data $t]
  ::http::cleanup $t
  set data [::json::json2dict $dataj]
  if { $httpc > 399 } {
    return -code error "HTTP Error $httpc"
  } elseif { [dict exists $data error] } {
    return -code error "Dropbox Error [dict get $data error] : [dict get $data error_description]"
  } else {
    return $data
  }
}



#
#
#
#
#
#
#
#
#
#
#
#
#
#
#
#
#
#
#
#
#
#
#
