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
  variable debug 1

  variable api "https://api.dropbox.com/1"
  variable apic "https://api-content.dropbox.com/1"
  variable locale "fr"
  variable db "dropbox.dat"
  variable dateformat "%a, %d %b %Y %H:%M:%S %z"
  variable tok; variable apikey; variable apisecret; variable uid

  variable agent "Mozilla/5.0 (Windows; U; Windows NT 5.1; ru; rv:1.9.0.1) Gecko/2008070208 Firefox/3.0.1"
  variable timeout 30000
}

###
### Debug proc
###
proc ::dropbox::dbg { msg } { if {$::dropbox::debug} {puts "== DropBox DEBUG == $msg"} }

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
# Some examples of code
# first OAuth or security for always having the good key
    #::dropbox::init $KEY $SECRET
    #puts "Please go to [::dropbox::request_token]"
    #puts "authentify to your dropbox, authorize the app $APPNAME and enter here the auth code"
    #puts "Authorization code : "
    #set code [gets stdin]
    #::dropbox::authorize $code $::dropbox::apikey $::dropbox::apisecret
# Invalid token / force regeneration of token
    #::dropbox::init
    #puts "Please go to [::dropbox::request_token]"
    #puts "authentify to your dropbox, authorize the app $APPNAME and enter here the auth code"
    #puts "Authorization code : "
    #set code [gets stdin]
    #::dropbox::authorize $code $::dropbox::apikey $::dropbox::apisecret

proc ::dropbox::writeDB {  } {
    ::dropbox::dbg "Writing database"
    if {![file writable $::dropbox::db]} { if {[file exists $::dropbox::db]} { return -code error "$::dropbox::db is not writable. Please correct this." } }
    set f [open $::dropbox::db w]
    fconfigure $f -encoding utf-8
    if {[info exists ::dropbox::apikey]}    { puts $f "apikey $::dropbox::apikey" }
    if {[info exists ::dropbox::apisecret]} { puts $f "apisecret $::dropbox::apisecret" }
    if {[info exists ::dropbox::tok]}       { puts $f "tok $::dropbox::tok" }
    if {[info exists ::dropbox::uid]}       { puts $f "uid $::dropbox::uid" }
    close $f
}

proc ::dropbox::init { {key load} {secret load} } {
  ::dropbox::dbg "Initializing dropbox SDK"
  # TODO : Check apikey and apisecret if they are good
  # TODO : 15 alphanum lower case
  # Load data
  if {![file exists $::dropbox::db]} {
    ::dropbox::dbg "dropbox.dat doesn't exist"
    # No database present. Check if key and secret are given in parameters
    if {[string equal $key "load"]} { return -code error "No database is present. You need to provide the key and secret." }
    if {[string equal $secret "load"]} { return -code error "No database is present. You need to provide the key and secret." }
    variable ::dropbox::apikey $key
    variable ::dropbox::apisecret $secret
    # Write variables to database
    ::dropbox::writeDB
  } else {
    # Database exist. Check if it is readable and load parameters
    ::dropbox::dbg "dropbox.dat exist. Reading it."
    set f [open $::dropbox::db r]
    fconfigure $f -encoding utf-8
    set content [read -nonewline $f]
    close $f
    ::dropbox::dbg "dropbox.dat read complete"
    foreach line [split $content "\n"] { ::dropbox::dbg "loading in tmp array : [lindex $line 0] -> [lrange $line 1 end]"; lappend tmp([lindex $line 0]) [lrange $line 1 end] }
    foreach data "apikey apisecret tok uid" {
      ::dropbox::dbg "Populating $data"
      if {[info exists tmp($data)]} { variable ::dropbox::$data $tmp($data) } else { return -code error "Dropbox data corrupted !" }
    }
    if {(![string equal $secret "load"]) && (![string equal $key "load"])} {
      ::dropbox::dbg "Overriding apikey and apisecret"
      variable ::dropbox::apikey $key
      variable ::dropbox::apisecret $secret
    }
    # Write variables to database
    ::dropbox::writeDB
  }
  return
}

proc ::dropbox::request_token { } {
  ::dropbox::dbg "Requesting token"
  return "https://www.dropbox.com/1/oauth2/authorize?response_type=code&client_id=$::dropbox::apikey"
}

proc ::dropbox::authorize { token } {
  ::dropbox::dbg "Authorizing SDK to dropbox"
  # This will call the Dropbox API to authorize the token and get the access token.
  # It will return the user Dropbox uid if all is OK.
  set url "$::dropbox::api/oauth2/token"
  set params [::http::formatQuery code $token grant_type authorization_code client_id $::dropbox::apikey client_secret $::dropbox::apisecret ]
  set t [::http::config -useragent $::dropbox::agent]
  set t [::http::geturl $url -query $params -timeout $::dropbox::timeout]
  set httpc [::http::ncode $t]
  set dataj [::http::data $t]
  ::http::cleanup $t
  set data [::json::json2dict $dataj]
  if { $httpc > 399 } {
    return -code error "HTTP Error $httpc"
  } elseif { [dict exists $data error] } {
    return -code error "Dropbox Error [dict get $data error] : [dict get $data error_description]"
  } else {
    variable ::dropbox::tok [dict get $data access_token]
    variable ::dropbox::uid [dict get $data uid]
    # Write token to database
    ::dropbox::writeDB
    return "$uid"
  }
}


###
### Dropbox subroutines
### 
proc ::dropbox::tokcheck { } {
  # TODO : check if apikey and secret are present : 
  #      :   NO -> call ::dropbox::init and recheck tok/key/secret. 
  #      :     No tok/key/secret -> INIT error
  #      :     No tok only -> call ::dropbox::request_token
  #      :   YES -> call ::dropbox::request_token
  # Return an error if we don't have an access token
  if {![info exists ::dropbox::tok]} { return 1 }
  return 0
}

###
### Dropbox Account
###
# This will get informations about the account.
# _info will return a dict with all informations.
# _uid will return only the Dropbox user uid
# _country will return only the Dropbox user country
# _referral will return the referral link of the Dropbox user
# _name will return the full name of the Dropbox user
# _quota will return a list with the quota information of the Dropbox account (normal, shared and allocated)

proc ::dropbox::account_info {  } {
  if {[::dropbox::tokcheck] != 0} { return -code error "App is not authorized or no token exist." }
  set url "$::dropbox::api/account/info?access_token=$::dropbox::tok&locale=$::dropbox::locale"
  set t [::http::config -useragent $::dropbox::agent]
  set t [::http::geturl $url -timeout $::dropbox::timeout]
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
proc ::dropbox::account_uid { }      { return [dict get [::dropbox::account_info] uid] }
proc ::dropbox::account_country { }  { return [dict get [::dropbox::account_info] country] }
proc ::dropbox::account_referral { } { return [dict get [::dropbox::account_info] referral_link] }
proc ::dropbox::account_name { }     { return [dict get [::dropbox::account_info] display_name] }
proc ::dropbox::account_quota { }    { return [dict get [::dropbox::account_info] quota_info] }

###
### Dropbox Files and Metadata
###

proc ::dropbox::shares { path {shorturl true} {root dropbox} } {
  # Get a public link to share a folder/file.
  #  path is the path to the folder/file relative to $root
  #  shorturl is a boolean to use or not the url shortener of dropbox (db.tt)
  #  root is the selected root : dropbox or sandbox
  if {[::dropbox::tokcheck] != 0} { return -code error "Token is not authorized or no token exist." }
  set url "$::dropbox::api/shares/$root/[url-encode $path]"
  set params [::http::formatQuery access_token $::dropbox::tok locale $::dropbox::locale short_url $shorturl]
  set t [::http::config -useragent $::dropbox::agent]
  set t [::http::geturl $url -query $params -timeout $::dropbox::timeout]
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

proc ::dropbox::search { query {limit 1000} {deleted false} {root dropbox} } {
  if {[::dropbox::tokcheck] != 0} { return -code error "Token is not authorized or no token exist." }
  set url "$::dropbox::api/search/$root/[url-encode $path]"
  set params [::http::formatQuery access_token $::dropbox::tok locale $::dropbox::locale query $query file_limit $limit include_deleted $deleted]
  set t [::http::config -useragent $::dropbox::agent]
  set t [::http::geturl $url -query $params -timeout $::dropbox::timeout]
  set dataj [::http::data $t]
  set httpc [::http::ncode $t]
  set dataj [::http::data $t]
  ::http::cleanup $t
  set data [::json::json2dict $dataj]
  if { $httpc == 406 } {
    return -code error "Too many file entries."
  } elseif { $httpc > 399 } {
    return -code error "HTTP Error $httpc"
  } elseif { [dict exists $data error] } {
    return -code error "Dropbox Error [dict get $data error] : [dict get $data error_description]"
  } else {
    return $data
  }
}
proc ::dropbox::search_size         { query {limit 1000} {deleted false} {root dropbox} } { return [dict get [::dropbox::search $query $limit $deleted $root] size] }
proc ::dropbox::search_rev          { query {limit 1000} {deleted false} {root dropbox} } { return [dict get [::dropbox::search $query $limit $deleted $root] rev] }
proc ::dropbox::search_bytes        { query {limit 1000} {deleted false} {root dropbox} } { return [dict get [::dropbox::search $query $limit $deleted $root] bytes] }
proc ::dropbox::search_modified     { query {limit 1000} {deleted false} {root dropbox} } { return [dict get [::dropbox::search $query $limit $deleted $root] modified] }
proc ::dropbox::search_path         { query {limit 1000} {deleted false} {root dropbox} } { return [dict get [::dropbox::search $query $limit $deleted $root] path] }
proc ::dropbox::search_is_dir       { query {limit 1000} {deleted false} {root dropbox} } { return [dict get [::dropbox::search $query $limit $deleted $root] is_dir] }
proc ::dropbox::search_icon         { query {limit 1000} {deleted false} {root dropbox} } { return [dict get [::dropbox::search $query $limit $deleted $root] icon] }
proc ::dropbox::search_root         { query {limit 1000} {deleted false} {root dropbox} } { return [dict get [::dropbox::search $query $limit $deleted $root] root] }
proc ::dropbox::search_mime_type    { query {limit 1000} {deleted false} {root dropbox} } { return [dict get [::dropbox::search $query $limit $deleted $root] mime_type] }
proc ::dropbox::search_revision     { query {limit 1000} {deleted false} {root dropbox} } { return [dict get [::dropbox::search $query $limit $deleted $root] revision] }
proc ::dropbox::search_thumb_exists { query {limit 1000} {deleted false} {root dropbox} } { return [dict get [::dropbox::search $query $limit $deleted $root] thumb_exists] }

###
### Skeleton for GET and POST
###
proc ::dropbox::skelG { } {
  if {[::dropbox::tokcheck] != 0} { return -code error "Token is not authorized or no token exist." }
  set url "$::dropbox::api/?access_token=$::dropbox::tok&locale=$::dropbox::locale"
  set t [::http::config -useragent $::dropbox::agent]
  set t [::http::geturl $url -timeout $::dropbox::timeout]
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
  if {[::dropbox::tokcheck] != 0} { return -code error "Token is not authorized or no token exist." }
  set url "$::dropbox::api/"
  set params [::http::formatQuery access_token $::dropbox::tok locale $::dropbox::locale]
  set t [::http::config -useragent $::dropbox::agent]
  set t [::http::geturl $url -query $params -timeout $::dropbox::timeout]
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
