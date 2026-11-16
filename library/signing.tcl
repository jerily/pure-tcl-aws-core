# 
# Copyright Jerily LTD. All Rights Reserved.
# SPDX-FileCopyrightText: 2026 Neofytos Dimitriou (neo@jerily.cy)
# SPDX-License-Identifier: MIT.
# 

# Derive the four-stage SigV4 signing key as raw bytes.
proc ::aws::core::signing_key {secret date region service} {
    set key [encoding convertto utf-8 AWS4$secret]
    foreach value [list $date $region $service aws4_request] {set key [::sha2::hmac -bin -key $key -- $value]}
    return $key
}

# Sign an S3 URL locally without sending a request or exposing the secret key.
proc ::aws::core::presign {method url region service credentials expires {now {}}} {
    integer $expires 1 604800 expiration
    set credentials [normalize_credentials $credentials]
    if {$now eq {}} {set now [clock seconds]}
    if {[dict exists $credentials expiration]} {set expires [expr {min($expires,[dict get $credentials expiration]-$now)}]}
    integer $expires 1 604800 expiration
    set p [urlparts $url]
    if {[dict get $p query] ne {}} {error "presign expects a URL without query parameters"}
    set date [clock format $now -gmt 1 -format %Y%m%d]
    set timestamp [clock format $now -gmt 1 -format %Y%m%dT%H%M%SZ]
    set scope $date/$region/$service/aws4_request
    set pairs [list X-Amz-Algorithm AWS4-HMAC-SHA256 X-Amz-Credential [dict get $credentials aws_access_key_id]/$scope X-Amz-Date $timestamp X-Amz-Expires $expires X-Amz-SignedHeaders host]
    if {[get $credentials aws_session_token] ne {}} {lappend pairs X-Amz-Security-Token [dict get $credentials aws_session_token]}
    set qs [querystring $pairs]
    set host [string tolower [dict get $p authority]]
    set canonical "$method\n[dict get $p path]\n$qs\nhost:$host\n\nhost\nUNSIGNED-PAYLOAD"
    set sign "AWS4-HMAC-SHA256\n$timestamp\n$scope\n[::sha2::sha256 -hex -- [encoding convertto utf-8 $canonical]]"
    set signature [::sha2::hmac -hex -key [signing_key [dict get $credentials aws_secret_access_key] $date $region $service] -- $sign]
    return "$url?$qs&X-Amz-Signature=$signature"
}
