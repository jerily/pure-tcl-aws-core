# 
# Copyright Jerily LTD. All Rights Reserved.
# SPDX-FileCopyrightText: 2026 Neofytos Dimitriou (neo@jerily.cy)
# SPDX-License-Identifier: MIT.
# 

package require Tcl 9.1
package require trequests 1.3
package require tjson 1.0.27
package require tdom 0.9
package require thashlib 0.1.0

namespace eval ::aws::core {
    variable version 1.0.0
    variable labels {s3 S3 sqs SQS dynamodb DynamoDB lambda Lambda iam IAM ssm SSM kms KMS ses SES sts STS}
}
# Return a dictionary value or a caller-supplied default.
proc ::aws::core::get {dict key {default {}}} {
    if {[dict exists $dict $key]} {return [dict get $dict $key]}
    return $default
}
# Read a nonempty environment setting or its default.
proc ::aws::core::env {name {default {}}} {
    if {[info exists ::env($name)] && $::env($name) ne {}} {return $::env($name)}
    return $default
}
# Reject misspelled or unsupported dictionary options.
proc ::aws::core::options {dict allowed} {
    dict for {k v} $dict {if {$k ni $allowed} {error "unknown option: $k"}}
    return $dict
}
# Require a nonempty dictionary field.
proc ::aws::core::required {dict key} {
    if {![dict exists $dict $key] || [dict get $dict $key] eq {}} {error "missing or empty option: $key"}
    return [dict get $dict $key]
}
# Validate an integer before constructing an AWS request.
proc ::aws::core::integer {v min max {name value}} {
    if {![string is entier -strict $v] || $v < $min || $v > $max} {error "$name must be an integer between $min and $max"}
    return $v
}
# Normalize Tcl boolean spellings to zero or one.
proc ::aws::core::boolean {v} {
    if {![string is boolean -strict $v]} {error "expected boolean value but got \"$v\""}
    expr {!!$v}
}
# Build a typed JSON array of strings.
proc ::aws::core::strings {values} {
    set out {}; foreach v $values {lappend out [list S $v]}; return [list L $out]
}
# Build a typed JSON object with string values.
proc ::aws::core::stringmap {values} {
    set out {}; dict for {k v} $values {dict set out $k [list S $v]}; return [list M $out]
}
# Serialize a request with explicit JSON field types.
proc ::aws::core::json_encode {fields} {::tjson::typed_to_json [list M $fields]}
# Decode UTF-8 JSON responses into Tcl values.
proc ::aws::core::json_decode {bytes} {::tjson::json_to_simple [encoding convertfrom utf-8 $bytes]}
# Read a file as bytes and always close its channel.
proc ::aws::core::readfile {path} {
    set f [open $path rb]; try {return [read $f]} finally {close $f}
}
# Percent-encode UTF-8 bytes using the SigV4 unreserved set.
proc ::aws::core::uri {text {slash 0}} {
    set result {}
    binary scan [encoding convertto utf-8 $text] cu* bytes
    foreach b $bytes {
        if {($b>=65 && $b<=90) || ($b>=97 && $b<=122) || ($b>=48 && $b<=57) || $b in {45 46 95 126} || ($slash && $b==47)} {
            append result [format %c $b]
        } else {append result %[format %02X $b]}
    }
    return $result
}
# Encode and sort query pairs without converting spaces to plus signs.
proc ::aws::core::querystring {pairs} {
    set out {}; foreach {k v} $pairs {lappend out "[uri $k]=[uri $v]"}
    return [join [lsort -ascii $out] &]
}
# Validate an HTTP URL and split its authority, path and query.
proc ::aws::core::urlparts {url} {
    if {![regexp {^(https?)://([^/?#]+)(/[^?#]*)?(?:\?([^#]*))?$} $url -> scheme authority path query] || [string first @ $authority] >= 0} {
        error "expected an HTTP(S) URL without user information or fragment"
    }
    if {$path eq {}} {set path /}
    return [dict create scheme $scheme authority $authority path $path query $query]
}
# Resolve commercial, China and GovCloud service endpoints.
proc ::aws::core::endpoint {service region} {
    if {![regexp {^[a-z0-9]+(?:-[a-z0-9]+)+-[0-9]+$} $region]} {error "invalid AWS region"}
    if {[string match cn-* $region]} {set suffix amazonaws.com.cn} else {set suffix amazonaws.com}
    if {[string match us-iso* $region] || [string match eu-isoe-* $region]} {error "this AWS partition requires an explicit endpoint"}
    if {$service eq "iam"} {
        if {[string match cn-* $region]} {return https://iam.cn-north-1.amazonaws.com.cn}
        if {[string match us-gov-* $region]} {return https://iam.us-gov.amazonaws.com}
        return https://iam.amazonaws.com
    }
    if {$service eq "ses"} {set service email}
    return "https://$service.$region.$suffix"
}
# Raise an AWS error with a stable service and exception code.
proc ::aws::core::aws_error {service code message} {
    variable labels
    return -code error -errorcode [list AWS [get $labels $service $service] $code] $message
}
# Parse UTF-8 XML with external parameter entities disabled.
proc ::aws::core::xml {bytes} {
    dom parse -paramentityparsing never [encoding convertfrom utf-8 $bytes]
}
# Select XML elements independently of their namespace prefix.
proc ::aws::core::nodes {node path} {
    set parts {}; foreach p [split $path /] {lappend parts "*\[local-name()='$p'\]"}
    $node selectNodes [join $parts /]
}
# Read one XML value or return a default.
proc ::aws::core::xget {node path {default {}}} {
    set found [nodes $node $path]
    if {[llength $found]} {return [[lindex $found 0] text]}
    return $default
}
# Read the text of repeated XML elements.
proc ::aws::core::xlist {node path} {
    set out {}; foreach n [nodes $node $path] {lappend out [$n text]}; return $out
}
# Escape text for an XML element or attribute.
proc ::aws::core::escape_xml {text} {string map {& &amp; < &lt; > &gt; \" &quot; ' &apos;} $text}
# Extract AWS exception names and messages from JSON or XML.
proc ::aws::core::failure {service status headers body} {
    set code "HTTP$status"; set message "AWS request failed (HTTP $status)"
    if {$body ne {}} {
        if {![catch {json_decode $body} data] && ![catch {dict size $data}]} {
            set code [get $data __type [get $data code [get $data Code $code]]]
            set message [get $data message [get $data Message $message]]
        } elseif {![catch {xml $body} doc]} {
            try {
                set root [$doc documentElement]
                if {[lindex [split [$root nodeName] :] end] eq "Error"} {set e $root} else {set e [lindex [nodes $root Error] 0]}
                if {$e ne {}} {set code [xget $e Code $code]; set message [xget $e Message $message]}
            } finally {$doc delete}
        }
    }
    if {[dict exists $headers x-amzn-errortype]} {set code [dict get $headers x-amzn-errortype]}
    set code [lindex [split [lindex [split $code #] end] :] 0]
    return [list $code $message]
}

oo::class create ::aws::core::Client {
    variable service config session credentialCache
    constructor {s cfg} {
        set service $s
        ::aws::core::options $cfg {region endpoint aws_access_key_id aws_secret_access_key aws_session_token profile credentials_file config_file credentials_provider timeout timeout_connect max_attempts retry_base_ms cafile force_path_style metadata_endpoint metadata_disabled}
        if {[dict exists $cfg aws_access_key_id] != [dict exists $cfg aws_secret_access_key]} {error "aws_access_key_id and aws_secret_access_key must be supplied together"}
        set profile [::aws::core::get $cfg profile [::aws::core::env AWS_PROFILE default]]
        set files [::aws::core::profile $cfg $profile]
        set region [::aws::core::get $cfg region [::aws::core::env AWS_REGION [::aws::core::env AWS_DEFAULT_REGION [::aws::core::get $files region us-east-1]]]]
        set config [dict merge [dict create region $region profile $profile timeout 30000 timeout_connect 3000 max_attempts 3 retry_base_ms 100 force_path_style 0] $cfg]
        dict set config custom_endpoint [dict exists $cfg endpoint]
        foreach {key min max} {timeout 1 2147483647 timeout_connect 1 2147483647 max_attempts 1 10 retry_base_ms 0 60000} {::aws::core::integer [dict get $config $key] $min $max $key}
        dict set config force_path_style [::aws::core::boolean [dict get $config force_path_style]]
        if {![dict exists $config endpoint]} {dict set config endpoint [::aws::core::endpoint $s $region]}
        ::aws::core::urlparts [dict get $config endpoint]
        set opts [list -allow_redirects false -timeout [dict get $config timeout] -timeout_connect [dict get $config timeout_connect]]
        if {[dict exists $config cafile]} {lappend opts -cafile [dict get $config cafile]}
        set session [::trequests::session {*}$opts]
        set credentialCache {}
    }
    destructor {if {[info exists session]} {catch {$session destroy}}; return}
    method awsservice {} {return $service}
    method awsconfig {} {return $config}
    method awscredentials {{invalidate 0}} {
        if {$invalidate} {set credentialCache {}}
        if {$credentialCache eq {} || ([dict exists $credentialCache expiration] && [dict get $credentialCache expiration] < [clock seconds]+60)} {
            set credentialCache [::aws::core::credentials $config]
        }
        return $credentialCache
    }
    method awsrequest {method url headers body {retry 0}} {
        set limit [expr {$retry ? [dict get $config max_attempts] : 1}]
        for {set attempt 1} {$attempt <= $limit} {incr attempt} {
            set cred [my awscredentials]
            set signed $headers
            if {[::aws::core::get $cred aws_session_token] ne {}} {dict set signed X-Amz-Security-Token [dict get $cred aws_session_token]}
            set region [dict get $config region]
            if {$service eq "iam"} {
                if {[string match cn-* $region]} {set region cn-north-1} elseif {[string match us-gov-* $region]} {set region us-gov-west-1} else {set region us-east-1}
            }
            set signing [expr {$service eq "ses" ? "ses" : $service}]
            set opts [list -headers $signed -auth [list [dict get $cred aws_access_key_id] [dict get $cred aws_secret_access_key]] -auth_aws_sigv4 [list aws amz $region $signing]]
            if {$method in {POST PUT PATCH} || [string length $body]} {lappend opts -data_binary $body}
            if {$service eq "s3"} {lappend opts -path_as_is true -decode_content false}
            set response [$session request $method $url {*}$opts]
            try {
                if {[$response state] eq "error"} {
                    set code TransportError; set message [$response error]; set status 0; set rh {}; set rb {}
                } else {
                    set status [$response status_code]; set rb [$response content]; set rh {}
                    foreach name {x-amzn-errortype x-amzn-requestid x-amz-request-id x-amz-bucket-region x-amz-function-error etag retry-after content-encoding} {
                        if {![catch {$response header $name} values] && [llength $values]} {dict set rh $name [lindex $values end]}
                    }
                    if {$status >= 200 && $status < 300} {return [dict create status $status headers $rh body $rb]}
                    lassign [::aws::core::failure $service $status $rh $rb] code message
                }
            } finally {$response destroy}
            set transient [expr {$status in {0 429 500 502 503 504} || $code in {Throttling ThrottlingException ThrottledException TooManyRequestsException RequestLimitExceeded ProvisionedThroughputExceededException RequestTimeout SlowDown}}]
            if {$code in {ExpiredToken ExpiredTokenException}} {set credentialCache {}; set transient 1}
            if {!$transient || $attempt >= $limit} {::aws::core::aws_error $service $code $message}
            set delay [expr {int(rand()*min(20000,[dict get $config retry_base_ms]*(2**($attempt-1))))}]
            if {[dict exists $rh retry-after] && [string is integer -strict [dict get $rh retry-after]]} {set delay [expr {min(20000,1000*[dict get $rh retry-after])}]}
            after $delay
        }
    }
    method unknown {method args} {::aws::core::dispatch $service [self] $method {*}$args}
}
# Reject stale handles and clients belonging to another service.
proc ::aws::core::client {service handle} {
    if {![info object isa object $handle] || ![info object isa typeof $handle ::aws::core::Client] || [$handle awsservice] ne $service} {
        variable labels
        error "[get $labels $service $service] client handle not found in this interpreter"
    }
    return $handle
}
# Route only registered service methods through validated handles.
proc ::aws::core::dispatch {service handle method args} {
    client $service $handle
    if {$method eq "destroy"} {
        if {[llength $args]} {error "wrong # args: should be \"$handle destroy\""}
        $handle destroy; return
    }
    set methods [namespace eval ::aws::$service {set methods}]
    if {$method ni $methods} {error "unknown method \"$method\": must be [join $methods {, }], or destroy"}
    ::aws::${service}::_$method $handle {*}$args
}
# Release a client when its bound variable leaves scope.
proc ::aws::core::release {handle args} {if {[info object isa object $handle]} {$handle destroy}}
# Construct a client and optionally bind its lifetime to a variable.
proc ::aws::core::create {service config {varname {}}} {
    set handle [::aws::core::Client new $service $config]
    if {$varname ne {}} {
        upvar 2 $varname var
        set var $handle
        trace add variable var unset [list ::aws::core::release $handle]
    }
    return $handle
}
# Expose the shared client and namespace API for one service.
proc ::aws::core::register {service methods} {
    if {[llength [info commands ::aws::${service}::create]]} {error "AWS $service implementation already loaded"}
    namespace eval ::aws::$service [list variable methods $methods]
    # Construct a client and optionally bind its lifetime to a variable.
    proc ::aws::${service}::create {config {varname {}}} [format {::aws::core::create %s $config $varname} $service]
    foreach method [concat $methods destroy] {
        # Expose a namespace command backed by the same service implementation.
        proc ::aws::${service}::$method {handle args} [format {::aws::core::dispatch %s $handle %s {*}$args} $service $method]
    }
}
# Send an AWS JSON request and decode its response.
proc ::aws::core::json {client target fields {version 1.1} {retry 0}} {
    set cfg [$client awsconfig]
    set response [$client awsrequest POST [dict get $cfg endpoint] [dict create X-Amz-Target $target Content-Type application/x-amz-json-$version] [encoding convertto utf-8 [json_encode $fields]] $retry]
    if {[dict get $response body] eq {}} {return {}}
    return [json_decode [dict get $response body]]
}
# Send an AWS Query request and return its XML document.
proc ::aws::core::query {client action version fields {retry 0}} {
    set cfg [$client awsconfig]
    set body [querystring [concat [list Action $action Version $version] $fields]]
    set response [$client awsrequest POST [dict get $cfg endpoint] [dict create Content-Type {application/x-www-form-urlencoded; charset=utf-8}] [encoding convertto utf-8 $body] $retry]
    return [xml [dict get $response body]]
}
# Detect repeated pagination tokens before another request.
proc ::aws::core::next {seenVar token} {
    upvar 1 $seenVar seen
    if {$token eq {}} {return 0}
    if {$token in $seen} {error "AWS returned a repeated pagination token"}
    lappend seen $token; return 1
}
source [file join [file dirname [info script]] credentials.tcl]
source [file join [file dirname [info script]] signing.tcl]
package provide pure-tcl-aws-core 1.0.0
