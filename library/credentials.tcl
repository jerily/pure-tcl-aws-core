# 
# Copyright Jerily LTD. All Rights Reserved.
# SPDX-FileCopyrightText: 2026 Neofytos Dimitriou (neo@jerily.cy)
# SPDX-License-Identifier: MIT.
# 

# Read shared AWS INI files without evaluating their contents.
proc ::aws::core::ini {filename} {
    set result {}; set section {}
    if {![file exists $filename]} {return $result}
    foreach line [split [encoding convertfrom utf-8 [readfile $filename]] \n] {
        set line [string trim $line]
        if {$line eq {} || [string index $line 0] in {# {;}}} {continue}
        if {[regexp {^\[([^\]]+)\]$} $line -> section]} {set section [string trim $section]; continue}
        if {$section ne {} && [regexp {^([^=]+)=(.*)$} $line -> key value]} {
            dict set result $section [string trim $key] [string trim $value]
        }
    }
    return $result
}

# Merge one profile, giving the credentials file precedence.
proc ::aws::core::profile {config name} {
    set home [env HOME ~]
    set cf [get $config config_file [env AWS_CONFIG_FILE [file join $home .aws config]]]
    set af [get $config credentials_file [env AWS_SHARED_CREDENTIALS_FILE [file join $home .aws credentials]]]
    set section [expr {$name eq "default" ? "default" : "profile $name"}]
    return [dict merge [get [ini $cf] $section] [get [ini $af] $name]]
}

# Normalize provider output and reject incomplete or expired credentials.
proc ::aws::core::normalize_credentials {data} {
    foreach {from to} {AccessKeyId aws_access_key_id SecretAccessKey aws_secret_access_key SessionToken aws_session_token Token aws_session_token Expiration expiration} {
        if {[dict exists $data $from]} {dict set data $to [dict get $data $from]}
    }
    required $data aws_access_key_id; required $data aws_secret_access_key
    if {[dict exists $data expiration]} {
        set exp [dict get $data expiration]
        if {![string is entier -strict $exp]} {set exp [clock scan $exp -gmt 1]}
        if {$exp <= [clock seconds]} {error "credential provider returned expired credentials"}
        dict set data expiration $exp
    }
    return $data
}

# Fetch metadata with short timeouts and redirects disabled.
proc ::aws::core::metadata {method url {headers {}}} {
    set r [::trequests::request $method $url -headers $headers -timeout 2000 -timeout_connect 1000 -allow_redirects false]
    try {
        if {[$r state] eq "error"} {error "credential endpoint transport failure: [$r error]"}
        if {[$r status_code] != 200} {error "credential endpoint returned HTTP [$r status_code]"}
        return [$r content]
    } finally {$r destroy}
}

# Restrict plaintext container credential endpoints to local AWS addresses.
proc ::aws::core::container_url {url} {
    set p [urlparts $url]
    set host [string tolower [dict get $p authority]]
    if {[dict get $p scheme] eq "http" && ![regexp {^(localhost|127\.[0-9]+\.[0-9]+\.[0-9]+|169\.254\.170\.(2|23)|\[::1\]|\[fd00:ec2::23\])(:[0-9]+)?$} $host]} {
        error "HTTP container credential endpoint must be loopback or an AWS container address"
    }
    return $url
}

# Exchange role parameters for temporary credentials using STS Query.
proc ::aws::core::role_credentials {config fields {source {}}} {
    set region [get $config region us-east-1]
    set endpoint [endpoint sts $region]
    set action [expr {$source eq {} ? "AssumeRoleWithWebIdentity" : "AssumeRole"}]
    if {$source eq {}} {
        set body [querystring [concat [list Action $action Version 2011-06-15] $fields]]
        set r [::trequests::post $endpoint -allow_redirects false -timeout 10000 -timeout_connect 3000 -content_type application/x-www-form-urlencoded -data_binary [encoding convertto utf-8 $body]]
        try {
            if {[$r state] eq "error"} {error "STS credential exchange failed: [$r error]"}
            set bytes [$r content]
            if {[$r status_code] != 200} {lassign [failure sts [$r status_code] {} $bytes] code message; aws_error sts $code $message}
            set doc [xml $bytes]
        } finally {$r destroy}
    } else {
        set cfg [dict create region $region endpoint $endpoint]
        foreach k {aws_access_key_id aws_secret_access_key aws_session_token} {if {[dict exists $source $k]} {dict set cfg $k [dict get $source $k]}}
        set c [Client new sts $cfg]
        try {set doc [query $c $action 2011-06-15 $fields]} finally {$c destroy}
    }
    try {
        set root [$doc documentElement]
        set node [lindex [nodes $root ${action}Result/Credentials] 0]
        if {$node eq {}} {error "STS response is missing credentials"}
        set result {}; foreach k {AccessKeyId SecretAccessKey SessionToken Expiration} {dict set result $k [xget $node $k]}
        return [normalize_credentials $result]
    } finally {$doc delete}
}

# Resolve profile roles recursively while detecting source-profile cycles.
proc ::aws::core::profile_credentials {config name {seen {}}} {
    if {$name in $seen} {error "cyclic AWS source_profile chain"}
    lappend seen $name
    set p [profile $config $name]
    if {[dict exists $p role_arn]} {
        set fields [list RoleArn [dict get $p role_arn] RoleSessionName [get $p role_session_name pure-tcl-aws]]
        if {[dict exists $p external_id]} {lappend fields ExternalId [dict get $p external_id]}
        if {[dict exists $p duration_seconds]} {lappend fields DurationSeconds [integer [dict get $p duration_seconds] 900 43200 duration_seconds]}
        if {[dict exists $p web_identity_token_file]} {
            lappend fields WebIdentityToken [string trim [encoding convertfrom utf-8 [readfile [dict get $p web_identity_token_file]]]]
            return [role_credentials $config $fields]
        }
        if {[dict exists $p mfa_serial]} {error "MFA role profiles require a credentials_provider callback"}
        if {[dict exists $p source_profile]} {
            set source [profile_credentials $config [dict get $p source_profile] $seen]
        } else {error "role profile requires source_profile or web_identity_token_file"}
        return [role_credentials $config $fields $source]
    }
    if {[dict exists $p aws_access_key_id] || [dict exists $p aws_secret_access_key]} {return [normalize_credentials $p]}
    if {[dict exists $p credential_process]} {
        # Execute an argv list directly; never evaluate a shell or Tcl script.
        set argv [dict get $p credential_process]
        if {![llength $argv]} {error "credential_process is empty"}
        if {[catch {exec -- {*}$argv} bytes]} {error "credential_process failed"}
        set data [json_decode $bytes]
        if {[get $data Version] != 1} {error "credential_process must return Version 1"}
        return [normalize_credentials $data]
    }
    if {[dict exists $p sso_start_url] || [dict exists $p sso_session]} {error "SSO profiles require a credentials_provider callback or credential_process"}
    return {}
}

# Resolve explicit, environment, profile, web identity, container or IMDSv2 credentials.
proc ::aws::core::credentials {config} {
    if {[dict exists $config credentials_provider]} {return [normalize_credentials [{*}[dict get $config credentials_provider]]]}
    if {[dict exists $config aws_access_key_id]} {return [normalize_credentials $config]}
    set access [env AWS_ACCESS_KEY_ID]; set secret [env AWS_SECRET_ACCESS_KEY]
    if {$access ne {} || $secret ne {}} {return [normalize_credentials [dict create aws_access_key_id $access aws_secret_access_key $secret aws_session_token [env AWS_SESSION_TOKEN]]]}
    if {[env AWS_WEB_IDENTITY_TOKEN_FILE] ne {} && [env AWS_ROLE_ARN] ne {}} {
        return [role_credentials $config [list RoleArn [env AWS_ROLE_ARN] RoleSessionName [env AWS_ROLE_SESSION_NAME pure-tcl-aws] WebIdentityToken [string trim [encoding convertfrom utf-8 [readfile [env AWS_WEB_IDENTITY_TOKEN_FILE]]]]]]
    }
    set fromProfile [profile_credentials $config [get $config profile [env AWS_PROFILE default]]]
    if {$fromProfile ne {}} {return $fromProfile}
    set relative [env AWS_CONTAINER_CREDENTIALS_RELATIVE_URI]
    set full [env AWS_CONTAINER_CREDENTIALS_FULL_URI]
    if {$relative ne {} || $full ne {}} {
        if {$relative ne {}} {
            if {![string match /* $relative] || [string match //* $relative]} {error "invalid container credentials relative URI"}
            set full "http://169.254.170.2$relative"
        }
        set headers {}; set token [env AWS_CONTAINER_AUTHORIZATION_TOKEN]
        if {[env AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE] ne {}} {set token [string trim [readfile [env AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE]]]}
        if {$token ne {}} {dict set headers Authorization $token}
        return [normalize_credentials [json_decode [metadata GET [container_url $full] $headers]]]
    }
    if {![boolean [get $config metadata_disabled [env AWS_EC2_METADATA_DISABLED false]]]} {
        set base [string trimright [get $config metadata_endpoint [env AWS_EC2_METADATA_SERVICE_ENDPOINT http://169.254.169.254]] /]
        set token [metadata PUT $base/latest/api/token {X-aws-ec2-metadata-token-ttl-seconds 21600}]
        set headers [dict create X-aws-ec2-metadata-token $token]
        set role [string trim [metadata GET $base/latest/meta-data/iam/security-credentials/ $headers]]
        if {$role eq {} || [string first \n $role] >= 0} {error "invalid instance profile role response"}
        return [normalize_credentials [json_decode [metadata GET $base/latest/meta-data/iam/security-credentials/[uri $role] $headers]]]
    }
    aws_error core CredentialsNotFound "no AWS credentials found"
}
