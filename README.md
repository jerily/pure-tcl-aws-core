# pure-tcl-aws-core

Shared AWS client infrastructure for Tcl 9.1: HTTP sessions, credentials,
AWS Signature Version 4 (SigV4) configuration, presigned URLs, JSON, Query/XML
and structured errors.
The implementation is Tcl; its HTTP, JSON, XML and hashing dependencies contain native
code. No AWS C++ SDK or AWS CRT package is required.

## Packages

Each service is maintained and installed separately:

- `pure-tcl-aws-s3`
- `pure-tcl-aws-sqs`
- `pure-tcl-aws-dynamodb`
- `pure-tcl-aws-lambda`
- `pure-tcl-aws-iam`
- `pure-tcl-aws-ssm`
- `pure-tcl-aws-kms`
- `pure-tcl-aws-ses`

Each depends only on this core package. The core declares Tcl >=9.1,<10,
`trequests` >=1.3,<2, `tjson` >=1.0.27,<2, `tdom` >=0.9.6,<0.10 and `thashlib` >=0.1,<1.
Tcl 8.6 is deliberately unsupported by the AWS packages.

## Client configuration

Service clients share this configuration dictionary:

| Key | Default / behavior |
| --- | --- |
| `region` | `AWS_REGION`, then `AWS_DEFAULT_REGION`, profile region, then `us-east-1` |
| `endpoint` | Regional service endpoint; override for local fixtures or compatible services |
| `aws_access_key_id`, `aws_secret_access_key` | Explicit credentials; supply both |
| `aws_session_token` | Session token for explicit temporary credentials |
| `profile` | `AWS_PROFILE`, then `default` |
| `credentials_file`, `config_file` | Standard AWS environment overrides or `~/.aws/` files |
| `credentials_provider` | Tcl command prefix returning a credential dictionary |
| `timeout`, `timeout_connect` | 30000 and 3000 milliseconds |
| `max_attempts`, `retry_base_ms` | 3 attempts and 100 ms initial retry delay |
| `cafile` | Optional CA bundle; TLS verification remains enabled |
| `force_path_style` | False; custom S3 endpoints and dotted bucket names use path-style addressing |
| `metadata_disabled` | `AWS_EC2_METADATA_DISABLED`, otherwise false |
| `metadata_endpoint` | `AWS_EC2_METADATA_SERVICE_ENDPOINT`, otherwise EC2 IMDS |

Clients are interpreter-local TclOO objects. Destroying or deleting a client
releases its HTTP session. `create config ?varname?` can bind a client's lifetime
to a variable; unsetting that variable releases the client. Do not load a native
`aws-sdk-tcl` implementation and its pure Tcl replacement in the same interpreter.
Service compatibility packages advertise `awsSERVICE` version 1.0.19; the new
service packages use version 1.0.0 and require core 1.0.0.
Core 1.0.0 removes the Tcllib dependency; the original 0.1.0 service releases remain on core 0.x.

## Credentials

Resolution order is: explicit callback, explicit credentials, environment keys,
environment web identity, shared profiles, container credentials, then IMDSv2.
Profiles support static keys, `credential_process`, `source_profile` role chains,
and web-identity token files. Role chains detect cycles. Temporary credentials
are cached per client and refreshed before expiration. Container authorization
tokens and IMDSv2 tokens are supported; metadata requests have short timeouts
and never follow redirects.

A callback returns `aws_access_key_id`, `aws_secret_access_key`, optional
`aws_session_token`, and optional `expiration` (Unix seconds or an ISO timestamp).
AWS-style `AccessKeyId`, `SecretAccessKey`, `SessionToken`/`Token`, and `Expiration`
are accepted too. `credential_process` uses a directly executed Tcl argv list
and must return the standard version-1 JSON document. No shell is evaluated.

Interactive SSO, MFA, and `credential_source` profiles are not implemented;
use a callback or process provider for those environments. Explicit credentials
without expiration remain fixed until the client is recreated. There is no
background credential thread.

## Requests and errors

libcurl supplies request signing. S3 paths are preserved when parsing the URL,
and content decoding is disabled so stored object bytes remain unchanged.
Presigned URLs use thashlib SHA-256/HMAC and match AWS's published test vector.
Commercial, China and GovCloud endpoints are supported. Other partitions need
an explicit endpoint. SigV4a and automatic redirects are not implemented.

Errors expose `-errorcode {AWS Service ExceptionName}`. Both JSON and XML errors
are decoded. Safe operations retry transient transport errors, throttling and
selected server errors with bounded exponential jitter. Expired credentials
are refreshed before a safe retry. Sending email/messages, invoking Lambda,
conditional writes and other ambiguous mutations are not automatically retried.
The per-request timeout applies to each attempt; it is not a whole-operation
deadline. Public service operations are synchronous.

## Install and test

After installing the dependencies:

```sh
make install PREFIX=/your/prefix
make test TCLSH=tclsh9.1
```

The release recipe declares a runnable example with file notation:

```json
"scripts": {
  "example-encode": { "file": "run-example.sh", "args": ["encode"] }
}
```

Run it with `ttrek run -package pure-tcl-aws-core -script example-encode`.
Tests use Python 3 loopback fixtures and fake credentials, including independent
signature verification, credential refresh, profile roles, web identity,
container credentials, IMDSv2, retries and non-BMP Unicode. They do not contact AWS.

Protocol references: [AWS SigV4](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_sigv-create-signed-request.html),
[S3 presigning test vector](https://docs.aws.amazon.com/AmazonS3/latest/userguide/sigv4-query-string-auth.html),
and [libcurl signing](https://curl.se/libcurl/c/CURLOPT_AWS_SIGV4.html).

## Install with ttrek

If you do not have the ttrek client, get it from [ttrek.sh](https://ttrek.sh).
Then install the package:

```sh
ttrek install pure-tcl-aws-core
```
