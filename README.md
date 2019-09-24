# ejabberd JWT authentication

[![Build Status](https://travis-ci.org/yokomizor/ejabberd-auth-jwt.svg?branch=master)](https://travis-ci.org/yokomizor/ejabberd-auth-jwt)
[![Coverage Status](https://img.shields.io/coveralls/github/yokomizor/ejabberd-auth-jwt/master.svg)](https://coveralls.io/github/yokomizor/ejabberd-auth-jwt?branch=master)

**NOTE: Since version [19.08](https://github.com/processone/ejabberd/blob/master/CHANGELOG.md#version-1908) ([3e5c0a1d](https://github.com/processone/ejabberd/commit/3e5c0a1df84b3e7871178fea350d1c2ec2537c6d)), ejabberd officially supports JWT authentication. In other words, this modules is not necessary anymore if you are using 19.08 or newer.**

This module enables [JWT](https://jwt.io/introduction/) authentication on [ejabberd](https://www.ejabberd.im/).

## Installation

The easiest way to install this module is using `ejabberdctl`:

```
# 1. Create the target directory.
mkdir -p ~/.ejabberd-modules/sources

# 2. Copy the source code into the target directory.
#
# Here we are using git, but you can copy it manually in case git is not available in your host.
#
# You should also edit the configuration file located at conf/ejabberd_auth_jwt (examples below).
git clone git@github.com:yokomizor/ejabberd-auth-jwt.git ~/.ejabberd-modules/sources/ejabberd_auth_jwt/

# 3. Load module
ejabberdctl module_install ejabberd_auth_jwt

# 4. Restart Ejabberd
# 
# Just reloading config won't update auth_method :/
ejabberdctl stop
ejabberdctl start # or foreground
```


## Configuration examples

Default config file: `~/.ejabberd-modules/ejabberd_auth_jwt/conf/ejabberd_auth_jwt.yml`.

**Symetric HMAC key**

```
auth_method: jwt
modules:
  ejabberd_auth_jwt:
    key: "SECRET" 
    strict_alg: "HS256" 
```


**Asymetric RSA key**

```
auth_method: jwt
modules:
  ejabberd_auth_jwt:
    pem_file: "/home/ejabberd/conf/jwt.pem" # Public key 
    strict_alg: "RS256" 
```


**Custom user claim**

This module checks if the JWT claim `sub` matches the user jid.
To use a custom JWT claim:

```
auth_method: jwt
modules:
  ejabberd_auth_jwt:
    user_claim: "myjid" 
```


**[JWKS](https://auth0.com/docs/jwks) key**

JWKS is a set of keys containing the public keys that should be used to verify
any JWT issued by the authorization server. Servers usually expose a JWKS
endpoint at https://example.com/.well-known/jwks.json.

To configure this module to check a JWKS list:

```
auth_method: jwt
modules:
  ejabberd_auth_jwt:
    user_claim: "username" 
    jwks_url: "https://cognito-idp.{region}.amazonaws.com/{userPoolId}/.well-known/jwks.json"
```

