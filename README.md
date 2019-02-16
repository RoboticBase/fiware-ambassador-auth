# fiware-ambassador-auth
This REST API service works with Ambassador on Kubernetes in order to authorize and authanticate the client.

[![TravisCI Status](https://travis-ci.org/RoboticBase/fiware-ambassador-auth.svg?branch=master)](https://travis-ci.org/RoboticBase/fiware-ambassador-auth)
[![Docker image size](https://img.shields.io/microbadger/image-size/roboticbase/fiware-ambassador-auth.svg)](https://hub.docker.com/r/roboticbase/fiware-ambassador-auth/)

## Description
This REST API service accepts any path and any methods, and checks the Authorization Header of HTTP Request. In this version, Bearer Token Authorization and Basic Authorization are acceptable.

The authrization and authentication flow is like below:

1. If request host does not match any `host`s, this service responds `403 Forbidden`.
1. If request path contains `no_auths.allowed_paths` associated with the host, this service responds `200 OK`.
1. If request host matches but Authorization Header does not exist, this service always responds with `401 Unauhtorized`.
1. If Bearer Token does not exist in `bearer_tokens` associated with the host, this service responds with `401 Unauthorized`.
1. If Bearer Token exists but requested path does not exist in `bearer_tokens[?].allowed_paths` associated with the host and Token, this service responds `403 Forbidden`.
1. If a set of username and password does not exist in `basic_auths` associated with the host, this service responds with `401 Unauthorized`.
1. If valid username and password exists but requested path does not exist in `basic_auths[?].allowed_paths` associated with the host and user, this service responds `403 Forbidden`.
1. otherwise, this service responds `200 OK`.

This REST API service is assumed to work with [Ambassador](https://www.getambassador.io/) on [Kubernetes](https://www.getambassador.io/).

## `AUTH_TOKENS` JSON template

* `host` and `allowed_paths` can accept "rgular expression".

```text
[
  {
    "host": "<<1st_FQDN_regex>>",
    "settings": {
      "bearer_tokens": [
        {
          "token": "<<token1>>",
          "allowed_paths": ["<<allowed_path1_regex>>", "<<allowed_path2_regex>>", ...]
        }, {
          ...
        }
      ],
      "basic_auths": [
        {
          "username": "<<user1>>",
          "password": "<<password_of_user1>>",
          "allowed_paths": ["<<allowed_path1_regex>>", "<<allowed_path2_regex>>", ...]
        }, {
          ...
        }
      ],
      "no_auths": {
        "allowed_paths": ["<<allowed_path1_regex>>", "<<allowed_path2_regex>>", ...]
      }
    }
  },
  {
    "host": "<<2nd_FQDN_regex>>",
    "settings": {
      ...
    }
  }
]
```

> example:
>
> ```json
> [
>   {
>     "host": "^api\\..+$",
>     "settings": {
>       "bearer_tokens": [
>         {
>           "token": "cTHMfPsSDbPd8y4TcsiNg2CnI0Y5mpfl",
>           "allowed_paths": ["^/path1/.*$", "^/path2/\\d+/.*.*$"]
>         }, {
>           "token": "Q0H83rnkIUVPSnoQb9UpZkEXIb42b5x9",
>           "allowed_paths": ["^/path1/.*$"]
>         }
>       ],
>       "basic_auths": [],
>       "no_auths": {}
>     }
>   },
>   {
>     "host": "^web\\..+$",
>     "settings": {
>       "bearer_tokens": [],
>       "basic_auths": [
>         {
>           "username": "admin",
>           "password": "0YziWgALc6PCXgwt4rn8qVxX6iANBRvl",
>           "allowed_paths": ["^/management/users/$", "^/management/pages/.*$"]
>         }, {
>           "username": "user1",
>           "password": "0YziWgALc6PCXgwt4rn8qVxX6iANBRvl",
>           "allowed_paths": ["^/management/pages/.*$"]
>         }
>       ],
>       "no_auths": {
>         "allowed_paths": ["^.*/static/.*$"]
>       }
>     }
>   }
> ]
> ```

## Run as Docker container

1. Pull container [roboticbase/fiware-ambassador-auth](https://hub.docker.com/r/roboticbase/fiware-ambassador-auth/) from DockerHub.

    ```bash
    $ docker pull roboticbase/fiware-ambassador-auth
    ```
1. Run Container.
    * If you want to change exposed port, set the `LISTEN_PORT` environment variable.

    ```bash
    $ docker run -d -e AUTH_TOKENS="$(cat auth-tokens.json)" -e LISTEN_PORT=3000 -p 3000:3000 roboticbase/fiware-ambassador-auth
    ```

## Build from source code

1. go get

    ```bash
    $ go get -u github.com/RoboticBase/fiware-ambassador-auth
    $ cd ${GOPATH}/src/github.com/RoboticBase/fiware-ambassador-auth
    ```
1. install dependencies

    ```bash
    $ go get -u github.com/golang/dep/cmd/dep
    $ dep ensure
    ```
1. go install

    ```bash
    $ go install github.com/RoboticBase/fiware-ambassador-auth
    ```
1. run service

    ```bash
    $ env LISTEN_PORT=3000 ${GOPATH}/bin/fiware-ambassador-auth
    ```

## License

[Apache License 2.0](/LICENSE)

## Copyright
Copyright (c) 2018 TIS Inc.
