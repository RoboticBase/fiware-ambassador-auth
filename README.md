# fiware-ambassador-auth
This REST API service works with Ambassador on Kubernetes in order to authorize and authanticate the client.

[![TravisCI Status](https://travis-ci.org/tech-sketch/fiware-ambassador-auth.svg?branch=master)](https://travis-ci.org/tech-sketch/fiware-ambassador-auth)
[![DockerHub Status](https://dockerbuildbadges.quelltext.eu/status.svg?organization=techsketch&repository=fiware-ambassador-auth)](https://hub.docker.com/r/techsketch/fiware-ambassador-auth/builds/)

## Description
This REST API service accepts any path and any methods, and checks the Authorization Header of HTTP Request. In this version, Bearer Token Authorization and Basic Authorization are acceptable.

The authrization and authentication flow is like below:

1. If request path contains `/static/`, this service responds `200 OK`.
1. If Authorization Header does not exist, this service always responds with `401 Unauhtorized`.
1. If Token does not exist in `AUTH_TOKENS` JSON which is given from the environment variable, this service responds with `401 Unauthorized`.
1. If a set of username and password does not exist in `AUTH_TOKENS` JSON which is given from the environment variable, this service responds with `401 Unauthorized`.
1. If Token exists but requested path does not be allowed, this service responds `403 Forbidden`.
1. If valid username exists but requested path does not be allowed, this service responds `403 Forbidden`.
1. otherwise, this service responds `200 OK`.

This REST API service is assumed to work with [Ambassador](https://www.getambassador.io/) on [Kubernetes](https://www.getambassador.io/).

## `AUTH_TOKENS` JSON template

* **caution**: `bearer_tokens` accept "regular expression" as the items of `allowed_paths`, but `basic_auths` **can not** accept "regular expression" as the items of `allowd_paths`.

```text
{
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
      "allowed_paths": ["<<allowed_path1_str>>", "<<allowd_path2_str>>", ...]
    }, {
      ...
    }
  ]
}
```

> example:
>
> ```json
> {
>   "bearer_tokens": [
>     {
>       "token": "cTHMfPsSDbPd8y4TcsiNg2CnI0Y5mpfl",
>       "allowed_paths": ["^/path1/.*$", "^/path2/\\d+/.*.*$"]
>     }, {
>       "token": "Q0H83rnkIUVPSnoQb9UpZkEXIb42b5x9",
>       "allowed_paths": ["^/path1/.*$"]
>     }
>   ],
>   "basic_auths": [
>     {
>       "username": "admin",
>       "password": "0YziWgALc6PCXgwt4rn8qVxX6iANBRvl",
>       "allowed_paths": ["/management/users/", "/management/pages/"]
>     }, {
>       "username": "user1",
>       "password": "0YziWgALc6PCXgwt4rn8qVxX6iANBRvl",
>       "allowed_paths": ["/management/pages/"]
>     }
>   ]
> }
> ```

## Run as Docker container

1. Pull container [techsketch/fiware-ambassador-auth](https://hub.docker.com/r/techsketch/fiware-ambassador-auth/) from DockerHub.

    ```bash
    $ docker pull techsketch/fiware-ambassador-auth
    ```
1. Run Container.
    * If you want to change exposed port, set the `LISTEN_PORT` environment variable.

    ```bash
    $ env LISTEN_PORT=3000 docker run -d -p 3000:3000 techsketch/fiware-ambassador-auth
    ```

## Build from source code

1. go get

    ```bash
    $ go get -u github.com/tech-sketch/fiware-ambassador-auth
    $ cd ${GOPATH}/src/github.com/tech-sketch/fiware-ambassador-auth
    ```
1. install dependencies

    ```bash
    $ go get -u github.com/golang/dep/cmd/dep
    $ dep ensure
    ```
1. go install

    ```bash
    $ go install github.com/tech-sketch/fiware-ambassador-auth
    ```
1. run service

    ```bash
    $ env LISTEN_PORT=3000 ${GOPATH}/bin/fiware-ambassador-auth
    ```

## License

[Apache License 2.0](/LICENSE)

## Copyright
Copyright (c) 2018 TIS Inc.
