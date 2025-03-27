# ⛏️ bot-idp

`bot-idp` is an [OpenID Connect](https://openid.net/developers/how-connect-works/) Provider that authenticates user browser
via [proof-of-work](https://en.wikipedia.org/wiki/Proof_of_work).
It is intended to slow down (AI) bots and scrapers.

# How it works

`bot-idp` works with any `reverse-proxy` that supports OpenID Connect protocol:

1. End user **navigates to a website or web application** via a browser.
2. `reverse-proxy` checks session **cookie** and proxies to the backend if it is valid.
3. Otherwise `reverse-proxy` **redirects user** to the `bot-idp`.
4. `bot-idp` **authenticates the User** by running a piece of code in their browser
   to obtain proof-of-work and use it to issue an **Identity Token**.
5. `bot-idp` **responds with an Identity Token** and an Access Token.
6. The `reverse-proxy` can **send a request** with the Access Token to the User device (not implemeneted).
7. The UserInfo Endpoint **returns Claims** about the End-User (not implemeneted).

# Examples

## Run bot-idp

Run from source repository:

```shell
DEBUG=1 \
DIFFICULTY=16 \
ADDRESS=:4159 \
SECRET=$(head -c 32 /dev/urandom | base64) \
CLIENT_ID=bot-idp \
CLIENT_SECRET=secret1 \
ISSUER=http://localhost:4159 \
EXPIRES_IN=3600 \
go run .
```
```
2025/03/23 21:21:08 DEBUG Keys signingKeyPub=11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo
2025/03/23 21:21:08 INFO Listen address=:4159
```

or via Docker:

```shell
docker pull ghcr.io/alexanderyastrebov/bot-idp:latest
docker run -p 4159:4159 \
-e DEBUG=1 \
-e DIFFICULTY=16 \
-e ADDRESS=:4159 \
-e SECRET=$(head -c 32 /dev/urandom | base64) \
-e CLIENT_ID=bot-idp \
-e CLIENT_SECRET=secret1 \
-e ISSUER=http://localhost:4159 \
-e EXPIRES_IN=3600 \
ghcr.io/alexanderyastrebov/bot-idp
```

Increase `DIFFICULTY` to harden the challenge.

## With oauth2-proxy

Run [oauth2-proxy](https://oauth2-proxy.github.io/oauth2-proxy/) using [example config](doc/oauth2-proxy.cfg):

```shell
docker run --rm -it --network=host -v ./doc/oauth2-proxy.cfg:/oauth2-proxy.cfg quay.io/oauth2-proxy/oauth2-proxy:v7.8.1 --config /oauth2-proxy.cfg --cookie-secret=$(head -c 32 /dev/urandom | base64 | tr '/+' '_-')
```
```
[2025/03/23 21:42:31] [provider.go:55] Performing OIDC Discovery...
[2025/03/23 21:42:31] [proxy.go:77] mapping path "/" => static response 200
[2025/03/23 21:42:31] [oauthproxy.go:172] OAuthProxy configured for OpenID Connect Client ID: bot-idp
[2025/03/23 21:42:31] [oauthproxy.go:178] Cookie settings: name:_oauth2_proxy secure(https):false httponly:true expiry:168h0m0s domains:.localtest.me path:/ samesite: refresh:disabled
```

and navigate to http://oauth2-proxy.localtest.me:4180/


## With Skipper

Run [Skipper](https://github.com/zalando/skipper) using [example config](doc/skipper.yaml):

```shell
head -c 32 /dev/urandom | base64 > /tmp/secret.txt
go run github.com/zalando/skipper/cmd/skipper@latest -config-file=./doc/skipper.yaml
```
```
...
[APP]INFO[0000] Listen on :9090
...
```

and navigate to http://skipper.localtest.me:9090/

> [!NOTE]
> This example uses routes generated from [Anubis](https://github.com/TecharoHQ/anubis) `botPolicies.json`
> via [anubis2eskip](./cmd/anubis2eskip/main.go) tool.

See [Skipper documentation](https://opensource.zalando.com/skipper/reference/filters/#oauthoidcallclaims) for configuration details.
