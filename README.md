# bot-idp

`bot-idp` is an OpenID Connect Provider that asks visitor to solve a challenge.

# Examples

## Run bot-idp

Run from source repository:

```console
$ DEBUG=1 ADDRESS=:4159 SECRET=nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A CLIENT_ID=bot-idp CLIENT_SECRET=secret1 ID_TOKEN_ISSUER=http://localhost:4159 DIFFICULTY=16 go run .
2025/03/23 21:21:08 DEBUG Keys signingKeyPub=11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo
2025/03/23 21:21:08 INFO Listen address=:4159
```

## With oauth2-proxy

Run [oauth2-proxy](https://oauth2-proxy.github.io/oauth2-proxy/)
using [example config](doc/oauth2-proxy.cfg):

```console
$ head -c 32 /dev/urandom | base64 | tr '/+' '_-' > /tmp/secret.txt
$ docker run --rm -it --network=host -v ./doc/oauth2-proxy.cfg:/oauth2-proxy.cfg quay.io/oauth2-proxy/oauth2-proxy:v7.8.1 --config /oauth2-proxy.cfg --cookie-secret=$(cat /tmp/secret.txt)
[2025/03/23 21:42:31] [provider.go:55] Performing OIDC Discovery...
[2025/03/23 21:42:31] [proxy.go:77] mapping path "/" => static response 200
[2025/03/23 21:42:31] [oauthproxy.go:172] OAuthProxy configured for OpenID Connect Client ID: bot-idp
[2025/03/23 21:42:31] [oauthproxy.go:178] Cookie settings: name:_oauth2_proxy secure(https):false httponly:true expiry:168h0m0s domains:.localtest.me path:/ samesite: refresh:disabled
```

and navigate to http://oauth2-proxy.localtest.me:4180/


## With Skipper

[Skipper](https://github.com/zalando/skipper) does not allow insecure cookies, so run using patched Skipper:

<details>
<summary>diff</summary>

```diff
$ git --no-pager diff
diff --git a/filters/auth/oidc.go b/filters/auth/oidc.go
index 88c952c5..bc7d62d6 100644
--- a/filters/auth/oidc.go
+++ b/filters/auth/oidc.go
@@ -489,10 +489,10 @@ func getHost(request *http.Request) string {

 func (f *tokenOidcFilter) createOidcCookie(ctx filters.FilterContext, name string, value string, maxAge int) (cookie *http.Cookie) {
        return &http.Cookie{
-               Name:     name,
-               Value:    value,
-               Path:     "/",
-               Secure:   true,
+               Name:  name,
+               Value: value,
+               Path:  "/",
+               //Secure:   true,
                HttpOnly: true,
                MaxAge:   maxAge,
                Domain:   extractDomainFromHost(getHost(ctx.Request()), f.subdomainsToRemove),
```

</details>

```console
$ head -c 32 /dev/urandom | base64 > /tmp/secret.txt
$ go run ./cmd/skipper/ -inline-routes='
all: *
    -> oauthOidcAllClaims("http://localhost:4159",
        "bot-idp", "secret1",
        "http://skipper.localtest.me:9090/oauth2/callback",
        "openid", "sub")
    -> inlineContent("OK\n")
    -> <shunt>;
' -oidc-secrets-file=/tmp/secret.txt -application-log-level=debug
...
[APP]INFO[0000] Listen on :9090
...
```

and navigate to http://skipper.localtest.me:9090/

See [documentation](https://opensource.zalando.com/skipper/reference/filters/#oauthoidcallclaims) for configuration details.
