# Smart IP AllowList

[中文说明](README_zh.md)

A Traefik v3 HTTP middleware plugin that selects a client IP from configurable
request headers and checks it against an allowlist.

## Features

- `sourceRange`: The allowlist. It accepts multiple individual IP addresses and
  CIDR ranges; every entry must be a valid IP address or CIDR.
- `ipHeaders`: Request headers checked in order. A value may contain
  comma-separated IP addresses. Requests with repeated instances of the same
  configured header are rejected. When omitted or empty, the defaults are
  `X-Forwarded-For` followed by `X-Real-Ip`.
- `privateSubnets`: IP ranges skipped during the first request-header scan.
  When omitted or empty, the defaults are `10.0.0.0/8`, `100.64.0.0/10`,
  `172.16.0.0/12`, `192.168.0.0/16`, and `198.18.0.0/15`.
- `headersForce`: If the first scan finds no usable address, accept the first
  valid header IP, including a private IP. The selected address must still
  match `sourceRange`.
- `rejectStatusCode`: HTTP status returned for rejected requests. Defaults to
  `403`.
- `debug`: Writes accept/reject decisions to standard error. Defaults to
  `false`; this output is independent of Traefik's global log level.

## Security

Only trust forwarded-IP headers when requests can reach Traefik exclusively
through trusted proxies that set or overwrite those headers. Otherwise, a
client can forge headers such as `X-Forwarded-For`, `X-Real-IP`, or
`CF-Connecting-IP`.

`privateSubnets` affects client-IP selection only; it does not reject private
addresses itself. The final selected address is always checked against
`sourceRange`.

## Dynamic configuration

The plugin alias below is `smartIpAllowlist`; it must match the alias configured
under `experimental.plugins` or `experimental.localPlugins`.

```yaml
http:
  middlewares:
    smart-ip-allowlist:
      plugin:
        smartIpAllowlist:
          sourceRange:
            - "203.0.113.10/32"
            - "198.51.100.0/24"
          ipHeaders:
            - "CF-Connecting-IP"
            - "X-Real-IP"
            - "X-Forwarded-For"
          # Omitting privateSubnets uses the built-in defaults.
          headersForce: false
          rejectStatusCode: 403
          debug: false
```

Replace the documentation-only IP ranges with the addresses or ranges that
should be allowed in your environment. Do not use `0.0.0.0/0` for an actual
allowlist, as it allows every IPv4 address.

## Build and test

```bash
go test ./...
```
