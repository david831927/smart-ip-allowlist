# Smart IP AllowList Traefik 插件

这是一个 Traefik v3 HTTP 中间件插件：它根据可配置的请求头选择客户端 IP，
再检查该 IP 是否在允许列表中。

## 功能

- `sourceRange`：允许列表，支持多个单独 IP 地址和 CIDR 网段；每个条目必须是有效的 IP 或 CIDR。
- `ipHeaders`：按顺序检查的请求头，支持逗号分隔的多个 IP。同名请求头出现多次时会被拒绝。
  未配置或为空时，依次使用 `X-Forwarded-For`、`X-Real-Ip`。
- `privateSubnets`：首次扫描请求头时跳过的 IP 网段。
- 未配置或为空数组时，`privateSubnets` 使用以下默认值；每个显式配置的条目必须是有效 IP 或 CIDR：
  - `10.0.0.0/8`
  - `100.64.0.0/10`
  - `172.16.0.0/12`
  - `192.168.0.0/16`
  - `198.18.0.0/15`
- `headersForce`：如果首次查找失败，则接受请求头中第一个有效的 IP，
  包括私有 IP。选中的 IP 仍必须匹配 `sourceRange`。
- `rejectStatusCode`：默认为 HTTP 403。
- `debug`：是否将请求放行或拒绝结果写入标准错误输出，默认为 `false`。
  该日志不受 Traefik 全局日志级别控制。

## 重要安全提示

仅当请求只能通过负责设置这些转发请求头的可信代理到达 Traefik 时，才应信任
这些请求头。否则，客户端可能伪造 `X-Forwarded-For`、`X-Real-IP` 或
`CF-Connecting-IP` 等请求头。

`privateSubnets` 影响 IP 的选择，但它本身不会拒绝私有地址。允许列表
（`sourceRange`）始终应用于最终选中的 IP。

## 动态配置示例

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
          # 省略 privateSubnets 时使用内置默认值。
          headersForce: false
          rejectStatusCode: 403
          debug: false
```

请将仅用于文档说明的示例 IP 网段替换为实际需要允许的 IP。

## 构建与测试

```bash
go test ./...
```
