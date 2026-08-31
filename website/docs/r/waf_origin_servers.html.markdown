---
subcategory: "WAF"
page_title: "fortiappseccloud_waf_origin_servers Resource - fortiappseccloud"
description: |-
  Configures the complete origin server-pool collection for one FortiAppSec Cloud WAF application.
---

# fortiappseccloud_waf_origin_servers

Configures the complete mutable `server_pools` collection for one application. This resource owns every pool and server in that collection, so include all entries that must remain. Use `waf_app.initial_origin` only to bootstrap application creation.

## Example Usage

```hcl
resource "fortiappseccloud_waf_origin_servers" "example" {
  ep_id = fortiappseccloud_waf_app.example.ep_id

  server_pools {
    name = "default_pool"

    health {
      enabled = false
    }

    persistence {
      type = "disable"
    }

    servers {
      address          = "origin.example.com"
      port             = 443
      ssl              = true
      encryption_level = "mozilla_intermediate"
      status           = "enable"
      type             = "domain"
    }
  }
}
```

The `default_pool` name matches the pool referenced by the content-routing example. Use unique pool names and keep content-routing `server_pool` values synchronized with this resource.

## Argument Reference

- `ep_id` (Required, Forces replacement) — Application endpoint ID.
- `server_pools` (Required Block, at least one) — Ordered, complete server-pool collection. Include every pool that must remain configured. Pool names identify existing pools when the provider preserves omitted optional/computed values during an update.

### `server_pools`

- `server_pools.name` (Required) — Unique server-pool name, from 1 through 40 UTF-8 characters. Content-routing policies refer to this exact value through their `server_pool` argument.
- `server_pools.lb_algorithm` (Optional, Computed) — Algorithm used to distribute new connections. One of `round-robin`, `weighted-round-robin`, `least-connections`, or `src-ip-hash`. Defaults to `round-robin` for a newly configured pool.
- `server_pools.server_balance` (Optional, Computed) — Enables load balancing across the pool's `servers` blocks. Defaults to `true`. When `true`, configure each server's `port`; when `false`, use `http_port` and/or `https_port` for the single-server service ports.
- `server_pools.health` (Required Block) — Health-check policy for this pool.
- `server_pools.persistence` (Required Block) — Client-session persistence policy for this pool.
- `server_pools.servers` (Required Block, at least one) — Ordered, complete origin-server collection. Add one block for each server that must remain in the pool. The provider generates sequential one-based wire indices.

### `server_pools.health`

- `enabled` (Required) — Enables or disables active origin health checks. The remaining health settings apply when this is `true`.
- `code` (Optional, Computed) — HTTP response status required for a successful check, from `200` through `599`. Defaults to `302` for a newly configured policy.
- `interval` (Optional, Computed) — Seconds between health checks, from `1` through `300`. Defaults to `10`.
- `matched` (Optional, Computed) — Response content that must be present for a successful `get` or `post` check. Maximum 1024 UTF-8 characters.
- `method` (Optional, Computed) — Health-check HTTP method: `head`, `get`, or `post`. Defaults to `head`.
- `retry` (Optional, Computed) — Number of retries after a failed check, from `1` through `10`. Defaults to `3`.
- `timeout` (Optional, Computed) — Health-check timeout in seconds, from `1` through `30`. Defaults to `3`.
- `url` (Optional, Computed) — Request path used by the health check, such as `/healthz`. Maximum 255 UTF-8 characters.

### `server_pools.persistence`

- `type` (Required) — How subsequent requests from a client are associated with the same origin: `disable`, `source-ip`, or `insert-cookie`.
- `timeout` (Optional, Computed) — Maximum time between client requests, in seconds, from `10` through `86400`. Configure it only for `source-ip` or `insert-cookie`. No unconditional Terraform default is applied because the value is type-dependent.
- `domain` (Optional, Computed) — Cookie `Domain` attribute for `insert-cookie`, up to 255 UTF-8 characters.
- `name` (Optional, Computed) — Cookie name for `insert-cookie`, up to 127 UTF-8 characters.
- `path` (Optional, Computed) — Cookie `Path` attribute for `insert-cookie`, up to 255 UTF-8 characters.

### `server_pools.servers`

- `type` (Required) — How the origin is identified: `ip`, `domain`, or `dynamic`.
- `status` (Required) — Origin status: `enable`, `disable`, or `maintain`.
- `address` (Required for `ip` and `domain`) — Origin IP address or fully qualified domain name. Do not configure it for a `dynamic` origin.
- `connection_name` (Required for `dynamic`) — Cloud Connector name. Do not configure it for an `ip` or `domain` origin.
- `connection_filters` (Optional Block) — Cloud Connector selectors for a `dynamic` origin. Each block requires `name` and a `values` list.
- `port` (Optional, Computed) — Origin TCP port when `server_balance = true`, from `1` through `65535`.
- `http_port` (Optional, Computed) — HTTP service port when `server_balance = false`, from `1` through `65535`.
- `https_port` (Optional, Computed) — HTTPS service port when `server_balance = false`, from `1` through `65535`.
- `ssl` (Optional, Computed) — Uses TLS for the origin connection. Defaults to `true`.
- `encryption_level` (Required when `ssl = true`) — Origin cipher policy: `mozilla_modern`, `mozilla_intermediate`, `mozilla_old`, `customized`, `high`, or `medium`.
- `certificate_verify` (Optional, Computed) — Enables origin TLS certificate verification. Defaults to `false`.
- `tls_1_0` (Optional, Computed) — Allows TLS 1.0 when TLS is enabled. No unconditional default is applied.
- `tls_1_1` (Optional, Computed) — Allows TLS 1.1 when TLS is enabled. No unconditional default is applied.
- `tls_1_2` (Optional, Computed) — Allows TLS 1.2 when TLS is enabled. Defaults to `true`.
- `tls_1_3` (Optional, Computed) — Allows TLS 1.3 when TLS is enabled. Defaults to `true`.
- `http2` (Optional, Computed) — Allows HTTP/2 when supported by the origin. Defaults to `false`.
- `backup` (Optional, Computed) — Marks this as a backup origin. Defaults to `false`.
- `weight` (Optional, Computed) — Relative connection-distribution weight, from `1` through `9999`. Defaults to `1`.
- `health_check_status` (Computed) — Current server-owned health-check status.
- `locked` (Computed) — Current server-owned lock state.

### `server_pools.servers.connection_filters`

- `name` (Required) — Cloud Connector filter-key name.
- `values` (Required) — Ordered list of values for the filter key.

Optional/computed values omitted from configuration are read from FortiAppSec Cloud and preserved when an existing pool and server can be matched by stable configured identity. The resource still owns the membership and ordering of the complete `server_pools` and `servers` collections: omitting a pool or server removes it from the next PUT.

## Import

Import using the application `ep_id`.

```shell
terraform import fortiappseccloud_waf_origin_servers.example application-endpoint-id
```

After import, add the complete observed pool configuration to HCL and require a zero-change plan before applying.

## Destroy Behavior

Destroy removes only Terraform state and emits a warning. It leaves the remote origin-server configuration unchanged.
