# intercertificate

> **Status: TODO**

The `inter_certificate` (and related certificate / CRL content-upload) resources
are **not yet developed**. This package is intentionally left as an empty
placeholder to mark where the future implementation will live.

## Why it is not implemented yet

The Terraform surface for certificate content (certificate, private-key, CA,
and CRL upload / attachment) depends on the exact wire contract of the backend
APIs. Those contracts are currently represented as `SingleJsonObject` (untyped)
in the pinned OpenAPI spec, so a durable, typed Terraform schema cannot be
safely derived from them yet.

Per the product-scope decision recorded in `CURRENT.md`, the following families
are explicit **terminal exclusions** for the v2.0.0 goal:

- `inter_certificate`
- `sni_certificate`
- `server_ca`
- `server_crl`
- `ca_certificate`
- `crl_certificate`

Application-level **automatic/custom certificate mode** (`waf_app.certificate_mode`)
is already covered in v2.0.0 — it switches between `automatic` (`cert_type=0`) and
`custom` (`cert_type=1`) certificate management, without uploading any certificate
or private-key content.

## When this can move forward

Development can resume only after:

1. The OpenAPI spec is updated so that certificate/CRL upload and attachment
   endpoints expose a typed, stable request schema (not `SingleJsonObject`).
2. The exact wire format is coordinated / confirmed against the backend API
   (including numeric certificate identity and delete-by-action semantics).
3. The product scope explicitly expands to allow certificate-content upload
   resources in a future release.

Until then, this package remains an intentional TODO placeholder. Do not add
certificate-content surfaces to the served provider goal.
