# WAF template example

This example shows the base `fortiappseccloud_waf_template` lifecycle plus one hand-written and one generated typed template-module resource.

Template creation requires `POST /v2/waf/template` to return `201 Created`, a stable `result.template_id`, and `Location: /v2/waf/template/{template_id}`.

Application membership is separate. Bind an application with `fortiappseccloud_waf_template_attachment`; do not put application endpoint IDs in the template resource.

Template-module endpoints have no `DELETE`. Destroy therefore disables the module: Terraform performs a fresh GET, preserves the complete response, applies the resource's reviewed status fields, PUTs and verifies the result, and then removes the resource from state. Thirty resources set only `template=false` and `configs.status=false`; caching/compression also sets its coupled `configs.cache.status=false` and `configs.compress.status=false` fields.
