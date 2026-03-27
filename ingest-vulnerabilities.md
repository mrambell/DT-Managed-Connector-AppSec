# Ingest Vulnerabilities - HTTP Action Configuration

## Overview

This step sends the formatted vulnerability findings to the Dynatrace SaaS
OpenPipeline security events endpoint using an **HTTP Request** workflow action.

## Prerequisites

- The SaaS environment must have an **OAuth client** or **API token** with the
  scope: `openpipeline.events_security`
- The token must be stored in the **Credential Vault** of the SaaS environment.

---

## Workflow Action Configuration

### Action Type
**HTTP Request** (Send request)

### Connection / Execution

Because the `format-vulnerabilities.js` action returns batches, you should
configure a **loop** on this HTTP action to iterate over each batch. Use the
expression:

```
{{ result("format_vulnerabilities").batches }}
```

Alternatively, if your finding count is always < 1000, you can skip batching
and send all findings at once.

### URL

```
https://<YOUR_SAAS_ENVIRONMENT_ID>.apps.dynatrace.com/platform/ingest/v1/security.events
```

Replace `<YOUR_SAAS_ENVIRONMENT_ID>` with your actual SaaS environment ID
(e.g., `abc12345`).

### Method

```
POST
```

### Headers

| Header          | Value                                   |
|-----------------|-----------------------------------------|
| Content-Type    | `application/json`                      |
| Authorization   | `Bearer <SaaS_OAuth_or_API_TOKEN>`      |

**For the Authorization header**, reference the credential vault:
- Use "Connection" pointing to the SaaS environment if available, OR
- Use a credential vault reference in the header value.

### Request Body

Use a **Jinja expression** to inject the batch from the previous action:

**If using batching (loop):**
```
{{ item }}
```

Where `item` is the loop variable containing one batch (array of findings).

**If sending all findings at once:**
```
{{ result("format_vulnerabilities").findings }}
```

The body must be a **JSON array** of finding objects. Example:

```json
[
  {
    "timestamp": 1711497600000000000,
    "event.id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
    "event.kind": "SECURITY_EVENT",
    "event.type": "VULNERABILITY_FINDING",
    "event.name": "Vulnerability finding event",
    "event.provider": "Dynatrace Managed",
    "event.description": "HTTP/2 Stream Cancellation Attack",
    "finding.id": "f1a2b3c4-d5e6-7890-abcd-ef1234567890",
    "dt.security.risk.level": "HIGH",
    "dt.security.risk.score": 8.4,
    "vulnerability.id": "CVE-2023-45871",
    "vulnerability.title": "HTTP/2 Stream Cancellation Attack",
    "vulnerability.references.cve": ["CVE-2023-45871"],
    "vulnerability.cvss.base_score": 7.5,
    "vulnerability.cvss.vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
    "vulnerability.risk.level": "HIGH",
    "vulnerability.risk.score": 8.4,
    "vulnerability.remediation.status": "AVAILABLE",
    "vulnerability.technology": "JAVA",
    "vulnerability.type": "HTTP/2 Stream Cancellation Attack",
    "vulnerability.url": "https://jak10854.live.dynatrace.com/ui/security/problem/13832399175368191923",
    "object.id": "PROCESS_GROUP_INSTANCE-ABC123",
    "object.name": "MyJavaService",
    "object.type": "process_group_instance",
    "component.name": "tomcat-embed-core-9.0.64.jar",
    "component.version": "9.0.64",
    "product.name": "DT Managed Connector",
    "product.vendor": "Dynatrace",
    "product.feature": "Third-party Vulnerability Analytics",
    "scan.id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
    "scan.time.completed": "2026-03-27T12:00:00.000Z",
    "scan.time.started": "2026-03-27T12:00:00.000Z",
    "dt.source_entity": "PROCESS_GROUP_INSTANCE-ABC123",
    "dt.source_entity.type": "process_group_instance",
    "dt.entity.process_group_instance": "PROCESS_GROUP_INSTANCE-ABC123",
    "dt.entity.process_group": "PROCESS_GROUP-DEF456",
    "dt.entity.host": "HOST-GHI789",
    "dt.entity.software_component": "SOFTWARE_COMPONENT-JKL012",
    "software_component.type": "library",
    "software_component.version": "9.0.64",
    "software_component.purl": "pkg:maven/org.apache.tomcat.embed/tomcat-embed-core"
  }
]
```

### Expected Response

| Code | Meaning                                       |
|------|-----------------------------------------------|
| 202  | Accepted — findings ingested successfully     |
| 400  | Bad request — check payload format            |
| 413  | Payload too large — reduce batch size         |
| 429  | Rate limited — add retry/delay between batches|

### Error Handling

- Configure the action to **retry on 429 and 5xx** with exponential backoff.
- Log the response status and body on failure for debugging.

---

## Recommended Sync Schedule

Set the workflow to run **every 15 minutes**.

Rationale:
- Vulnerability data in Managed changes infrequently (new detections,
  status changes, re-scans).
- 15 minutes provides near-real-time visibility without excessive API load.
- Adjust to 5 minutes if you need faster propagation, or 30–60 minutes
  if API rate limits are a concern.

---

## Full Workflow Summary

| Step | Action Type   | Name                    | Purpose                                         |
|------|---------------|-------------------------|--------------------------------------------------|
| 1    | JavaScript    | fetch_vulnerabilities   | Fetch vulns + enrich with PGI/Host from Managed  |
| 2    | JavaScript    | format_vulnerabilities  | Transform to OpenPipeline security event format   |
| 3    | HTTP Request  | ingest_vulnerabilities  | POST findings to SaaS OpenPipeline endpoint       |

### Wiring

- **Step 2** receives input from Step 1:
  Map `result_from_fetch` → `{{ result("fetch_vulnerabilities") }}`
- **Step 3** receives input from Step 2:
  Body → `{{ result("format_vulnerabilities").batches }}` (loop) or
  `{{ result("format_vulnerabilities").findings }}` (single request)

---

## Security Notes

- **Never hardcode tokens** in JavaScript actions. Use the Credential Vault.
- In `fetch-vulnerabilities.js`, replace `<CREDENTIAL_VAULT_REF>` with a
  reference to the Managed API token stored in your SaaS Credential Vault.
- Ensure the Managed API token has these scopes:
  - `securityProblems.read`
  - `entities.read`
