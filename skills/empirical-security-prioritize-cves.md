---
name: Prioritize CVEs by exploitation probability
description: Authenticate to Empirical Security and rank vulnerabilities by real-time exploitation probability so remediation is prioritized on likelihood of attack.
api: openapi/empirical-security-openapi.yml
operations: [searchCves, getCve, getCveScoreHistory]
---

# Prioritize CVEs by exploitation probability

Use the Empirical Security API to find and rank the CVEs most likely to be
exploited, using the Foundation (`global`) model or an EPSS model
(`epss_v5`).

## 1. Authenticate

Empirical uses OAuth 2.0 client credentials. Exchange your client ID/secret
(HTTP Basic) at the FusionAuth token endpoint:

```
POST https://empiricalsecurity.fusionauth.io/oauth2/token
Authorization: Basic base64(client_id:client_secret)
grant_type=client_credentials
scope=target-entity:0c6d5dcc-8bf0-4cd1-bd65-066ef0422369
```

The response `access_token` is a JWT valid for one hour. Send it as
`Authorization: Bearer <JWT>` on every request.

## 2. Search for high-risk CVEs (`searchCves`)

Query with Empirical search syntax and pick a scoring model:

```
GET /search?q=score:>90&scoring_model=epss_v5
```

Returns an array of CVEs with `has_exploitation_activity` and per-model
`scores` (`score` + `percentile`). Rank by percentile.

## 3. Inspect a specific CVE (`getCve`)

```
GET /cves/CVE-2023-49103
```

Read `scores` for the model(s) you care about and `has_exploitation_activity`.

## 4. Confirm the trend (`getCveScoreHistory`)

```
GET /cves/CVE-2023-49103/score_history?scoring_model=epss_v5
```

A rising score history is a stronger prioritization signal than a single point.

## Rules

- All operations are GET (read-only) — no idempotency key needed.
- Errors return `{ "error": { "code", "message" } }` (not RFC 9457). Handle
  `missing_token`/`invalid_token` (401) by refreshing the JWT, and
  `parameter_missing` (400) by supplying `scoring_model`.
- Set `accept=application/jsonl` to stream large result sets as JSON Lines.
