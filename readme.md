# wazuh-confluence

Ingest Confluence audit records into Wazuh through the Confluence API endpoint
`/wiki/rest/api/audit`.

- Integration: dependency-free Python poller run by the Wazuh `command` wodle.
- Schedule: Wazuh runs it every 5 minutes.
- Incremental import: the poller stores a high-water mark and recent event IDs in
  `/var/ossec/queue/confluence/confluence-events-state.json`, so only new audit
  records are written after the initial backfill.
- Decoder/rules: flat `conf_*` fields, decoder `confluence-json`, rule IDs
  `127000-127099`.

## How it works

```text
Confluence /wiki/rest/api/audit
        |
        |  Basic auth or Bearer/PAT auth, start/limit pagination
        v
confluence_events.py  --->  /var/ossec/logs/confluence/confluence-events.json
   (command wodle, 5 min)       |
                                v
                         confluence-json decoder  --->  rules 127000-127099
```

The script writes one JSON object per line. It flattens nested Confluence audit
fields into collision-safe scalar fields such as `conf_summary`, `conf_category`,
`conf_author_account_id`, `conf_affected_name`, and `conf_changed_fields`.

## Requirements

- Wazuh 4.x manager.
- A Confluence account with Confluence administrator access.
- Network access from the Wazuh manager to the Confluence base URL.
- One supported auth method:
  - Confluence Cloud: email address plus Atlassian API token using Basic auth.
  - Data Center or proxy auth: personal access token using Bearer auth, if
    supported by your environment.

Quick API test:

```bash
curl -s -u '<email-or-user>:<api-token>' \
  -H 'Accept: application/json' \
  'https://<site>.atlassian.net/wiki/rest/api/audit?limit=1'
```

Bearer/PAT test:

```bash
curl -s -H 'Authorization: Bearer <pat-or-token>' \
  -H 'Accept: application/json' \
  'https://<site>.atlassian.net/wiki/rest/api/audit?limit=1'
```

## Installation

Run these commands on the Wazuh manager from this `wazuh-confluence` directory.

### 1. Install the integration script

```bash
sudo install -o root -g wazuh -m 0750 integration/confluence_events.py \
  /var/ossec/integrations/confluence_events.py

sudo install -d -o wazuh -g wazuh -m 0750 \
  /var/ossec/logs/confluence \
  /var/ossec/queue/confluence
```

### 2. Install configuration and secrets

```bash
sudo cp config/confluence-events.env.example /var/ossec/etc/confluence-events.env
sudo chown root:wazuh /var/ossec/etc/confluence-events.env
sudo chmod 0640 /var/ossec/etc/confluence-events.env
sudo -e /var/ossec/etc/confluence-events.env
```

For Confluence Cloud Basic auth:

```text
CONFLUENCE_BASE_URL=https://your-site.atlassian.net
CONFLUENCE_AUDIT_PATH=/wiki/rest/api/audit
CONFLUENCE_AUTH_MODE=basic
CONFLUENCE_USERNAME=admin@example.com
CONFLUENCE_API_TOKEN=<atlassian-api-token>
```

For Bearer/PAT auth:

```text
CONFLUENCE_BASE_URL=https://confluence.example.com
CONFLUENCE_AUDIT_PATH=/wiki/rest/api/audit
CONFLUENCE_AUTH_MODE=bearer
CONFLUENCE_BEARER_TOKEN=<confluence-token>
```

### 3. Install decoder and rules

```bash
sudo cp ruleset/127-confluence_decoders.xml /var/ossec/etc/decoders/
sudo cp ruleset/127-confluence_rules.xml    /var/ossec/etc/rules/

sudo chown wazuh:wazuh \
  /var/ossec/etc/decoders/127-confluence_decoders.xml \
  /var/ossec/etc/rules/127-confluence_rules.xml

sudo chmod 0660 \
  /var/ossec/etc/decoders/127-confluence_decoders.xml \
  /var/ossec/etc/rules/127-confluence_rules.xml
```

### 4. Add ossec.conf blocks

Add the two blocks from `config/ossec.conf.snippet` inside the top-level
`<ossec_config>` element in `/var/ossec/etc/ossec.conf`.

The important schedule setting is:

```xml
<interval>5m</interval>
```

That means Wazuh runs the poller every 5 minutes. The poller itself exits after
one incremental import.

### 5. Test and restart

```bash
sudo -u wazuh CONFLUENCE_DEBUG=true /var/ossec/integrations/confluence_events.py

tail -n1 /var/ossec/logs/confluence/confluence-events.json | sudo /var/ossec/bin/wazuh-logtest

sudo systemctl restart wazuh-manager
```

## Configuration Reference

All settings live in `/var/ossec/etc/confluence-events.env`.

| Variable | Default | Description |
|---|---:|---|
| `CONFLUENCE_BASE_URL` | required | Confluence base URL, no trailing slash. |
| `CONFLUENCE_AUDIT_PATH` | `/wiki/rest/api/audit` | Audit API path. |
| `CONFLUENCE_AUTH_MODE` | `auto` | `auto`, `basic`, or `bearer`. |
| `CONFLUENCE_USERNAME` | empty | Username or email for Basic auth. |
| `CONFLUENCE_API_TOKEN` | empty | API token/password for Basic auth. |
| `CONFLUENCE_API_TOKEN_FILE` | empty | File containing the API token. |
| `CONFLUENCE_BEARER_TOKEN` / `CONFLUENCE_PAT` | empty | Bearer/PAT token. |
| `CONFLUENCE_BEARER_TOKEN_FILE` | empty | File containing the bearer token. |
| `CONFLUENCE_BACKFILL_HOURS` | `24` | Initial backfill window. |
| `CONFLUENCE_LOOKBACK_SECONDS` | `300` | Query overlap for late-arriving events. |
| `CONFLUENCE_SEEN_RETENTION_HOURS` | `48` | How long to retain dedupe IDs. |
| `CONFLUENCE_LIMIT` | `1000` | Records per page. |
| `CONFLUENCE_MAX_PAGES` | `10` | Maximum pages per run. |
| `CONFLUENCE_DATE_FORMAT` | `date` | `date`, `iso`, or `epoch_ms` for `startDate`/`endDate`. |
| `CONFLUENCE_INCLUDE_END_DATE` | `true` | Include a bounded `endDate` query parameter. |
| `CONFLUENCE_SEARCH_STRING` | empty | Optional Confluence audit search string. |
| `CONFLUENCE_EXTRA_QUERY` | empty | Optional extra query string. |
| `CONFLUENCE_DEBUG` | `false` | Verbose stderr logging. |

## Event Fields

| Field | Notes |
|---|---|
| `conf_integration` | Always `confluence`; used by the decoder and base rule. |
| `conf_event_id` | API event ID or stable hash fallback. |
| `conf_creation_date`, `conf_created_utc` | Original and normalized event time. |
| `conf_summary`, `conf_action` | Human-readable summary and normalized action slug. |
| `conf_category` | Confluence audit category. |
| `conf_author_account_id`, `conf_author_name` | Actor fields when present. |
| `conf_src_ip` | Remote address when present. |
| `conf_affected_*` | Primary affected object from `affectedObject`. |
| `conf_changed_fields`, `conf_changed_values` | Scalar summary of `changedValues`. |
| `conf_associated_objects`, `conf_associated_types` | Scalar summary of `associatedObjects`. |

## Ruleset Design

Rule IDs are `127000-127099`. Within each family the most specific rule
appears first in the file, because sibling rules under `127000` are evaluated
in file order and the first match wins. Correlation rules use
`frequency="N"`, which fires on the (N+2)th matching event within the
timeframe.

| Rule | Level | Meaning |
|---|---:|---|
| `127000` | 3 | Base rule for every Confluence audit record. |
| `127010` | 5 | Single failed authentication. |
| `127011` | 10 | 5 failed authentications by the same account in 4 minutes. |
| `127012` | 10 | 7 failed authentications from the same source IP in 4 minutes. |
| `127013` | 3 | Successful login/logout (kept low, out of the fallback tier). |
| `127015` | 9 | Admin key, websudo/secure admin session, or impersonation. |
| `127016` | 11 | MFA/2FA/SSO/SAML disabled or removed. |
| `127017` | 10 | Other authentication/password configuration changes. |
| `127019` | 7 | Administrative privilege removed. |
| `127020` | 12 | Administrative privilege or global permission granted. |
| `127021` | 12 | User added to a group whose name contains `admin` (structured). |
| `127022` | 11 | Anonymous/public/guest/external exposure enabled. |
| `127023` | 5 | Exposure removed or set to private. |
| `127024` | 10 | Global permission changed. |
| `127025` | 7 | Space/page permission or restriction changed. |
| `127026` | 10 | 5 permission/exposure changes by the same actor in 10 minutes. |
| `127030` | 10 | App/plugin/webhook installed, enabled, or OAuth app authorized. |
| `127031` | 6 | App/plugin removed or disabled. |
| `127032` | 10 | API/personal access token created. |
| `127033` | 5 | API/personal access token revoked. |
| `127040` | 5 | Page/blog/attachment/template/comment deleted. |
| `127041` | 10 | Space deleted or archived. |
| `127042` | 10 | 8 deletions by the same actor in 5 minutes (mass deletion). |
| `127045` | 6 | Group or group membership changed. |
| `127046` | 5 | User lifecycle change (create/invite/deactivate/delete). |
| `127050` | 11 | Audit log configuration/retention changed or records purged. |
| `127051` | 7 | Audit log exported. |
| `127052` | 5 | Audit log viewed or searched. |
| `127060` | 12 | Full site export or backup activity. |
| `127061` | 9 | Space export. |
| `127062` | 8 | Restore or import activity. |
| `127063` | 6 | Single page/attachment export or download. |
| `127064` | 12 | 5 export/backup/download events by the same actor in 10 minutes. |
| `127090` | 6 | Fallback: security/identity audit categories. |
| `127091` | 5 | Fallback: remaining administrative/content categories. |

Severity levels are aligned with the Jira `126xxx` ruleset so the same event
class scores the same level in both products.

## Dashboard

`dashboard/confluence-audit-dashboard.ndjson` is a ready-to-import "Confluence
Audit Events" dashboard for OpenSearch Dashboards 2.19 (Wazuh dashboard). It
covers overview KPIs and severity trends, top actors/summaries, security
detections with a MITRE ATT&CK table, authentication and brute-force
correlations, permission/exposure changes, content deletion (including the
mass-deletion correlation), export/backup collection, audit-log integrity,
users/groups plus guest and external-collaborator activity, a
category-fallback canary, and a rule coverage reference. Every panel is scoped
by a dashboard-level `data.conf_integration:confluence` filter.

Import via **Dashboards Management → Saved objects → Import** (requires the
`wazuh-alerts-*` index pattern). To customize, edit
`dashboard/generate_dashboard.py` and re-run it to regenerate the NDJSON.

## Operational Notes

- The first run imports up to `CONFLUENCE_BACKFILL_HOURS` of history.
- Later runs query from the saved high-water mark minus `CONFLUENCE_LOOKBACK_SECONDS`.
- Recent event IDs are retained so the lookback window catches late events
  without duplicating already imported records.
- The default `CONFLUENCE_DATE_FORMAT=date` is compatible with Confluence audit
  date filters but may ask Confluence for the whole current day. Dedupe ensures
  only new records are written to Wazuh.
- Keep `/var/ossec/etc/confluence-events.env` owned by `root:wazuh` and mode
  `0640`.
- Keep `/var/ossec/logs/confluence` and `/var/ossec/queue/confluence` owned by
  `wazuh:wazuh` or writable by the Wazuh user.

## Troubleshooting

- `HTTP 401`: credentials are wrong or the auth mode does not match your Confluence.
- `HTTP 403`: the account does not have Confluence administrator access.
- `HTTP 400`: check `CONFLUENCE_AUDIT_PATH` and `CONFLUENCE_DATE_FORMAT`.
- No alerts: confirm the localfile path, run `wazuh-logtest`, and restart
  `wazuh-manager` after installing the decoder/rules.
- Duplicate lines after a crash: remove only the duplicate log lines if needed;
  do not delete the state file unless you intentionally want to backfill again.
