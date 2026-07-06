#!/usr/bin/env python3
"""Generate the 'Confluence Audit Events' dashboard NDJSON for OpenSearch Dashboards 2.19.

Scope: dashboard-level filter pins data.conf_integration:confluence so every panel inherits it.
Source: wazuh-confluence integration (/var/ossec/integrations/confluence_events.py, polled
every 5 minutes) -> confluence-json decoder -> ruleset 127000-127099.

Flat fields emitted by the poller power the panels:
  data.conf_summary             human-readable audit summary (what the rules match on)
  data.conf_category            Confluence audit category
  data.conf_author_name         display name of the acting user
  data.conf_author_account_id   actor account id (what the correlation rules key on)
  data.conf_author_is_guest     true when the actor is a guest user
  data.conf_author_is_external_collaborator  true for external collaborators
  data.conf_src_ip              source IP when the audit record carries one
  data.conf_affected_type/name  primary object acted on
  data.conf_site_host           Confluence site host

Index pattern: wazuh-alerts-*  (saved-object id == title).
Import: OpenSearch Dashboards -> Dashboards Management -> Saved objects -> Import.
"""
import json
import os

IDX = "wazuh-alerts-*"
IDXREF = "kibanaSavedObjectMeta.searchSourceJSON.index"
D = "data."
OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "confluence-audit-dashboard.ndjson")
objects = []

def idx_reference():
    return [{"name": IDXREF, "type": "index-pattern", "id": IDX}]

def viz(vid, title, vis_state, extra_filters=None):
    refs = idx_reference()
    filters = []
    if extra_filters:
        for i, (f, _field) in enumerate(extra_filters):
            ref_name = f"kibanaSavedObjectMeta.searchSourceJSON.filter[{i}].meta.index"
            f = json.loads(json.dumps(f))
            f["meta"]["indexRefName"] = ref_name
            filters.append(f)
            refs.append({"name": ref_name, "type": "index-pattern", "id": IDX})
    ss = {"query": {"query": "", "language": "kuery"}, "filter": filters, "indexRefName": IDXREF}
    objects.append({
        "id": vid, "type": "visualization",
        "attributes": {
            "title": title, "visState": json.dumps(vis_state), "uiStateJSON": "{}",
            "description": "", "version": 1,
            "kibanaSavedObjectMeta": {"searchSourceJSON": json.dumps(ss)},
        },
        "references": refs,
    })

# ---- filters ----------------------------------------------------------------
def level_gte(n, alias):
    return ({"meta": {"alias": alias, "disabled": False, "negate": False, "type": "range",
                      "key": "rule.level", "params": {"gte": n}},
             "range": {"rule.level": {"gte": n}}, "$state": {"store": "appState"}}, "rule.level")

def phrase(field, value, alias=None, negate=False):
    return ({"meta": {"alias": alias or value, "disabled": False, "negate": negate, "type": "phrase",
                      "key": field, "params": {"query": value}},
             "query": {"match_phrase": {field: value}}, "$state": {"store": "appState"}}, field)

def kql(query, alias):
    return ({"meta": {"alias": alias, "disabled": False, "negate": False, "type": "custom", "key": "query"},
             "query": {"query_string": {"query": query}}, "$state": {"store": "appState"}}, "query")

# ---- agg builders -----------------------------------------------------------
def count_metric():
    return {"id": "1", "enabled": True, "type": "count", "schema": "metric", "params": {}}

def cardinality(field, label, gid="1"):
    return {"id": gid, "enabled": True, "type": "cardinality", "schema": "metric",
            "params": {"field": field, "customLabel": label}}

def terms(field, size, schema="segment", label=None, gid="2", order_field="1"):
    p = {"field": field, "orderBy": order_field, "order": "desc", "size": size,
         "otherBucket": False, "otherBucketLabel": "Other",
         "missingBucket": False, "missingBucketLabel": "Missing"}
    if label:
        p["customLabel"] = label
    return {"id": gid, "enabled": True, "type": "terms", "schema": schema, "params": p}

def bucket(field, size, label, gid, order_field="1"):
    return terms(field, size, "bucket", label, gid, order_field)

def filters_agg(buckets, schema="segment", gid="2"):
    return {"id": gid, "enabled": True, "type": "filters", "schema": schema,
            "params": {"filters": [{"input": {"language": "kuery", "query": q}, "label": lab}
                                    for lab, q in buckets]}}

# ---- viz factories ----------------------------------------------------------
def metric(vid, title, agg, color_to=2000000, filt=None):
    viz(vid, title, {
        "title": title, "type": "metric",
        "params": {"addTooltip": True, "addLegend": False, "type": "metric",
                   "metric": {"percentageMode": False, "useRanges": False, "colorSchema": "Green to Red",
                              "metricColorMode": "None", "colorsRange": [{"from": 0, "to": color_to}],
                              "labels": {"show": True}, "invertColors": False,
                              "style": {"bgColor": False, "labelColor": False, "subText": "", "fontSize": 36}}},
        "aggs": [agg]}, extra_filters=filt)

def pie(vid, title, field, label, size=10, filt=None):
    viz(vid, title, {
        "title": title, "type": "pie",
        "params": {"type": "pie", "addTooltip": True, "addLegend": True,
                   "legendPosition": "right", "isDonut": True,
                   "labels": {"show": True, "values": True, "last_level": True, "truncate": 100}},
        "aggs": [count_metric(), terms(field, size, "segment", label)]}, extra_filters=filt)

def pie_filters(vid, title, buckets, filt=None):
    viz(vid, title, {
        "title": title, "type": "pie",
        "params": {"type": "pie", "addTooltip": True, "addLegend": True,
                   "legendPosition": "right", "isDonut": True,
                   "labels": {"show": True, "values": True, "last_level": True, "truncate": 100}},
        "aggs": [count_metric(), filters_agg(buckets, "segment")]}, extra_filters=filt)

def table(vid, title, bucket_aggs, perPage=10, filt=None, metric_agg=None):
    viz(vid, title, {
        "title": title, "type": "table",
        "params": {"perPage": perPage, "showPartialRows": False, "showMetricsAtAllLevels": False,
                   "showTotal": True, "totalFunc": "sum", "percentageCol": "", "showToolbar": True},
        "aggs": [metric_agg or count_metric()] + bucket_aggs}, extra_filters=filt)

def _bar_axes(pos_cat, pos_val):
    return {"grid": {"categoryLines": False},
            "categoryAxes": [{"id": "CategoryAxis-1", "type": "category", "position": pos_cat,
                              "show": True, "scale": {"type": "linear"},
                              "labels": {"show": True, "filter": False, "truncate": 200}, "title": {}}],
            "valueAxes": [{"id": "ValueAxis-1", "name": "LeftAxis-1", "type": "value", "position": pos_val,
                           "show": True, "scale": {"type": "linear", "mode": "normal"},
                           "labels": {"show": True, "rotate": 0, "filter": True, "truncate": 100},
                           "title": {"text": "Count"}}],
            "seriesParams": [{"show": True, "type": "histogram", "mode": "stacked",
                              "data": {"label": "Count", "id": "1"}, "valueAxis": "ValueAxis-1",
                              "drawLinesBetweenPoints": True, "showCircles": True}],
            "addTooltip": True, "addLegend": False, "legendPosition": "right",
            "times": [], "addTimeMarker": False, "labels": {}}

def hbar(vid, title, field, label, size=15, filt=None):
    p = _bar_axes("left", "bottom"); p["type"] = "horizontal_bar"
    viz(vid, title, {"title": title, "type": "horizontal_bar", "params": p,
                     "aggs": [count_metric(), terms(field, size, "segment", label)]}, extra_filters=filt)

def timeline_filters(vid, title, buckets, filt=None):
    p = _bar_axes("bottom", "left"); p["type"] = "histogram"
    p["addLegend"] = True
    viz(vid, title, {"title": title, "type": "histogram", "params": p,
                     "aggs": [count_metric(),
                              {"id": "2", "enabled": True, "type": "date_histogram", "schema": "segment",
                               "params": {"field": "timestamp", "useNormalizedEsInterval": True,
                                          "interval": "auto", "drop_partials": False,
                                          "min_doc_count": 1, "extended_bounds": {}}},
                              filters_agg(buckets, "group", gid="3")]}, extra_filters=filt)

def markdown(vid, title, md):
    viz(vid, title, {"title": title, "type": "markdown",
                     "params": {"fontSize": 12, "openLinksInNewTab": False, "markdown": md},
                     "aggs": []})

# ---- shared bucket sets -----------------------------------------------------
SEVERITY = [("Critical/High (L≥10)", "rule.level >= 10"),
            ("Medium (L6-9)", "rule.level >= 6 and rule.level < 10"),
            ("Low/Informational (L<6)", "rule.level < 6")]

DETECTIONS = [("Admin granted (127020/1)", "rule.id:(127020 or 127021)"),
              ("MFA/SSO disabled (127016)", "rule.id:127016"),
              ("Auth config changed (127017)", "rule.id:127017"),
              ("Exposure enabled (127022)", "rule.id:127022"),
              ("Global perm changed (127024)", "rule.id:127024"),
              ("App installed (127030)", "rule.id:127030"),
              ("API token created (127032)", "rule.id:127032"),
              ("Admin key/impersonation (127015)", "rule.id:127015"),
              ("Audit log tampering (127050)", "rule.id:127050"),
              ("Site export/backup (127060)", "rule.id:127060"),
              ("Space deleted (127041)", "rule.id:127041"),
              ("Mass deletion (127042)", "rule.id:127042"),
              ("Brute force (127011/2)", "rule.id:(127011 or 127012)"),
              ("Bulk export (127064)", "rule.id:127064")]

AUTH = [("Success/session (127013)", "rule.id:127013"),
        ("Failed login (127010)", "rule.id:127010"),
        ("Brute force (127011/2)", "rule.id:(127011 or 127012)"),
        ("Admin key/impersonation (127015)", "rule.id:127015")]

PERMS = [("Exposure enabled (127022)", "rule.id:127022"),
         ("Exposure removed (127023)", "rule.id:127023"),
         ("Global perm changed (127024)", "rule.id:127024"),
         ("Perm/restriction changed (127025)", "rule.id:127025"),
         ("Repeated changes (127026)", "rule.id:127026")]

CONTENT = [("Content deleted (127040)", "rule.id:127040"),
           ("Space deleted (127041)", "rule.id:127041"),
           ("Mass deletion corr (127042)", "rule.id:127042")]

EXPORTS = [("Site export/backup (127060)", "rule.id:127060"),
           ("Space export (127061)", "rule.id:127061"),
           ("Restore/import (127062)", "rule.id:127062"),
           ("Content export/download (127063)", "rule.id:127063"),
           ("Bulk export corr (127064)", "rule.id:127064")]

AUDIT = [("Config/retention changed (127050)", "rule.id:127050"),
         ("Exported (127051)", "rule.id:127051"),
         ("Viewed/searched (127052)", "rule.id:127052")]

USERS = [("Group changed (127045)", "rule.id:127045"),
         ("User lifecycle (127046)", "rule.id:127046"),
         ("Added to admin group (127021)", "rule.id:127021")]

FALLBACK = [("Security/identity fallback (127090)", "rule.id:127090"),
            ("Admin/content fallback (127091)", "rule.id:127091")]

EXPORT_IDS = "rule.id:(127060 or 127061 or 127063 or 127064)"
PERM_IDS = "rule.id:(127022 or 127023 or 127024 or 127025 or 127026)"
DELETE_IDS = "rule.id:(127040 or 127041 or 127042)"
CORR_IDS = "rule.id:(127011 or 127012 or 127026 or 127042 or 127064)"
EXTERNAL_KQL = (f"{D}conf_author_is_guest:true or "
                f"{D}conf_author_is_external_collaborator:true")

# ============================================================================
# PANELS
# ============================================================================
markdown("conf-header", "CONF — Header",
         "## 🟦 Confluence Audit Events\n"
         "Confluence audit records from `/wiki/rest/api/audit`, collected by the "
         "`confluence_events.py` integration (command wodle, polled every 5 minutes) → "
         "`confluence-json` decoder → ruleset **127000-127099** (`wazuh-alerts-*`, scoped to "
         "`data.conf_integration:confluence`). Every audit record is flattened to "
         "collision-safe `conf_*` fields; rules classify the free-text `conf_summary` into "
         "layered severity tiers with correlation rules for brute force, repeated permission "
         "changes, mass deletion, and bulk export.")

# ---- Overview / KPIs -------------------------------------------------------
markdown("conf-md-overview", "CONF — md Overview", "### 📊 Overview")
metric("conf-total", "CONF — Total Events", count_metric())
metric("conf-actors", "CONF — Distinct Actors", cardinality(f"{D}conf_author_name", "Actors"), color_to=500)
metric("conf-categories", "CONF — Distinct Categories", cardinality(f"{D}conf_category", "Categories"), color_to=50)
metric("conf-high", "CONF — High Severity (L≥10)", count_metric(), color_to=50,
       filt=[level_gte(10, "L>=10")])
metric("conf-corr", "CONF — Correlation Alerts", count_metric(), color_to=25,
       filt=[kql(CORR_IDS, "correlations")])
metric("conf-external", "CONF — Guest/External Actor Events", count_metric(), color_to=100,
       filt=[kql(EXTERNAL_KQL, "guest/external")])
timeline_filters("conf-timeline", "CONF — Events Over Time (by severity)", SEVERITY)
pie_filters("conf-severity", "CONF — Severity Distribution", SEVERITY)
hbar("conf-category", "CONF — Category Distribution", f"{D}conf_category", "Category", 20)
hbar("conf-rules-bar", "CONF — Top Rules Fired", "rule.description", "Rule", 15)

# ---- Activity detail -------------------------------------------------------
markdown("conf-md-activity", "CONF — md Activity",
         "### 🧭 Activity Detail  \n_Who did what: most frequent audit summaries and actors, "
         "which rules fired, and which objects and sites were touched._")
table("conf-top-actions", "CONF — Top Audit Summaries (summary · category)",
      [bucket(f"{D}conf_summary", 30, "Summary", "2"),
       bucket(f"{D}conf_category", 1, "Category", "3")], 15)
table("conf-top-actors", "CONF — Top Actors (name · account id)",
      [bucket(f"{D}conf_author_name", 25, "Actor", "2"),
       bucket(f"{D}conf_author_account_id", 1, "Account ID", "3")], 15)
hbar("conf-actor-bar", "CONF — Most Active Actors", f"{D}conf_author_name", "Actor", 15)
table("conf-rules", "CONF — Rules Fired (ID · Description · Level)",
      [bucket("rule.id", 40, "Rule ID", "2"),
       bucket("rule.description", 1, "Description", "3"),
       bucket("rule.level", 1, "Level", "4")], 15)
table("conf-objects", "CONF — Objects Acted On (type · name)",
      [bucket(f"{D}conf_affected_type", 15, "Object type", "2"),
       bucket(f"{D}conf_affected_name", 3, "Top objects", "3")], 10)
table("conf-sites", "CONF — Sites (data.conf_site_host)",
      [bucket(f"{D}conf_site_host", 10, "Site host", "2"),
       bucket(f"{D}conf_author_account_type", 1, "Top account type", "3")], 10)

# ---- Security & detections -------------------------------------------------
markdown("conf-md-sec", "CONF — md Security",
         "### 🚨 Security & Detections  \n_High-signal detections from Layer 1 (summary-specific) "
         "and the correlation rules. The KPI row counts each detection family; the table lists "
         "every event at **level ≥ 8**; the MITRE table maps alerts to ATT&CK techniques._")
metric("conf-sec-admin", "Admin granted (127020/1)", count_metric(), color_to=10,
       filt=[kql("rule.id:(127020 or 127021)", "admin granted")])
metric("conf-sec-mfa", "MFA/SSO disabled (127016)", count_metric(), color_to=10,
       filt=[phrase("rule.id", "127016", "mfa disabled")])
metric("conf-sec-public", "Exposure enabled (127022)", count_metric(), color_to=10,
       filt=[phrase("rule.id", "127022", "exposure enabled")])
metric("conf-sec-app", "App installed (127030)", count_metric(), color_to=25,
       filt=[phrase("rule.id", "127030", "app installed")])
metric("conf-sec-token", "API token created (127032)", count_metric(), color_to=25,
       filt=[phrase("rule.id", "127032", "api token")])
metric("conf-sec-audit", "Audit log tampering (127050)", count_metric(), color_to=10,
       filt=[phrase("rule.id", "127050", "audit tampering")])
timeline_filters("conf-sec-timeline", "CONF — Detections Over Time", DETECTIONS)
pie_filters("conf-sec-pie", "CONF — Detection Mix", DETECTIONS)
table("conf-sec-table", "CONF — High-Severity Events (L≥8): actor · summary · detection",
      [bucket(f"{D}conf_author_name", 30, "Actor", "2"),
       bucket(f"{D}conf_summary", 1, "Summary", "3"),
       bucket("rule.description", 1, "Detection", "4"),
       bucket("rule.level", 1, "Level", "5")], 20, filt=[level_gte(8, "L>=8")])
table("conf-mitre", "CONF — MITRE ATT&CK (technique · tactic)",
      [bucket("rule.mitre.id", 20, "Technique ID", "2"),
       bucket("rule.mitre.technique", 1, "Technique", "3"),
       bucket("rule.mitre.tactic", 1, "Tactic", "4")], 10)

# ---- Authentication --------------------------------------------------------
markdown("conf-md-auth", "CONF — md Auth",
         "### 🔑 Authentication & Privileged Access  \n_Login successes vs failures, admin "
         "key/websudo/impersonation events, and the brute-force correlations (127011 "
         "per-account, 127012 per-source-IP). Source IP is only present when the audit "
         "record carries one._")
timeline_filters("conf-auth-timeline", "CONF — Authentication Over Time", AUTH)
metric("conf-auth-bf-acct", "Brute force: account (127011)", count_metric(), color_to=5,
       filt=[phrase("rule.id", "127011", "bf account")])
metric("conf-auth-bf-ip", "Brute force: source IP (127012)", count_metric(), color_to=5,
       filt=[phrase("rule.id", "127012", "bf source ip")])
table("conf-auth-fail", "CONF — Failed Logins (actor · src IP)",
      [bucket(f"{D}conf_author_name", 20, "Actor", "2"),
       bucket(f"{D}conf_src_ip", 1, "Source IP", "3")], 10,
      filt=[phrase("rule.id", "127010", "failed auth")])
table("conf-src-ip", "CONF — Source IPs (when present)",
      [bucket(f"{D}conf_src_ip", 20, "Source IP", "2"),
       bucket(f"{D}conf_author_name", 1, "Top actor", "3")], 10)

# ---- Permissions & exposure ------------------------------------------------
markdown("conf-md-perms", "CONF — md Permissions",
         "### 🛡️ Permissions & Public Exposure  \n_Space/page permission and restriction "
         "changes, global permissions, and anonymous/public/guest exposure toggles. "
         "Correlation 127026 fires on repeated changes by one actor (≥5 in 10 min)._")
timeline_filters("conf-perm-timeline", "CONF — Permission & Exposure Changes Over Time", PERMS)
table("conf-perm-actor", "CONF — Permission Changes by Actor (actor · summary)",
      [bucket(f"{D}conf_author_name", 20, "Actor", "2"),
       bucket(f"{D}conf_summary", 2, "Top changes", "3")], 10,
      filt=[kql(PERM_IDS, "perm changes")])

# ---- Content deletion ------------------------------------------------------
markdown("conf-md-content", "CONF — md Content",
         "### 🗑️ Content Deletion  \n_Page/blog/attachment deletions (127040) are routine "
         "alone; whole-space deletion (127041) is destructive; correlation 127042 fires on "
         "≥8 deletions by one actor in 5 minutes (mass-deletion / sabotage signal)._")
metric("conf-del-space", "Space deleted/archived (127041)", count_metric(), color_to=5,
       filt=[phrase("rule.id", "127041", "space deleted")])
metric("conf-del-mass", "Mass deletion corr (127042)", count_metric(), color_to=5,
       filt=[phrase("rule.id", "127042", "mass deletion")])
timeline_filters("conf-del-timeline", "CONF — Deletions Over Time", CONTENT)
table("conf-del-actor", "CONF — Deletions by Actor (actor · summary)",
      [bucket(f"{D}conf_author_name", 20, "Actor", "2"),
       bucket(f"{D}conf_summary", 2, "Top deletions", "3")], 10,
      filt=[kql(DELETE_IDS, "deletions")])

# ---- Export / backup -------------------------------------------------------
markdown("conf-md-export", "CONF — md Export",
         "### 📤 Export, Backup & Data Collection  \n_Site exports and backups (127060), space "
         "exports (127061), content downloads (127063), and the bulk-export correlation 127064 "
         "that fires on ≥5 exports by one actor in 10 minutes._")
metric("conf-export-site", "Site export/backup (127060)", count_metric(), color_to=10,
       filt=[phrase("rule.id", "127060", "site export")])
metric("conf-export-bulk", "Bulk export corr (127064)", count_metric(), color_to=5,
       filt=[phrase("rule.id", "127064", "bulk export")])
timeline_filters("conf-export-timeline", "CONF — Export/Backup Over Time", EXPORTS)
table("conf-export-actor", "CONF — Export Activity by Actor (actor · summary)",
      [bucket(f"{D}conf_author_name", 20, "Actor", "2"),
       bucket(f"{D}conf_summary", 2, "Top exports", "3")], 10,
      filt=[kql(EXPORT_IDS, "exports")])

# ---- Audit log integrity ---------------------------------------------------
markdown("conf-md-audit", "CONF — md Audit Integrity",
         "### 🧾 Audit Log Integrity  \n_Who touches the audit trail itself. Retention/config "
         "changes and purges (127050) can hide later activity — treat any hit as significant. "
         "Exports (127051) and views (127052) are normal admin behavior at low volume._")
metric("conf-audit-cfg", "Audit config changed (127050)", count_metric(), color_to=5,
       filt=[phrase("rule.id", "127050", "audit config")])
metric("conf-audit-export", "Audit log exported (127051)", count_metric(), color_to=10,
       filt=[phrase("rule.id", "127051", "audit export")])
metric("conf-audit-view", "Audit log viewed (127052)", count_metric(), color_to=100,
       filt=[phrase("rule.id", "127052", "audit viewed")])
timeline_filters("conf-audit-timeline", "CONF — Audit Log Activity Over Time", AUDIT)
table("conf-audit-actor", "CONF — Audit Log Activity by Actor (actor · summary)",
      [bucket(f"{D}conf_author_name", 15, "Actor", "2"),
       bucket(f"{D}conf_summary", 2, "Activity", "3")], 10,
      filt=[kql("rule.id:(127050 or 127051 or 127052)", "audit log activity")])

# ---- Users, groups & external actors ---------------------------------------
markdown("conf-md-users", "CONF — md Users",
         "### 👥 Users, Groups & External Actors  \n_User lifecycle and group membership changes "
         "(admin-group additions escalate to 127021, level 12), plus everything done by guest "
         "users and external collaborators — an audience worth watching on its own._")
timeline_filters("conf-users-timeline", "CONF — User & Group Changes Over Time", USERS)
table("conf-users-table", "CONF — User/Group Changes (summary · actor)",
      [bucket(f"{D}conf_summary", 20, "Change", "2"),
       bucket(f"{D}conf_author_name", 1, "Actor", "3")], 10,
      filt=[kql("rule.id:(127021 or 127045 or 127046)", "user/group changes")])
table("conf-external-table", "CONF — Guest/External Collaborator Activity (actor · summary)",
      [bucket(f"{D}conf_author_name", 20, "Actor", "2"),
       bucket(f"{D}conf_summary", 2, "Top activity", "3")], 10,
      filt=[kql(EXTERNAL_KQL, "guest/external")])

# ---- Fallback canary -------------------------------------------------------
markdown("conf-md-fallback", "CONF — md Fallback",
         "### 🕵️ Category Fallback (Canary)  \n_Events no Layer 1 rule claimed, caught by the "
         "category tiers 127090 (security/identity) and 127091 (admin/content). A sustained "
         "spike of one summary here means Confluence introduced an event the ruleset should "
         "classify — review and add a Layer 1 rule._")
timeline_filters("conf-fallback-timeline", "CONF — Fallback Hits Over Time", FALLBACK)
table("conf-fallback-table", "CONF — Unclassified Summaries (summary · category)",
      [bucket(f"{D}conf_summary", 30, "Summary", "2"),
       bucket(f"{D}conf_category", 1, "Category", "3")], 15,
      filt=[kql("rule.id:(127090 or 127091)", "fallback")])

# ---- Coverage reference ----------------------------------------------------
markdown("conf-coverage", "CONF — Coverage Reference",
         "### 🗺️ Rule & Coverage Reference\n"
         "Layered ruleset — base rule 127000 guarantees **no event is missed**; the most "
         "specific rule in each family wins (file order); category tiers backstop the long "
         "tail. Levels are aligned with the Jira 126xxx ruleset so the same event class "
         "scores the same in both products.\n\n"
         "| Rule | Level | Meaning |\n|---|---|---|\n"
         "| **127000** | 3 | Base — every Confluence audit record (no-miss catch-all) |\n"
         "| **127010** | 5 | Single failed login |\n"
         "| **127011 / 127012** | **10** | Brute force: same account / same source IP |\n"
         "| **127013** | 3 | Successful login / logout |\n"
         "| **127015** | 9 | Admin key / websudo / impersonation |\n"
         "| **127016** | **11** | MFA/2FA/SSO/SAML disabled or removed |\n"
         "| **127017** | 10 | Authentication/password config changed |\n"
         "| **127019** | 7 | Admin privilege removed |\n"
         "| **127020 / 127021** | **12** | Admin privilege granted / added to admin group |\n"
         "| **127022 / 127023** | **11** / 5 | Public/anonymous exposure enabled / removed |\n"
         "| **127024** | 10 | Global permission changed |\n"
         "| **127025** | 7 | Space/page permission or restriction changed |\n"
         "| **127026** | 10 | Repeated permission/exposure changes (corr) |\n"
         "| **127030 / 127031** | 10 / 6 | App installed or authorized / removed |\n"
         "| **127032 / 127033** | 10 / 5 | API token created / revoked |\n"
         "| **127040** | 5 | Page/blog/attachment/template deleted |\n"
         "| **127041** | 10 | Space deleted or archived |\n"
         "| **127042** | 10 | Mass content deletion (corr, ≥8 in 5 min) |\n"
         "| **127045 / 127046** | 6 / 5 | Group membership / user lifecycle |\n"
         "| **127050 / 127051 / 127052** | **11** / 7 / 5 | Audit log config changed / exported / viewed |\n"
         "| **127060 / 127061** | **12** / 9 | Site export or backup / space export |\n"
         "| **127062 / 127063** | 8 / 6 | Restore or import / content export/download |\n"
         "| **127064** | **12** | Bulk export by one actor (corr, ≥5 in 10 min) |\n"
         "| **127090 / 127091** | 6 / 5 | Category fallback tiers (security / admin) |\n\n"
         "**Notes:**\n"
         "- Correlation `frequency=\"N\"` fires on the (N+2)th event; `ignore` suppresses "
         "per-rule, not per-actor (anti-storm trade-off).\n"
         "- Correlations key on `conf_author_account_id`; the actor panels display "
         "`conf_author_name` for readability.\n"
         "- Source IP panels populate only when audit records carry an address (mostly "
         "login events).")

# ============================================================================
# DASHBOARD LAYOUT  (48-col grid; rows expand to absolute y coordinates)
# ============================================================================
rows = [
    (5,  [("conf-header", 0, 48)]),
    # Overview
    (2,  [("conf-md-overview", 0, 48)]),
    (8,  [("conf-total", 0, 8), ("conf-actors", 8, 8), ("conf-categories", 16, 8),
          ("conf-high", 24, 8), ("conf-corr", 32, 8), ("conf-external", 40, 8)]),
    (13, [("conf-timeline", 0, 32), ("conf-severity", 32, 16)]),
    (14, [("conf-category", 0, 24), ("conf-rules-bar", 24, 24)]),
    # Activity
    (2,  [("conf-md-activity", 0, 48)]),
    (15, [("conf-top-actions", 0, 24), ("conf-top-actors", 24, 24)]),
    (13, [("conf-actor-bar", 0, 24), ("conf-rules", 24, 24)]),
    (11, [("conf-objects", 0, 24), ("conf-sites", 24, 24)]),
    # Security
    (3,  [("conf-md-sec", 0, 48)]),
    (8,  [("conf-sec-admin", 0, 8), ("conf-sec-mfa", 8, 8), ("conf-sec-public", 16, 8),
          ("conf-sec-app", 24, 8), ("conf-sec-token", 32, 8), ("conf-sec-audit", 40, 8)]),
    (13, [("conf-sec-timeline", 0, 32), ("conf-sec-pie", 32, 16)]),
    (16, [("conf-sec-table", 0, 24), ("conf-mitre", 24, 24)]),
    # Authentication
    (3,  [("conf-md-auth", 0, 48)]),
    (12, [("conf-auth-timeline", 0, 24), ("conf-auth-bf-acct", 24, 12), ("conf-auth-bf-ip", 36, 12)]),
    (12, [("conf-auth-fail", 0, 24), ("conf-src-ip", 24, 24)]),
    # Permissions
    (3,  [("conf-md-perms", 0, 48)]),
    (13, [("conf-perm-timeline", 0, 24), ("conf-perm-actor", 24, 24)]),
    # Content deletion
    (3,  [("conf-md-content", 0, 48)]),
    (11, [("conf-del-space", 0, 12), ("conf-del-mass", 12, 12), ("conf-del-timeline", 24, 24)]),
    (12, [("conf-del-actor", 0, 48)]),
    # Export
    (3,  [("conf-md-export", 0, 48)]),
    (11, [("conf-export-site", 0, 12), ("conf-export-bulk", 12, 12), ("conf-export-timeline", 24, 24)]),
    (12, [("conf-export-actor", 0, 48)]),
    # Audit integrity
    (3,  [("conf-md-audit", 0, 48)]),
    (8,  [("conf-audit-cfg", 0, 16), ("conf-audit-export", 16, 16), ("conf-audit-view", 32, 16)]),
    (12, [("conf-audit-timeline", 0, 24), ("conf-audit-actor", 24, 24)]),
    # Users, groups & external
    (3,  [("conf-md-users", 0, 48)]),
    (12, [("conf-users-timeline", 0, 24), ("conf-users-table", 24, 24)]),
    (12, [("conf-external-table", 0, 48)]),
    # Fallback canary
    (3,  [("conf-md-fallback", 0, 48)]),
    (12, [("conf-fallback-timeline", 0, 24), ("conf-fallback-table", 24, 24)]),
    # Coverage
    (24, [("conf-coverage", 0, 48)]),
]

layout, y = [], 0
for height, row in rows:
    for vid, x, w in row:
        layout.append((vid, x, y, w, height))
    y += height

panels, references = [], []
for i, (vid, x, py, w, h) in enumerate(layout, start=1):
    pid = str(i)
    panels.append({"version": "2.19.5", "gridData": {"x": x, "y": py, "w": w, "h": h, "i": pid},
                   "panelIndex": pid, "embeddableConfig": {}, "panelRefName": f"panel_{i}"})
    references.append({"name": f"panel_{i}", "type": "visualization", "id": vid})

# dashboard-level scope filter: data.conf_integration:confluence
scope_filter = {
    "meta": {"alias": "confluence", "disabled": False, "negate": False, "type": "phrase",
             "key": f"{D}conf_integration", "params": {"query": "confluence"},
             "indexRefName": "kibanaSavedObjectMeta.searchSourceJSON.filter[0].meta.index"},
    "query": {"match_phrase": {f"{D}conf_integration": "confluence"}},
    "$state": {"store": "appState"}}
references.append({"name": "kibanaSavedObjectMeta.searchSourceJSON.filter[0].meta.index",
                   "type": "index-pattern", "id": IDX})

objects.append({
    "id": "confluence-audit-events-dashboard", "type": "dashboard",
    "attributes": {
        "title": "Confluence Audit Events",
        "hits": 0,
        "description": "Confluence audit-log monitoring (data.conf_integration:confluence): "
                       "volume, category and severity trends, top actors/summaries, security "
                       "detections (admin grants, MFA-disable, exposure, app installs, API "
                       "tokens), authentication and brute-force correlations, permission "
                       "changes, content deletion, export/backup collection, audit-log "
                       "integrity, users/groups and guest/external actors, fallback canary, "
                       "and a rule/coverage reference. Ruleset 127000-127099.",
        "panelsJSON": json.dumps(panels),
        "optionsJSON": json.dumps({"useMargins": True, "hidePanelTitles": False}),
        "version": 1, "timeRestore": True, "timeTo": "now", "timeFrom": "now-7d",
        "refreshInterval": {"pause": True, "value": 0},
        "kibanaSavedObjectMeta": {"searchSourceJSON": json.dumps(
            {"query": {"query": "", "language": "kuery"}, "filter": [scope_filter]})},
    },
    "references": references,
})

with open(OUT, "w") as f:
    for o in objects:
        f.write(json.dumps(o) + "\n")
nv = sum(1 for o in objects if o["type"] == "visualization")
print(f"Wrote {len(objects)} saved objects ({nv} visualizations + 1 dashboard), "
      f"{len(layout)} panels -> {OUT}")
