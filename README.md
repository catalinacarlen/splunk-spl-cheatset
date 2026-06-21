# Splunk SPL Cheatsheet

A practical, no-fluff reference for **Splunk Search Processing Language (SPL)** — the query language used to search, correlate and visualize machine data in a SIEM. Built as a study aid and quick reference for security analysis and threat hunting.

> Una referencia práctica de **SPL (Splunk Search Processing Language)**, el lenguaje de consulta de Splunk para buscar, correlacionar y visualizar logs en un SIEM. Pensada como ayuda de estudio y referencia rápida para análisis de seguridad y threat hunting.

---

## 1. Anatomy of a search

A search reads left to right; data flows through a **pipeline** of commands separated by `|`.

```
index=web sourcetype=access_combined status=500   ← search terms (filter early!)
| stats count by clientip                          ← transform
| sort -count                                      ← order
| head 10                                          ← limit
```

**Golden rule:** filter as much as possible *before* the first pipe. The more events you discard early (by `index`, `sourcetype`, time range), the faster and cheaper the search.

---

## 2. Time

| Task | SPL |
|------|-----|
| Last 15 min / 24 h / 7 d | use the time picker, or `earliest=-15m` / `-24h` / `-7d` |
| Relative range | `earliest=-7d@d latest=now` |
| Snap to start of day | `@d` (also `@h`, `@w`, `@mon`) |
| Absolute | `earliest="10/01/2024:00:00:00"` |
| Bucket events into time bins | `bin _time span=1h` |

---

## 3. Filtering & search terms

| Goal | SPL |
|------|-----|
| Field equals | `status=404` |
| Wildcard | `uri_path="/admin*"` |
| Boolean | `status=500 OR status=503`, `NOT status=200` |
| Comparison | `bytes>10000`, `duration<=2` |
| Field exists | `field=*` |
| In a set | `status IN (500, 502, 503)` |
| Free-text | `"failed password"` |

> Tip: field names are **case-sensitive**, values are **not** (unless you use `case()` / `CASE()`).

---

## 4. Core commands

| Command | What it does | Example |
|---------|--------------|---------|
| `fields` | Keep/remove fields (speeds searches) | `\| fields clientip, status` |
| `table` | Show results as a table | `\| table _time, user, action` |
| `rename` | Rename a field | `\| rename clientip AS src_ip` |
| `dedup` | Remove duplicate events | `\| dedup user` |
| `sort` | Order results | `\| sort -count` (desc) |
| `head` / `tail` | First / last N | `\| head 20` |
| `where` | Filter with expressions | `\| where count > 100` |
| `eval` | Create/modify fields | `\| eval mb=bytes/1024/1024` |
| `search` | Filter mid-pipeline | `\| search status=500` |

---

## 5. Statistics & aggregation

| Command | Use | Example |
|---------|-----|---------|
| `stats` | Aggregate across all events | `\| stats count, avg(bytes) by host` |
| `tstats` | Fast stats over indexed/accelerated data | `\| tstats count where index=* by sourcetype` |
| `chart` | Aggregate into a table for charting | `\| chart count over status by host` |
| `timechart` | Aggregate over time | `\| timechart span=1h count by status` |
| `top` | Most common values (+ %) | `\| top limit=10 src_ip` |
| `rare` | Least common values | `\| rare user` |
| `eventstats` | Add aggregate as a field to each event | `\| eventstats avg(bytes) as avg_b` |
| `streamstats` | Running/cumulative stats | `\| streamstats count by user` |

**Common `stats` functions:** `count`, `dc` (distinct count), `sum`, `avg`, `min`, `max`, `values`, `list`, `latest`, `earliest`, `range`, `stdev`, `perc95`.

```spl
index=auth action=failure
| stats count AS failures, dc(user) AS users_tried by src_ip
| where failures > 20
| sort -failures
```

---

## 6. eval — the swiss-army knife

```spl
| eval status_class = case(
    status>=500, "server_error",
    status>=400, "client_error",
    status>=200, "ok",
    true(), "other")
```

| Function | Example |
|----------|---------|
| `if(cond, a, b)` | `eval flag=if(bytes>1e6,"big","small")` |
| `case(...)` | multi-branch (see above) |
| `coalesce(a,b)` | first non-null |
| `round(x, n)` | `eval mb=round(bytes/1048576, 2)` |
| `len(x)` | string length |
| `lower()/upper()` | case change |
| `strftime/strptime` | epoch ↔ text time |
| `mvcount()/mvindex()` | multivalue fields |

---

## 7. CIM — standard field names

Splunk's **Common Information Model (CIM)** normalizes field names across sources so a search works the same whether the data comes from a firewall, a proxy or an EDR. Use these names instead of arbitrary ones (`src` not `ip_origen`, `user` not `usuario`) to keep searches portable across real environments.

> El **CIM** normaliza los nombres de campos entre distintas fuentes. Usar la nomenclatura estándar (`src`, `user`, `action`…) en vez de nombres propios hace que tus búsquedas sean portables a entornos reales.

| CIM field | Meaning | Common in |
|-----------|---------|-----------|
| `src` / `src_ip` | Source host / IP | Network, Authentication |
| `dest` / `dest_ip` | Destination host / IP | Network, Web |
| `src_port` / `dest_port` | Source / destination port | Network |
| `user` | Account involved | Authentication, Endpoint |
| `action` | Outcome (`success`, `failure`, `allowed`, `blocked`) | Most models |
| `app` | Application / service | Web, Network |
| `bytes_in` / `bytes_out` | Bytes received / sent | Network |
| `signature` | Rule / alert name | IDS, Malware |
| `dvc` | Device that reported the event | Most models |
| `vendor_product` | Source product (e.g. `Cisco ASA`) | All |

> Tip: align to CIM and your queries plug straight into Splunk Enterprise Security and accelerated data models.

---

## 8. Correlation & lookups

| Command | Use |
|---------|-----|
| `lookup` | Enrich events from a CSV/KV store (e.g. map IP → asset owner) |
| `inputlookup` | Read a lookup table as events |
| `join` | SQL-style join of two searches (use sparingly — costly) |
| `append` / `appendcols` | Combine result sets |
| `transaction` | Group related events into one (by session, user, etc.) |

```spl
index=firewall
| lookup threat_intel ip AS src_ip OUTPUT category, score
| where score > 80
```

---

## 9. Security / threat-hunting patterns

**Hunting vs Alerting** — know which one you're writing. A *hunt* is exploratory: high-cardinality, wide time range, run on demand, you read the results yourself. An *alert* is production: tightly filtered, narrow window, runs on a schedule against the Search Head, and must be cheap because it fires over and over. Don't put an expensive hunt on a 5-minute cron — it will hammer the cluster.

> Diferenciá *hunting* (exploratorio, manual, ventana amplia) de *alerting* (programado, filtrado estricto, ventana corta). Una búsqueda de hunting cara corriendo cada 5 minutos como alerta satura el Search Head en producción.

Each pattern is tagged with its **MITRE ATT&CK** tactic and technique so the search maps directly to a detection use case.

> Cada patrón está mapeado a su táctica y técnica de **MITRE ATT&CK**, para que cada búsqueda se traduzca a un caso de detección concreto (útil en un SOC / respuesta a incidentes).

**Brute force — many failures, one source**
`Credential Access` · [T1110 — Brute Force](https://attack.mitre.org/techniques/T1110/)
```spl
index=auth action=failure
| bin _time span=5m
| stats count AS failures, dc(user) AS users_tried by _time, src_ip
| where failures > 10
```

**Password spraying — one source, many accounts, few attempts each**
`Credential Access` · [T1110.003 — Password Spraying](https://attack.mitre.org/techniques/T1110/003/)
```spl
index=auth action=failure
| bin _time span=10m
| stats dc(user) AS users_targeted, count AS attempts by _time, src_ip
| where users_targeted > 15 AND attempts < 50
```

**Possible data exfiltration — large outbound transfer**
`Exfiltration` · [T1048 — Exfiltration Over Alternative Protocol](https://attack.mitre.org/techniques/T1048/)
```spl
index=firewall direction=outbound
| stats sum(bytes_out) AS total by src_ip, dest_ip
| where total > 1000000000
| sort -total
```

**Rare process per host — living-off-the-land / anomaly**
`Execution` · [T1059 — Command and Scripting Interpreter](https://attack.mitre.org/techniques/T1059/)
```spl
index=endpoint sourcetype=process
| rare limit=20 process by host
```

**First-time-seen — new user/source pair (possible valid-account abuse)**
`Initial Access / Persistence` · [T1078 — Valid Accounts](https://attack.mitre.org/techniques/T1078/)
```spl
index=auth
| stats earliest(_time) AS first_seen by user, src_ip
| where first_seen > relative_time(now(), "-24h")
```

**Impossible travel — same user, two far-apart sources fast**
`Credential Access` · [T1078 — Valid Accounts](https://attack.mitre.org/techniques/T1078/)
```spl
index=auth action=success
| stats dc(src_ip) AS distinct_ips, values(src_ip) AS ips by user
| where distinct_ips > 1
```

---

## 10. Output & visualization

| Command | Use |
|---------|-----|
| `timechart` | time-series charts |
| `chart` | bar/column/pie by field |
| `stats` + table | tabular dashboards |
| `eval` + `gauge` | single-value KPIs |
| `outputcsv` / `outputlookup` | save results |

---

## 11. Performance tips

- Always specify `index=` and `sourcetype=` — never search `index=*` in production.
- Filter **before** the first `|`; transform after.
- Use `fields` early to drop unused fields.
- Prefer `tstats` over `stats` on large/accelerated datasets.
- Avoid `join` and `transaction` when `stats by` can do the job.
- Narrow the time range — it's the single biggest performance lever.

**Search modes** — pick the cheapest that answers your question:

| Mode | What it does | When to use |
|------|--------------|-------------|
| **Fast** | Skips field discovery, returns only fields used in the search | Dashboards, scheduled alerts, large datasets |
| **Smart** | Default — switches behavior based on the search type | General day-to-day searching |
| **Verbose** | Discovers and returns every field | Deep investigation / hunting, when you need full event context |

> Verbose es el más caro: úsalo para investigar, no para alertas. Fast mode es el que querés en dashboards y búsquedas programadas.

---

Made by [Catalina Carlen](https://github.com/catalinacarlen) · Cybersecurity — Universidad de Palermo
