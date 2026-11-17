# Splunk Queries – SOC Incident Investigation

This document contains SPL searches for reproducing and validating the investigation documented in this repository.

**Environment:** Boss of the SOC (BOTS) v1  
**Index:** `botsv1`  
**Target server:** `192.168.250.70`  
**Suspicious domain:** `imreallynotbatman.com`

## Important Note

The searches below are investigation starting points based on the indicators and findings documented in this project. They are not necessarily the exact original searches used during the lab.

Field names can differ depending on the event source, sourcetype, and field extractions in Splunk. Verify field names before running searches.

## 1. Event Source Discovery

Count events by sourcetype:

```spl
index=botsv1
| stats count by sourcetype
| sort - count
```

Find events mentioning the suspicious domain:

```spl
index=botsv1 "imreallynotbatman.com"
| table _time sourcetype host source _raw
| sort _time
```

## 2. Reconnaissance – Domain Discovery

Search for suspicious domain activity:

```spl
index=botsv1 "imreallynotbatman.com"
| table _time sourcetype host _raw
| sort _time
```

Summarize source and destination IP addresses, after confirming the extracted field names:

```spl
index=botsv1 "imreallynotbatman.com"
| stats count by src_ip dest_ip
| sort - count
```

## 3. Source IP Analysis

Investigation IP addresses:

- `40.80.148.42`
- `23.22.63.114`

Search for both IP addresses:

```spl
index=botsv1 ("40.80.148.42" OR "23.22.63.114")
| table _time sourcetype host _raw
| sort _time
```

Summarize activity by source IP:

```spl
index=botsv1 ("40.80.148.42" OR "23.22.63.114")
| stats count by src_ip sourcetype
| sort - count
```

## 4. Suricata Alert Investigation

Search for Suricata alerts associated with the suspicious domain:

```spl
index=botsv1 "imreallynotbatman.com" "alert"
| table _time sourcetype signature category severity src_ip dest_ip _raw
| sort _time
```

Alert categories documented in this investigation:

- Cross-Site Scripting (XSS)
- SQL Injection
- XML External Entity (XXE)
- Invalid HTTP Host Header

Verify the actual extracted field names in Splunk.

## 5. Authentication and Brute-Force Analysis

Find POST requests related to the Joomla administrator login:

```spl
index=botsv1 "joomla" "POST"
| table _time sourcetype src_ip http_method uri_path status _raw
| sort _time
```

Count requests by source IP, after confirming the field names:

```spl
index=botsv1 http_method=POST uri_path="*/administrator/*"
| stats count by src_ip
| sort - count
```

Count authentication events and unique password values:

```spl
index=botsv1 http_method=POST uri_path="*/administrator/*"
| stats count AS authentication_events dc(password) AS unique_password_values by src_ip
| sort - authentication_events
```

Replace `password` and the filter fields with the actual extracted field names.

Documented findings:

- 413 authentication-related events.
- 412 unique password values.
- Two source IP addresses.

A high number of POST requests alone does not prove successful account compromise.

## 6. Suspicious File Upload Investigation

Search for the identified filenames:

```spl
index=botsv1 ("3791.exe" OR "agent.php")
| table _time sourcetype host src_ip dest_ip _raw
| sort _time
```

Investigate:

- Upload request.
- Destination path.
- HTTP response.
- Upload success message.

A filename appearing in a request does not by itself prove a successful upload.

## 7. Sysmon Process Creation Analysis

Search for the suspicious executable:

```spl
index=botsv1 "3791.exe"
| table _time sourcetype host EventCode Image ParentImage User ProcessGuid _raw
| sort _time
```

Narrow the search to Sysmon Event ID 1:

```spl
index=botsv1 EventCode=1 "3791.exe"
| table _time host Image ParentImage User CommandLine ProcessGuid
| sort _time
```

Documented process information:

- Executable: `3791.exe`
- Location: `C:\inetpub\wwwroot\joomla\3791.exe`
- Parent process: `cmd.exe`
- Execution context: `NT AUTHORITY\IUSR`

Validate these values against the actual Sysmon event.

## 8. Actions on Objectives – Suspicious Web Artifact

Search for the suspicious image filename and domain:

```spl
index=botsv1 ("poisonivy-is-coming-for-you-batman.jpeg" OR "prankglassinebracket.jumpingcrab.com")
| table _time sourcetype host src_ip dest_ip _raw
| sort _time
```

Investigate the HTTP request and response context.

The artifact may indicate attacker messaging or website defacement activity. Further evidence is required before confirming the full impact.

## 9. Investigation Checklist

- [ ] Confirm available sourcetypes.
- [ ] Verify extracted field names.
- [ ] Record the search time range.
- [ ] Validate suspicious source IP addresses.
- [ ] Confirm Suricata alert signatures.
- [ ] Reproduce authentication-event counts.
- [ ] Validate unique password counts.
- [ ] Confirm suspicious file uploads.
- [ ] Verify Sysmon process creation details.
- [ ] Preserve relevant screenshots.

## References

- [Splunk – Stats Command](https://help.splunk.com/en/splunk-enterprise/search/spl2-search-reference/stats-command/stats-command-overview-syntax-and-usage)
- [Splunk – Aggregate Functions](https://help.splunk.com/en/splunk-cloud-platform/search/spl2-search-reference/statistical-and-charting-functions/aggregate-functions)

---

**Project:** SOC Incident Investigation – Splunk  
**Dataset:** Boss of the SOC (BOTS) v1  
**Platform:** TryHackMe  
**Focus:** Blue Team | SOC Operations | SIEM Investigation
