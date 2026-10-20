# Playbook: Reported Phishing Email

**Trigger:** user reports a suspicious email (Report button, help desk ticket, or email to the security mailbox)
**Goal:** decide *malicious / suspicious / benign* fast, contain if needed, and protect everyone else who received it
**Target time:** triage verdict ≤ 30 min · containment ≤ 60 min for confirmed malicious

---

## 1. Intake (5 min)

- [ ] Acknowledge the reporter and tell them **not** to click, reply, or forward the message.
- [ ] Get the original as an attachment (`.eml`/`.msg`) — a forwarded copy loses headers.
- [ ] Open a ticket: reporter, time received, subject, sender, whether they clicked/opened/entered credentials.

> If the user says they **entered their password** or **ran an attachment**, jump straight to [Compromised Account](compromised-account.md) or [Malware on Endpoint](malware-endpoint.md) in parallel.

## 2. Analyze the message (15 min)

**Headers**
- [ ] `Return-Path` / `From` / `Reply-To` mismatch?
- [ ] SPF, DKIM, DMARC results in `Authentication-Results` — `fail` or `none` on a domain that should pass is a strong signal
- [ ] First external `Received:` hop — IP reputation (AbuseIPDB, VirusTotal), geography, hosting provider
- [ ] Look-alike domains (`rnicrosoft.com`, `contoso-billing.co`), newly registered domains (WHOIS age < 30 days)

**Content**
- [ ] Urgency / authority / fear cues: "account suspended", "CEO needs gift cards", "invoice overdue"
- [ ] Links: hover/expand, defang (`hxxps://evil[.]com`), check in a sandbox (urlscan.io) — **never** in a production browser
- [ ] Attachments: hash (SHA-256) and look up; detonate only in a sandbox. Watch for macros, HTML smuggling, `.iso`, `.lnk`, password-protected zips

**Verdict**

| Verdict | Criteria | Next |
|---|---|---|
| Malicious | Known-bad IOC, credential-harvest page, malware, or clear BEC | Step 3 |
| Suspicious | Indicators but no confirmation | Step 3 (block), keep investigating |
| Benign / Spam | Legitimate or marketing | Close, thank reporter |

## 3. Scope & contain (15 min)

- [ ] **Find every recipient** — Microsoft 365 Message Trace or Defender Threat Explorer by sender, subject, and URL/attachment hash
- [ ] **Purge** the message from all mailboxes (Threat Explorer → Soft delete, or `New-ComplianceSearchAction -Purge`)
- [ ] **Block** sender/domain, URLs and attachment hashes (Tenant Allow/Block List)
- [ ] Check proxy/DNS/firewall logs: who **clicked** the URL? Each clicker → follow-up
- [ ] Check sign-in logs for anyone who may have entered credentials on the phish page

## 4. Recover & communicate

- [ ] Reset passwords + revoke sessions for any user who submitted credentials
- [ ] Send a short heads-up to staff if the campaign was widespread (include a screenshot, not the link)
- [ ] Thank the reporter — reporting is the behavior we want more of

## 5. Close out

- [ ] Ticket notes: timeline, IOCs (defanged), affected users, actions taken
- [ ] Add IOCs to the blocklist / threat intel
- [ ] Lessons learned: did filtering miss it? tune rules, add awareness-training example

---

**ATT&CK:** T1566.001 Spearphishing Attachment · T1566.002 Spearphishing Link · T1534 Internal Spearphishing
**Related detections:** [`office_spawning_shell.yml`](../detections/sigma/office_spawning_shell.yml), [`inbox_rule_forwarding.kql`](../detections/kql/inbox_rule_forwarding.kql)
