# Playbook: Compromised User Account (Microsoft 365 / Entra ID)

**Triggers:** impossible-travel or risky sign-in alert · MFA fatigue alert · user entered credentials on a phish page · suspicious inbox rule · user reports "I didn't send that email"
**Goal:** cut off attacker access, find out what they did, restore the user safely

---

## 1. Confirm (10 min)

- [ ] Review the user's **sign-in logs** for the last 7–30 days: unfamiliar IPs, countries, devices, user agents, legacy-auth protocols
- [ ] Any successful sign-in after MFA prompts the user says they didn't expect?
- [ ] Ask the user (by phone or Teams, **not** email): did you travel, use a VPN, approve a prompt, enter your password anywhere?

## 2. Contain immediately (10 min)

Do these in order — if you revoke sessions while the attacker still knows the password, they can simply sign back in and get fresh tokens.

- [ ] **Block sign-in** for the account (Entra admin center → user → Block sign-in)
- [ ] **Reset the password** to a strong random value
- [ ] **Revoke all sessions / refresh tokens** (`Revoke-MgUserSignInSession`)
- [ ] **Review MFA methods** — remove any phone number or authenticator the user doesn't recognize (attackers often register their own)
- [ ] Disable or remove any **app passwords / OAuth consents** granted recently

## 3. Investigate what the attacker did

**Mailbox**
- [ ] Inbox rules: forwarding, redirect, delete, move-to-RSS (classic BEC hiding trick)
- [ ] Mailbox-level forwarding (`ForwardingSmtpAddress`)
- [ ] Sent Items / unified audit log `Send` events — phishing sent *from* this account to contacts?
- [ ] `MailItemsAccessed` — what did they read?

**Files & apps**
- [ ] OneDrive/SharePoint: mass downloads, new sharing links to external users
- [ ] New app registrations or consented enterprise apps

**Privilege**
- [ ] Was the user an admin, or were they added to any role/group during the window?

## 4. Eradicate & recover

- [ ] Remove malicious rules, forwarding, sharing links, rogue MFA methods, and app consents
- [ ] If phishing went out from the account: notify recipients, purge the messages internally
- [ ] Re-enable sign-in; walk the user through re-registering MFA (prefer number matching / phishing-resistant methods)
- [ ] Watch the account closely for 7 days (watchlist / alert rule)

## 5. Close out

- [ ] Timeline: first malicious sign-in → detection → containment (measure dwell time)
- [ ] IOCs: attacker IPs, user agents, domains (defanged)
- [ ] Root cause: phish? reused password? MFA fatigue? legacy auth?
- [ ] Prevent: Conditional Access (block legacy auth, require compliant device / phishing-resistant MFA for admins), user training

---

**ATT&CK:** T1078.004 Cloud Accounts · T1621 MFA Request Generation · T1114.003 Email Forwarding Rule · T1098.005 Device Registration
**Related detections:** [`impossible_travel_signins.kql`](../detections/kql/impossible_travel_signins.kql), [`mfa_fatigue.kql`](../detections/kql/mfa_fatigue.kql), [`inbox_rule_forwarding.kql`](../detections/kql/inbox_rule_forwarding.kql)
