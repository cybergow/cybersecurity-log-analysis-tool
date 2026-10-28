# Task 6 — Manual Authentication Log Investigation Report

- **Analyst Name:** Gowtham (Security Operations Analyst)
- **Assessment Module:** Cybersecurity Assessment — Task 6 (Security-Log Analysis)
- **Dataset Analyzed:** `data/auth_logs.csv` (18 synthetic authentication events)
- **Date of Analysis:** 2026-10-28

---

## 1. Executive Summary & Analytical Posture

For Task 6, `data/auth_logs.csv` was manually reviewed to identify suspicious authentication patterns, separate directly observable **facts** from **hypotheses**, and specify the corroborating evidence required before reaching a **conclusion** or declaring a security incident.

A small authentication log establishes what was recorded by the authentication service at specific timestamps, but does not by itself establish actor intent, credential compromise, or who controlled a source IP address.

---

## 2. Answers to the Four Investigation Questions

### Question 1: Are there repeated failed logins from one IP?
- **Fact (Directly visible in logs):** Yes. Source IP `192.0.2.20` recorded **5 consecutive login failures** for username `maya` within a 54-second window between `2026-10-27T09:02:11` and `2026-10-27T09:03:05`. Additionally, `198.51.100.45` recorded 3 failed logins across distinct usernames, and `203.0.113.12` recorded 2 failed logins for `liam` (below the 5-failure threshold).
- **Hypothesis (Possible interpretation):** The burst from `192.0.2.20` could represent manual password entry mistakes, a misconfigured saved credential client, or automated/manual password guessing against `maya`.
- **Follow-up / Corroboration Required:** Check account status for `maya`, inspect MFA challenge logs, verify ownership/geolocation of `192.0.2.20`, and confirm whether authentication rate limiting or account lockout controls are active.

### Question 2: Does a successful login follow repeated failures for the same account and IP?
- **Fact (Directly visible in logs):** Yes. At `2026-10-27T09:03:42`, username `maya` recorded a `login,success` event from `192.0.2.20` immediately following the 5 consecutive failures from that same IP (`09:02:11`–`09:03:05`). By contrast, `liam` at `203.0.113.12` had only 2 failures (`11:20:10`, `11:20:28`) before a success at `11:21:02`.
- **Hypothesis (Possible interpretation):** Either `maya` legitimately recalled or reset their password after mistyping it five times, or an unauthorized party successfully guessed the password on the sixth attempt.
- **Follow-up / Corroboration Required:** Contact `maya` out-of-band to verify whether the `09:03:42` login was legitimate; inspect MFA completion telemetry, session creation IDs, User-Agent/device identifiers, and post-login activity.

### Question 3: Does one IP attempt logins for several usernames?
- **Fact (Directly visible in logs):** Yes. Source IP `198.51.100.45` attempted logins against **4 distinct usernames** inside a 99-second window:
  - `2026-10-27T10:14:05` — `alex` (`failure`)
  - `2026-10-27T10:14:32` — `devon` (`failure`)
  - `2026-10-27T10:15:09` — `priya` (`failure`)
  - `2026-10-27T10:15:44` — `sam` (`success`)
- **Hypothesis (Possible interpretation):** This pattern could indicate horizontal account enumeration / password spraying across multiple user accounts, or it could be normal traffic originating from a shared corporate NAT gateway, campus proxy, or VPN concentrator.
- **Follow-up / Corroboration Required:** Check network asset inventory to determine whether `198.51.100.45` is an approved corporate egress, VPN, or NAT address; verify `sam`'s successful session at `10:15:44` and check device fingerprints across the four attempts.

### Question 4: Are successful logins outside the assumed normal-hours window (06:00–22:00)?
- **Fact (Directly visible in logs):** Yes. At `2026-10-27T23:48:19`, username `jordan` recorded a `login,success` event from source IP `203.0.113.88`, which falls outside the assumed `06:00–22:00` business-hours window. Earlier in the day (`16:49:12`), `jordan` logged in from `192.0.2.18`.
- **Hypothesis (Possible interpretation):** The `23:48:19` login from a different IP (`203.0.113.88`) may be legitimate late-night remote work, travel across time zones, an approved maintenance window, or unauthorized off-hours access.
- **Follow-up / Corroboration Required:** Compare `23:48:19` against `jordan`'s shift schedule, on-call rotation, and approved remote access logs; confirm whether `203.0.113.88` matches `jordan`'s home ISP or travel location.

---

## 3. Evidence, Interpretation, and Follow-Up Matrix

| Evidence Observed in `data/auth_logs.csv` | Specific Log Rows & Entities | Possible Interpretation (Hypothesis) | Recommended Follow-Up Action |
| :--- | :--- | :--- | :--- |
| **Repeated failures from one IP** | `192.0.2.20` (`maya`, 5 failures from `09:02:11` to `09:03:05`) | Password mistakes, cached credential failure, or password guessing activity. | Check account status, MFA logs, source IP ownership, and rate limiting. |
| **Success after repeated failures** | `192.0.2.20` (`maya`, `login,success` at `09:03:42` after 5 failures) | Could be legitimate password recovery/recall or successful password guessing. | Verify directly with user `maya`; review session creation and device records. |
| **One IP touches several usernames** | `198.51.100.45` (`alex`, `devon`, `priya` failures; `sam` success `10:14:05`–`10:15:44`) | Could be username enumeration / password spraying or a shared VPN/NAT source. | Confirm network ownership of `198.51.100.45` and verify `sam`'s session. |
| **Successful login at an unusual hour** | `203.0.113.88` (`jordan`, `login,success` at `23:48:19`, outside `06:00–22:00`) | May be unusual off-hours access for that account or legitimate remote work. | Compare with `jordan`'s work schedule and approved remote access records. |

---

## 4. Recommended Investigation Actions

1. **Validate Network Context:** Check whether `192.0.2.20`, `198.51.100.45`, and `203.0.113.88` belong to an approved VPN concentrator, corporate NAT gateway, campus network, or known employee ISP.
2. **Correlate Identity & Endpoint Telemetry:** Review MFA challenge outcomes, session tokens, User-Agent strings, device identifiers, and endpoint detection (EDR) alerts around `09:03:42` (`maya`), `10:15:44` (`sam`), and `23:48:19` (`jordan`).
3. **Out-of-Band User Verification:** Ask account owners (`maya`, `sam`, `jordan`) via a trusted secondary channel to verify whether the successful logins were initiated by them.
4. **Evidence Preservation:** Preserve the raw authentication logs (`data/auth_logs.csv`) and document triage timestamps and rationale in the ticketing system.
5. **Defensive Hardening:** Recommend progressive rate limiting, MFA enforcement on all external logins, and anomaly detection tuned to organizational baselines where justified.
