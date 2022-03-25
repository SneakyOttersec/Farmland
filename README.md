# Farmland
```
  ______                   _                 _   __   ___
 |  ____|                 | |               | | /_ | / _ \
 | |__ __ _ _ __ _ __ ___ | | __ _ _ __   __| |  | || | | |
 |  __/ _` | '__| '_ ` _ \| |/ _` | '_ \ / _` |  | || | | |
 | | | (_| | |  | | | | | | | (_| | | | | (_| |  | || |_| |
 |_|  \__,_|_|  |_| |_| |_|_|\__,_|_| |_|\__,_|  |_(_)___/



usage: main.py [-h] --domain DOMAIN [--wordlist WORDLIST] [--output-dir OUTPUTDIR] [--massdns] [--crt] [--nmap] [--masscan] [--intrigue INTRIGUE]
               [--nrich] [--eyewitness] [--from-save FROM_SAVE] [--massdns-rate MASSDNS_RATE] [--nmap-ports NMAP_PORTS] [--eyewitness-full]

Farmland is a tool to automate the domain discovery

optional arguments:
  -h, --help            show this help message and exit

General arguments:
  --domain DOMAIN, -d DOMAIN
                        Seed domain
  --wordlist WORDLIST, -w WORDLIST
                        Wordlist used to brute force
  --output-dir OUTPUTDIR, -o OUTPUTDIR
                        Root ouput dir
  --massdns, -s         Subdomain brute force using massdns
  --crt, -c             Find subdomains using crt.sh
  --nmap, -n            Enable scan using nmap
  --masscan, -m         Enable scan using masscan
  --intrigue INTRIGUE, -i INTRIGUE
                        Find what technologies are being used
  --nrich, -r           Quick check on InternetDB regarding CVE
  --eyewitness, -e      Screenshot of everywebsite that we have found
  --from-save FROM_SAVE
                        Resume the scan from a previously generated .json file

Massdns Options:
  --massdns-rate MASSDNS_RATE
                        Rate in pps for massdns

Nmap Options:
  --nmap-ports NMAP_PORTS
                        Port range using nmap syntax

Massdns Options:
  --eyewitness-full, -ef
                        Screenshot on every domains/ports that we gatehered (time consuming)
```
