# genEye

I got really tired of formatting masscan results for EyeWitness so I made a little tool to do that. 
It also will take in CIDR notation if you want to skip port scanning. This defaults to standard ports for each service EyeWitness supports. 

`--outfile` is optional and will output to the screen by default
`--masscan` is the file with masscan output. See `tests/` for examples.

```
usage: genEye.py [-h] [--masscan LOAD_FILE] [--outfile OUT_FILE]
                 [--http [HTTP]] [--https [HTTPS]] [--rdp [RDP]] [--vnc [VNC]]
                 [ip [ip ...]]

Process a list or range of IPs to match EyeWitness's format

positional arguments:
  ip                   IPs to parse

optional arguments:
  -h, --help           show this help message and exit
  --masscan LOAD_FILE  Load list of IPs from a file
  --outfile OUT_FILE   Output results to file
  --http [HTTP]        Used with ip, prepends http and postpends port 80
  --https [HTTPS]      Used with ip, prepends https and postpends port 443
  --rdp [RDP]          Used with ip, prepends rdp and postpends port 3389
  --vnc [VNC]          Used with ip, prepends vnc and postpends port 5001

Examples:
python3 genEye.py 192.168.1.0/24 192.168.2.0/24 --https --http
python3 genEye.py --masscan tests/test.masscan.txt --outfile out.txt

```
