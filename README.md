## -- new env ---
1. build a env in the code dir
   python3 -m venv env (note: evn*/ dir is not tracked in git)
   source env/bin/activate

2. install needed package - example
   pip install pandas openpyxl

3. if using vscode
   open the Command Palette 
   search Python: select interpreter
   choose the env-diff-ip/

4. deactivate env
   deactivate


## -- keyring (Mac and Win) --
1. setup kerying secret in command line - set password
   python3 -c 'import keyring; keyring.set_password("service_name", "user_name", "password")'
   python3 -c 'import keyring; svc='svc_name'; user="xxx"; pwd="xxx"; keyring.set_password(svc, 'username', user); keyring.set_password(svc, 'password', pwd)''


## -- diff_sh ---
for diff show outputs
flags:
1. --arp arp table check, with options (None if default when not used)
   'ip'    - check against IP address (for static IP use case, with possible MAC changes in VMs)
   'mac'   - check against MAC address (for dhcp endpoint use case, this is the default behavior)
   'ipmac' - check against both IP/MAC, both must be the same to be matched
2. --route-no-next-hop - for ip route checks, compare only the route code(s)/prefix and ignore next-hop changes, e.g. B 10.1.1.1/32 or O IA 10.1.1.1/32
3. --no-nat-port - for ip nat translations checks, ignore ports in the inside global, inside local, outside local, and outside global columns
4. --in DIR - read pre-status and post-status files from outputs/DIR. By default, input is read from the --out folder
5. --out DIR - write diff files under outputs/DIR/DIFF

Example: `python diff_sh.py --no-nat-port`

Read status files from one folder and write differences to another:

```bash
python diff_sh.py --in collected-status --out comparison-results
```


## -- diff_cf ---
for diff running config
flags:
1. -f force, ignore hostname check
2. -m match, auto select all files to check, no prompt



## -- py_ssh --
use parameters example
python py_ssh.py --devices dmss.json --device-groups dc --commands-file cmd_dc.txt --append pre-status
python py_ssh.py --devices dmss.json --device-groups 3850 --commands-file cmd_3850.txt --append pre-status
python py_ssh.py --devices dmss.json --device-groups voip --commands-file cmd_voip.txt --append pre-status
python py_ssh.py --devices dmss.json --device-groups router --commands-file cmd_router.txt --append pre-status
python py_ssh.py --devices dmss.json --device-groups campus --commands-file cmd_campus.txt --append pre-status
python py_ssh.py --devices dmss.json --device-groups router 3850 voip --commands-file cmd_archive.txt --append pre-status
python py_ssh.py --devices dmss.json --device-groups critical --commands-file cmd_critical.txt --out critical --per-cmd-timeout 60 --append post-status -d
python py_ssh.py --devices devices.json --device-groups sa21 --commands-file cmd_eigrp.txt --keyring-service none --default-username derwc@state.gov --append pre-status

Command-file block ID format:

- `command; id` writes `################################################ id (command)`
- `command` writes `################################################ (command)`

Each command waits for the device prompt before the next command is sent. If a
response is delayed by packet loss, it remains in its original command block
instead of being collected under the following block. Use
`--per-cmd-timeout SECONDS` to allow more time for slow or lossy connections.

Use `--out FOLDERNAME` to save results in `outputs/FOLDERNAME`. The folder is
created automatically if it does not exist. `--output-dir` is the equivalent
long-form option.

```bash
python py_ssh.py --devices dmss.json --device-groups critical --commands-file cmd_critical.txt --out critical-results
```

### Diff after collection

Use `-d` (or `--diff`) to run `diff_sh.py` automatically after the SSH command
collection finishes and the output files are saved. This is useful on a
post-status run to compare the newly collected output with the pre-status output.

Example:

```bash
python py_ssh.py --devices dmss.json --device-groups critical --commands-file cmd_critical.txt --append post-status -d
```

For NAT comparisons that should ignore ports, add `--no-nat-port` with `-d`:

```bash
python py_ssh.py --devices dmss.json --device-groups critical --commands-file cmd_critical.txt --append post-status -d --no-nat-port
```


## Current supported DIFF key words -
"ip arp" 
"mac address-table"
"cisco interface status - sh ip int bri"
"arista interface status - sh int status"
"interface description"
"access-session"
"bgp summary"
"lisp status"
"portchannel"      
"isdn status"
"bridge-domain"
"sip tls"
"ospf database"
"ip route"
"ip nat translations"


### AIR GAPPED 

# build wheelhouse for air gap (Python 3.13) at internet Windows system
py -m pip download -r .\requirements.txt -d .\wheelhouse\ --only-binary=:all: --platform win_amd64 --implementation cp --python-version 3.13 --abi cp313


# Make & activate a clean venv in the air gap Windows system
py -m venv env
.\env\Scripts\Activate.ps1


# Install everything from your local wheelhouse in the air gapped Windows system
py -m pip install --no-index --find-links=wheelhouse -r requirements.txt
