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


## -- diff_cf ---
for diff running config
flags:
1. -f force, ignore hostname check
2. -m match, auto select all files to check, no prompt



## -- py_ssh --
use parameters example
python py_ssh.py --devices dmss.json --device-group dc --commands-file cmd_dc.txt --append pre-status
python py_ssh.py --devices dmss.json --device-group 3850 --commands-file cmd_3850.txt --append pre-status
python py_ssh.py --devices dmss.json --device-group voip --commands-file cmd_voip.txt --append pre-status
python py_ssh.py --devices dmss.json --device-group router --commands-file cmd_router.txt --append pre-status
python py_ssh.py --devices dmss.json --device-group campus --commands-file cmd_campus.txt --append pre-status
python py_ssh.py --devices dmss.json --device-group router 3850 voip --commands-file cmd_archive.txt --append pre-status
python py_ssh.py --devices dmss.json --device-group critical --commands-file cmd_critical.txt --append post-status -d
python py_ssh.py --devices devices.json --device-group sa21 --commands-file cmd_eigrp.txt --keyring-service none --default-username derwc@state.gov --append pre-status


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


### AIR GAPPED 

# build wheelhouse for air gap (Python 3.13) at internet Windows system
py -m pip download -r .\requirements.txt -d .\wheelhouse\ --only-binary=:all: --platform win_amd64 --implementation cp --python-version 3.13 --abi cp313


# Make & activate a clean venv in the air gap Windows system
py -m venv env
.\env\Scripts\Activate.ps1


# Install everything from your local wheelhouse in the air gapped Windows system
py -m pip install --no-index --find-links=wheelhouse -r requirements.txt
