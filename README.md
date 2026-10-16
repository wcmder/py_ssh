# Network configuration and command-output tools

Collect network device configurations and command output over SSH, then compare saved files to review changes.

| Script | What it does |
| --- | --- |
| `py_ssh.py` | Connects to network devices over SSH using Netmiko, runs commands such as configuration or status commands, and saves the output per device. Supports device groups, command files, and custom output folders. |
| `diff_sh.py` | Compares saved before/after show-command output using command-specific checks for interfaces, ARP, MAC tables, routing, BGP, NAT, and more. Writes per-device reports with `!   BEFORE` and `!   AFTER` sections; a missing command block is reported as `no such output`. |
| `diff_cf.py` | Compares saved running configurations and reports differences in both directions, ignoring blank lines, `!` comments, and `Current configuration` lines. Supports automatic file matching and an option to skip hostname checks. |

A typical workflow is to collect a baseline with `py_ssh.py`, collect again after a change, and compare the saved results with `diff_sh.py` for command output or `diff_cf.py` for configurations. Use `py_ssh.py -d` to run the show-output comparison automatically after collection.

Before running `py_ssh.py`, rename `devices.json.example` to `devices.json`
and edit its device groups, hostnames, and IP addresses for your network:

```bash
mv devices.json.example devices.json
```

The examples below use `devices.json`. Replace the group and command-file names
with your own. For example, collect command output before and after a change:

```bash
python py_ssh.py --devices devices.json --device-groups routers --commands-file commands.txt --append pre-status
python py_ssh.py --devices devices.json --device-groups routers --commands-file commands.txt --append post-status -d
```

By default, `diff_sh.py` reads status files from `./outputs` and writes reports under `./outputs/DIFF`. Its options let you choose ARP matching behavior, ignore route next-hop or NAT port changes, and use separate input and output folders.

See the sections below for setup, script options, and more examples.

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

Rename the supplied `devices.json.example` to `devices.json` before use, then
edit it to define your device groups. Groups can be lists:

```json
{
    "router3": [
        {
            "hostname": "router3",
            "ip": "10.1.1.3"
        }
    ]
}
```

Select this group with `--device-groups router3`. Add `device_type` to an
individual device when needed; otherwise, the script uses `--device-type`,
or `cisco_ios` by default. The nested group format with a `devices` list and
group defaults is also supported.

### Supported command-line flags

| Flag | Description |
| --- | --- |
| `-h`, `--help` | Show command-line usage and available options. |
| `--devices TARGET [TARGET ...]` | Device IPs/hostnames or JSON/text device-list files. Defaults to `devices.json`, then `device.json`. |
| `--device-groups GROUP [GROUP ...]` | Select groups from a JSON device file. Defaults to the configured `TARGET` list (`nipr`). |
| `--device-type TYPE` | Fallback Netmiko platform, default `cisco_ios`. Device or group settings take precedence. |
| `--commands "COMMAND" ["COMMAND" ...]` | Commands to run. Quote each command containing spaces. Takes precedence over positional commands and the command file. |
| `--commands-file FILE` | Read commands from a text file, one per line; blank lines and lines beginning with `#` are ignored. Used when no commands are supplied directly. |
| `--out DIR`, `--output-dir DIR` | Save results under `./outputs/DIR`, creating the folder if needed. Default: `./outputs`. |
| `--append LABEL` | Name output files `<hostname>-<LABEL>.txt`, such as `pre-status` or `post-status`. Replaces an existing file with the same name; it does not append content. |
| `--prefix LABEL` | Prefix timestamped output filenames when `--append` is not used; also limits which filenames are archived with `-a`. |
| `-a` | Archive existing `.txt` output files before collection. |
| `--archive-dir DIR` | Archive destination for `-a`. Default: the output folder's `archives` subfolder. |
| `-l` | Repeat collection, waiting 60 seconds between runs. Stop with Ctrl+C. |
| `--max-workers N` | Maximum concurrent device workers. Default: `20`; minimum: `1`. |
| `--timeout SECONDS` | Connection timeout. Default: `20`; must be greater than zero. |
| `--per-cmd-timeout SECONDS` | Accepted by the parser, but currently not forwarded by the CLI to the command runner, so setting it has no effect. |
| `--initial-wait SECONDS` | Optional delay after connecting, before sending commands. |
| `--idle-quiet SECONDS` | Deprecated compatibility option; commands now wait for the device prompt. Has no effect. |
| `--default-username USER` | Fallback username when a device does not specify one. |
| `--keyring-service SERVICE` | Keyring service used for credentials. Default: `py_ssh`. |
| `-d`, `--diff` | Run `diff_sh.py` after collection to compare saved pre-status and post-status output. |
| `--no-nat-port` | With `-d`, ignore ports in all four NAT address columns during comparison. |

Commands can also be supplied as positional arguments. If neither direct
commands nor a command file is supplied, the script uses its built-in commands.

### Examples

```bash
python py_ssh.py --devices devices.json --device-groups dc --commands-file cmd_dc.txt --append pre-status
python py_ssh.py --devices devices.json --device-groups 3850 --commands-file cmd_3850.txt --append pre-status
python py_ssh.py --devices devices.json --device-groups voip --commands-file cmd_voip.txt --append pre-status
python py_ssh.py --devices devices.json --device-groups router --commands-file cmd_router.txt --append pre-status
python py_ssh.py --devices devices.json --device-groups campus --commands-file cmd_campus.txt --append pre-status
python py_ssh.py --devices devices.json --device-groups router 3850 voip --commands-file cmd_archive.txt --append pre-status
python py_ssh.py --devices devices.json --device-groups critical --commands-file cmd_critical.txt --out critical --per-cmd-timeout 60 --append post-status -d
python py_ssh.py --devices devices.json --device-groups sa21 --commands-file cmd_eigrp.txt --keyring-service none --default-username derwc@state.gov --append pre-status
```

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
python py_ssh.py --devices devices.json --device-groups critical --commands-file cmd_critical.txt --out critical-results
```

### Diff after collection

Use `-d` (or `--diff`) to run `diff_sh.py` automatically after the SSH command
collection finishes and the output files are saved. This is useful on a
post-status run to compare the newly collected output with the pre-status output.

Example:

```bash
python py_ssh.py --devices devices.json --device-groups critical --commands-file cmd_critical.txt --append post-status -d
```

For NAT comparisons that should ignore ports, add `--no-nat-port` with `-d`:

```bash
python py_ssh.py --devices devices.json --device-groups critical --commands-file cmd_critical.txt --append post-status -d --no-nat-port
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
