# VPN neighbor and ARP audit

`vpn_neighbor_audit.py` audits Cisco IOS XE SD-WAN routers targeting release
17.15.6. It uses the existing `py_ssh.py` inventory, credential, Netmiko, console,
raw command-block and output-folder conventions. It does not change router
configuration, clear ARP, enable discovery or send active probes.

Install the repository requirements in your environment:

```bash
python -m pip install -r requirements.txt
```

Run against an inventory group:

```bash
python vpn_neighbor_audit.py --devices devices.json --device-groups routers --out vpn-audit
```

The script prompts for VPN numbers and accepted domain names, then resolves missing
credentials through the existing keyring/getpass workflow before starting workers.
For unattended selection, supply `--vpn 20 --domain example.org`. Credentials must
already be available to avoid a password prompt. Passwords are never CLI arguments.
Service VPNs 1–65525 excluding 512 are accepted; transport and management VPNs are
outside this audit's scope.

## Rebuild a report from saved text files

Use `--from-files` instead of SSH to analyze saved router command output:

```bash
python vpn_neighbor_audit.py --from-files ./outputs/saved/router1.txt --vpn 20 --domain example.org --out offline-audit
python vpn_neighbor_audit.py --from-files ./outputs/saved --vpn 20 30 --domain example.org another.org --out offline-audit
python vpn_neighbor_audit.py --from-files "./outputs/saved/*.txt" --vpn 20 --domain example.org --out offline-audit
```

The flag accepts one or more `.txt` files, folders (nonrecursive), or quoted globs.
Files are deduplicated by resolved path. No inventory, keyring/password prompts,
SSH sessions or active commands are used. VPN/domain prompts still apply when
those flags are omitted. `--from-files` cannot be combined with `--devices` or
`--device-groups`; use `--vrf` mappings for named VRFs. `--threads` also controls
concurrent processing of saved files.

Supported sources are this audit's per-router raw files and `py_ssh.py` raw output
with `################################################ (command)` or
`################################################ label (command)` blocks. Unmarked
terminal text and Excel exports are not accepted. Each file represents one router
snapshot; different files are not merged, even if their router names agree.
Use a folder containing the intended snapshots rather than a mixture of raw,
diff and error files. Unrecognized files are reported in Collection while other
files continue.

The current parsers, domain rules and MAC thresholds are applied again. All
required evidence must be present in the saved file: missing commands are
explicitly marked `missing`, not successful empty results, and affected rows are
amber. If interface discovery is absent, unknown interfaces cannot be invented.
A listed fallback is used if the primary block is absent or explicitly unsupported;
there is no SSH fallback. Saved failed/disabled/unsupported results remain failures;
old parser errors with output are reparsed so updated parsers can recognize them.
Original command timestamps are retained when present; older files without them
leave command timestamps blank. If a command appears repeatedly, the last block
matching its VRF is used, with unscoped blocks as a fallback. Another VRF's scoped
block is never substituted.

The source `.txt` files are never overwritten, and offline mode writes no new raw
`.txt` copies. It creates a fresh workbook with a Source file column at the end of
each data sheet, without moving the established columns. Source identity/address
metadata is used when available. Historical audit filenames can supply an IPv4 SSH
address; otherwise an unavailable address stays blank. `show version` supplies
the router name when present. New live audit files include explicit router-name
and SSH-address metadata for reliable future replay.

The summary counts snapshots rather than unique routers in offline mode. Workbook
timestamps indicate report generation; saved output is not a fresh observation
of the network. Collection and the Readme identify offline inputs and limitations.

## VPN and domain selection

Select multiple VPNs and accepted domains using spaces or commas:

```bash
python vpn_neighbor_audit.py --devices devices.json --device-groups routers --vpn 20 30 --domain example.org another.org --threads 5 -out vpn-audit
python vpn_neighbor_audit.py --devices devices.json --device-groups routers --vpn 20,30 --domain example.org,another.org -out vpn-audit
```

`--vpns` and `--domains` are aliases, and flags can be repeated. Prompts also
accept spaces or commas. Duplicate VPNs/domains are removed after normalization.
A neighbor matches if its hostname has the exact dot-delimited suffix of **any**
accepted domain. Each root domain includes its subdomains. The accepted domains
apply to all selected VPNs; there is no positional domain-to-VPN pairing.

Each router uses one SSH session and one shared CDP/LLDP collection, with separate
ARP tables and counts for each VRF. Failure to find one VRF does not prevent the
other selected VRFs from being audited. Collection includes a summary per VRF;
shared device commands have a blank VRF, while VRF-specific commands record it.

Other shared options: `--default-username`, `--keyring-service` (default `py_ssh`),
`--device-type` (default `cisco_ios`), `--timeout` (20 seconds),
`--per-cmd-timeout` (30 seconds), `--max-workers`/`--threads` (10), `--out`/`--output-dir`,
`--prefix` (default `vpn-audit`) and `--append`. Output labels accept letters,
numbers, underscores and hyphens. Like `py_ssh.py`, `--append` means a stable
filename that is overwritten, not appended content. Raw filenames include both
inventory hostname and SSH address to distinguish identically named routers.

Use `--threads 5` to collect from up to five routers concurrently. Commands for
each router run sequentially in its own SSH session. Console progress shows
`[connect]`, then `[connected]` after SSH login and optional enable authentication
succeed, followed by `[done]` or an error.
Authentication/connection failures print one short console error. Full diagnostic
details remain in Collection and the router's raw text file. A failed login does
not print `[connected]` or `[done]`.
Paramiko background SSH errors (including `Invalid packet blocking` tracebacks)
go to a matching `*-ssh.log` file in the output directory instead of the console.
The log is created only when errors are logged. These are transport errors, not
normal missing-VRF responses. Missing or unverified VRFs receive a short console
message; detailed reasons remain in Collection and raw output.

VPN 20 normally selects a verified VRF named `20`. A named VRF requires an
explicit mapping, never a guess based on an RD or an interface number:

```bash
python vpn_neighbor_audit.py --devices devices.json --device-groups routers --vpn 20 --domain example.org --vrf LAN20
```

With multiple VPNs, use explicit mappings for named VRFs:

```bash
python vpn_neighbor_audit.py --device-groups routers --vpn 20 30 --domain example.org --vrf 20=LAN20 30=LAN30
```

Unmapped VPNs use inventory mappings or their numeric names. A bare `--vrf LAN20`
is accepted only when one VPN is selected. Conflicting mappings and multiple VPNs
resolving to the same VRF are reported instead of duplicating interface rows.

For different mappings per router, add `"vpn_vrf_map": {"20": "LAN20"}` to the
device or group defaults in your inventory. `--vrf` takes precedence. The VRF
must still be found on the router. Empty inventory selections fail before SSH.
The existing default inventory group is `nipr`; explicitly select your group.

## Command review and confirmation

Print the entire application command allowlist without SSH, credentials or prompts:

```bash
python vpn_neighbor_audit.py --list-commands
```

Every show command is listed below. `<VRF>` is the validated resolved VRF name;
`<INTERFACE>` is a validated router-discovered interface. There is no arbitrary
command-file execution in this audit.

| Purpose | Primary command | When / fallback |
| --- | --- | --- |
| Version and hostname | `show version` | Every router; accepts release formatting `17.15.06` |
| VRF inventory | `show vrf` | Every router; fallback `show ip vrf brief` |
| Interface membership | `show ip vrf interfaces` | Every router |
| VPN/VRF definitions | `show sdwan running-config \| section ^vrf definition` | Every router; fallback `show running-config \| section ^vrf definition` |
| Interface configuration | `show sdwan running-config \| section ^interface` | Every router; fallback `show running-config \| section ^interface` |
| ARP mapping | `show ip arp vrf <VRF>` | Selected VRF; fallback `show arp vrf <VRF>` |
| Local MAC/status | `show interfaces <INTERFACE>` | Each selected logical interface and unique physical parent |
| Local IP addresses | `show ip interface <INTERFACE>` | Each selected logical interface |
| CDP global status | `show cdp` | Every router, regardless of ARP count |
| CDP interface status | `show cdp interface` | Every router, regardless of ARP count |
| CDP neighbors | `show cdp neighbors detail` | Every router, regardless of ARP count |
| LLDP global status | `show lldp` | Every router, regardless of ARP count |
| LLDP interface status | `show lldp interface` | Every router, regardless of ARP count |
| LLDP neighbors | `show lldp neighbors detail` | Every router, regardless of ARP count |

Fallbacks run only when the primary is explicitly unsupported. Authorization
failures, unrecognized output and timeouts do not trigger an unrelated command.
The original unsupported result remains in Collection even if its fallback works.
There is no global-ARP fallback. Blank output cannot establish successful absence.
After a command exception, the session stops issuing commands to prevent late
output from being attributed to the next command. Earlier results are retained.

Netmiko's platform driver also performs prompt detection and terminal session
preparation, typically `terminal width 511` and `terminal length 0`. Optional enable
authentication follows the existing inventory settings. These session actions are
not show commands and do not alter persistent configuration. Their exact sequence
depends on the installed Netmiko version; the raw audit records application show
commands, not a full SSH transport transcript.

**Device verification remains required.** This repository has offline parser
fixtures, not live 17.15.6 certification. On a representative router for each
hardware type, run the manifest commands, check their complete output against
the raw audit files, and reconcile the workbook's interfaces, counts and neighbor
ports manually. Collection records exact expanded commands, UTC timestamps,
success with entries, success empty, disabled, unsupported, failed, parse error,
or missing (offline inputs).
An unsupported or unrecognized required command makes affected rows amber.

Reference command families: Cisco's
[SD-WAN interface guide](https://www.cisco.com/c/en/us/td/docs/routers/sdwan/17-x/systems-interfaces/systems-interfaces-guide-17-x.pdf),
[SD-WAN segmentation guide](https://www.cisco.com/c/en/us/td/docs/routers/sdwan/configuration/segmentation/ios-xe-17/segmentation-book-xe/segmentation.html),
[CDP reference](https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/cdp/command/cdp-cr-book/cdp-cr-a1.html),
and [IOS XE LLDP guide](https://www.cisco.com/c/en/us/td/docs/routers/ios/config/17-x/application-services/b-application-services/m_ce-lldp-multivend.html).
These document the command families; they do not certify every router model.

## Counting and classification

ARP is keyed by **VRF + logical interface**, retaining the IP-to-MAC association.
Counts are distinct complete IPv4 addresses and distinct normalized complete MACs.
Incomplete entries and verified router-owned IP/MAC entries are excluded. Local
IP exclusions are scoped to the selected VRF because addresses may overlap
between VPNs. A static remote entry with age `-` is retained. Duplicate ARP lines
do not inflate counts. Unknown counts are blank, never zero.

For example, four IPs sharing one MAC count as four IPs and one unique MAC.
Two MACs on `Gi0/0/1.20` cross the threshold on that interface; one MAC on
`Gi0/0/1.21` does not. One MAC on each interface is never combined into two.
Subinterfaces retain separate counts even when their physical parent is shared.

Neighbors are matched to the logical interface first, then its physical parent.
No physical parent is invented for SVIs, BDI,
loopbacks, tunnels or port channels. Every discovered selected interface is
exported, including down interfaces and those without ARP/neighbor entries.

| Color | Rule / classification |
| --- | --- |
| Green | Advertised hostname has our exact dot-delimited DNS suffix: Our domain |
| Red | Neighbor advertises a determinable different domain |
| Red | Neighbor has a hostname without a domain: Neighbor hostname without domain |
| Red | Successful no-neighbor collection and **more than 1 unique complete non-router MAC on the same logical interface**: Likely third-party switch |
| Neutral | Successful no-neighbor collection and 0–1 unique MACs: Unknown |
| Amber | Neighbor name missing/unusable or domain otherwise undetermined, or required collection incomplete |

For neutral Unknown rows, Observed finding reads `1 host found, likely not a switch`
when one non-router MAC is counted, or `0 hosts found, likely not a switch` when
none are counted. This is an ARP-based inference, not confirmation of host count
or absence of a switch. Failed collection does not receive this finding.

For `example.org`, `sw.example.org` and `sw.site.example.org` match;
`sw.badexample.org` and `sw.example.org.other.net` do not. Comparison is
case-insensitive and tolerates a trailing DNS dot. A short hostname without a
domain is red. Missing names, IPs, MAC IDs and the bare domain do not establish
a hostname domain and remain amber. Advertised neighbor names
may contain underscores (for example `btn01_sw01.example.com`); configured root
domains still require DNS domain syntax. Cisco serial suffixes in
parentheses are removed before comparison. DNS lookups, advertised model/vendor,
system description and VTP domain do not establish domain membership.

All protocol advertisements remain visible. Any different-domain neighbor makes
the interface red; a hostname without a domain also makes it red. Otherwise an unresolved name makes it amber; otherwise it is
green. Required collection failure overrides the row to amber while Observed
finding retains known neighbor evidence. If discovery cannot establish absence,
Observed finding says `Neighbor absence unverified`. Both protocols must be
successfully collected, with interface discovery available, to establish absence;
disabled or unsupported discovery is amber, rather than neutral Unknown.

## Outputs and limitations

Excel uses a single VRF column; the VPN selection is not repeated as a separate column.
The Interfaces sheet opens with a color legend above the
table. The table header is on row 8; filters apply only to the table, and frozen
panes keep the legend, header and identifying columns visible while scrolling.
On Interfaces, F is Neighbor, G is Observed finding, H is ARP IP count,
and I is Unique MAC count. Neighbor displays all known advertised CDP/LLDP names,
regardless of domain or row color, with duplicate names removed. If no name is
available, it displays Unknown. Observed finding and row colors retain the
classification result and collection limitations.
The workbook contains Interfaces, ARP Details, Neighbors, Collection, Command
Manifest and Readme. Interfaces has one row per selected interface with full-row
colors; ARP Details includes exclusions and their reasons; Neighbors preserves
each protocol advertisement; Collection also lists routers whose interfaces could
not be discovered. Raw per-router text files retain every attempted command.
Router identity comes from `show version` when available; the actual inventory
connection address is retained separately. Untrusted spreadsheet strings are
stored as text, not executable Excel formulas.

An inaccessible router cannot have its unknown interfaces invented. A VRF with
no assigned interfaces has no Interfaces rows and a Collection summary. Exit
codes: 0 for complete collection (including red findings), 1 for incomplete router
collection, 2 for input/dependency/file errors.

ARP is a cached IPv4 snapshot, not an endpoint census. Silent hosts, proxy ARP,
stale entries, remote static entries, virtual machines and many IPs sharing one
MAC affect inference. Advertised neighbor names are unverified. Shared parent
neighbors do not prove connectivity in each VLAN. Neither the switch inference
nor a neutral Unknown classification confirms device identity. Unknown CLI formats remain
visible errors and may need parser updates after device verification.

Run offline checks without contacting routers:

```bash
python -m unittest discover -s tests -v
```
