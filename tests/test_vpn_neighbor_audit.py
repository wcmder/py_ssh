"""Offline fixtures, deliberately not a claim of device certification."""
import argparse
from contextlib import redirect_stdout
import io
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import vpn_neighbor_audit as audit


HEADER = "Protocol  Address          Age (min)  Hardware Addr   Type   Interface\n"
CONFIG = """interface GigabitEthernet0/0/1
 no ip address
!
interface GigabitEthernet0/0/1.20
 encapsulation dot1Q 20
 vrf forwarding 20
 ip address 10.20.0.1 255.255.255.0
!
interface GigabitEthernet0/0/1.21
 encapsulation dot1Q 21
 vrf forwarding 20
 ip address 10.21.0.1 255.255.255.0
!
interface GigabitEthernet0/0/2.30
 vrf forwarding 30
 ip address 10.20.0.99 255.255.255.0
!
"""
CDP = """-------------------------
Device ID: switch.example.org
Entry address(es):
  IP address: 192.0.2.1
Platform: cisco C9300, Capabilities: Switch IGMP
Interface: GigabitEthernet0/0/1, Port ID (outgoing port): GigabitEthernet1/0/1
Holdtime : 123 sec
Version :
Cisco IOS XE Software
advertisement version: 2
Total cdp entries displayed : 1
"""
LLDP = """------------------------------------------------
Local Intf: Gi0/0/1
Chassis id: aabb.ccdd.eeff
Port id: Gi1/0/1
Port Description: uplink
System Name: switch.example.org
System Description:
Cisco IOS XE Software, C9300
Time remaining: 100 seconds
System Capabilities: B,R
Enabled Capabilities: B,R
Total entries displayed: 1
"""


def arp(ip, mac, interface="GigabitEthernet0/0/1.20", age="5"):
    return f"Internet  {ip}  {age}  {mac}  ARPA  {interface}\n"


class FakeConnection:
    def __init__(self, overrides=None):
        self.overrides = overrides or {}
        self.sent = []
        self.disconnected = False

    def send_command(self, command, **kwargs):
        self.sent.append(command)
        if command in self.overrides:
            value = self.overrides[command]
            if isinstance(value, Exception):
                raise value
            return value
        answers = {
            "show version": "Cisco IOS XE Software, Version 17.15.06\nactual-router uptime is 1 day",
            "show vrf": "  Name  Default RD  Protocols  Interfaces\n  20  1:20  ipv4  Gi0/0/1.20\n                                 Gi0/0/1.21",
            "show ip vrf interfaces": "Interface IP-Address VRF Protocol\nGi0/0/1.20 10.20.0.1 20 up\nGi0/0/1.21 10.21.0.1 20 down",
            "show sdwan running-config | section ^vrf definition": "vrf definition 20\n rd 1:20\nvrf definition 30\n rd 1:30",
            "show sdwan running-config | section ^interface": CONFIG,
            "show ip arp vrf 20": HEADER,
            "show cdp": "Global CDP information:\n Sending CDP packets every 60 seconds",
            "show cdp interface": "GigabitEthernet0/0/1 is up, line protocol is up\n Encapsulation 802.1Q\n Sending CDP packets every 60 seconds",
            "show cdp neighbors detail": "Total cdp entries displayed : 0",
            "show lldp": "Global LLDP Information:\n Status: ACTIVE",
            "show lldp interface": "GigabitEthernet0/0/1:\n Tx: enabled\n Rx: enabled",
            "show lldp neighbors detail": "Total entries displayed: 0",
        }
        if command in answers:
            return answers[command]
        if command.startswith("show interfaces "):
            name = command.split()[-1]
            return f"{name} is up, line protocol is up\n Hardware is vNIC, address is 0011.2233.4455 (bia 0011.2233.4455)"
        if command.startswith("show ip interface "):
            name = command.split()[-1]
            ip = "10.20.0.1" if name.endswith(".20") else "10.21.0.1"
            return f"{name} is up, line protocol is up\n Internet address is {ip}/24"
        raise AssertionError(f"Unexpected command: {command}")

    def disconnect(self):
        self.disconnected = True


class AuditTests(unittest.TestCase):
    def collect(self, overrides=None, device_extra=None, arg_extra=None):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        args = argparse.Namespace(vpn=20, domain="example.org", vrf=None, device_type="cisco_ios",
                                  timeout=20, per_cmd_timeout=30, output_dir=Path(temp.name),
                                  prefix="audit", append=None)
        for key, value in (arg_extra or {}).items():
            setattr(args, key, value)
        device = {"hostname": "inventory-router", "connect_host": "192.0.2.10", "username": "test", "password": "test"}
        device.update(device_extra or {})
        conn = FakeConnection(overrides)
        with patch.object(audit.ssh, "ConnectHandler", return_value=conn), redirect_stdout(io.StringIO()):
            result = audit.audit_device(device, args)
        self.assertTrue(conn.disconnected)
        return result, conn, args

    def test_interface_normalization_and_parent(self):
        self.assertEqual(audit.interface_name("Gi0/0/1.20"), "GigabitEthernet0/0/1.20")
        self.assertEqual(audit.physical_parent("GigabitEthernet0/0/1.20"), "GigabitEthernet0/0/1")
        for name in ("Vlan20", "Port-channel1.20", "Loopback20", "BDI20", "Tunnel20"):
            self.assertEqual(audit.physical_parent(name), "")

    def test_suffix_boundaries(self):
        for name in ("sw.example.org", "SW.EXAMPLE.ORG.", "sw.site.example.org", "sw.example.org(SERIAL)"):
            self.assertEqual(audit.neighbor_domain(name, "example.org"), "Our domain")
        for name in ("sw.badexample.org", "sw.example.org.evil.net", "sw.other.net"):
            self.assertEqual(audit.neighbor_domain(name, "example.org"), "Different advertised domain")
        for name in ("sw", "example.org", "192.0.2.1", "0011.2233.4455", "", "bad name.example.org"):
            self.assertEqual(audit.neighbor_domain(name, "example.org"), "Neighbor domain undetermined")

    def test_domain_validation(self):
        self.assertEqual(audit.domain_name(" .EXAMPLE.ORG. "), "example.org")
        for domain in ("", "example", "192.0.2.1", "bad domain.org", "a..org"):
            with self.assertRaises(ValueError):
                audit.domain_name(domain)

    def test_multiple_domains_exact_suffix(self):
        domains = ["example.org", "another.org"]
        for name in ("sw.s1.example.org", "sw.another.org", "sw.site.another.org"):
            self.assertEqual(audit.neighbor_domain(name, domains), "Our domain")
        for name in ("sw.badanother.org", "sw.another.org.evil.net", "sw.other.org"):
            self.assertEqual(audit.neighbor_domain(name, domains), "Different advertised domain")
        self.assertEqual(audit.neighbor_domain("sw", domains), "Neighbor domain undetermined")

    def test_multiple_input_formats_and_overrides(self):
        args = audit.build_parser().parse_args(["--vpn", "20,30", "--vpn", "20", "--domain", "example.org", "another.org"])
        self.assertEqual(audit.vpn_numbers(args.vpn), [20, 30])
        self.assertEqual(audit.vpn_numbers("20 30,20"), [20, 30])
        self.assertEqual(audit.vrf_overrides(["20=LAN20", "30=LAN30"], [20, 30]), {"20": "LAN20", "30": "LAN30"})
        for values in ([], "512", "0", "20,65526", "foo"):
            with self.assertRaises(ValueError):
                audit.vpn_numbers(values)
        with self.assertRaises(ValueError):
            audit.vrf_overrides("LAN20", [20, 30])

    def test_multiple_vpns_one_session_separate_arp_and_ownership(self):
        overrides = {
            "show ip arp vrf 20": HEADER + arp("10.20.0.99", "aaaa.bbbb.0001"),
            "show ip arp vrf 30": HEADER + arp("10.20.0.99", "0011.2233.4455", "Gi0/0/2.30") + arp("10.20.0.1", "aaaa.bbbb.0002", "Gi0/0/2.30"),
            "show ip interface GigabitEthernet0/0/2.30": "GigabitEthernet0/0/2.30 is up, line protocol is up\n Internet address is 10.20.0.99/24",
            "show cdp interface": "GigabitEthernet0/0/1 is up, line protocol is up\n Sending CDP packets every 60 seconds\nGigabitEthernet0/0/2 is up, line protocol is up\n Sending CDP packets every 60 seconds",
            "show lldp interface": "GigabitEthernet0/0/1:\n Tx: enabled\n Rx: enabled\nGigabitEthernet0/0/2:\n Tx: enabled\n Rx: enabled",
        }
        result, conn, args = self.collect(overrides, arg_extra={"vpn": [20, 30], "domain": ["example.org", "another.org"]})
        self.assertFalse(result["error"], result["error"])
        self.assertEqual(conn.sent.count("show version"), 1)
        self.assertEqual(conn.sent.count("show cdp neighbors detail"), 1)
        self.assertEqual(conn.sent.count("show lldp neighbors detail"), 1)
        rows = {(row["VRF"], row["Logical interface"]): row for row in result["interfaces"]}
        self.assertEqual(rows[("20", "GigabitEthernet0/0/1.20")]["ARP IP count"], 1)
        self.assertEqual(rows[("30", "GigabitEthernet0/0/2.30")]["ARP IP count"], 1)
        self.assertEqual(rows[("30", "GigabitEthernet0/0/2.30")]["Unique MAC count"], 1)
        arp_commands = [row for row in result["collection"] if row["Purpose"] == "arp"]
        self.assertEqual([row["VRF"] for row in arp_commands], ["20", "30"])
        from openpyxl import load_workbook
        path = args.output_dir / "multi.xlsx"
        audit.write_workbook(path, [result], args)
        wb = load_workbook(path)
        self.assertEqual(wb["Interfaces"].max_row, audit.INTERFACES_HEADER_ROW + 3)
        self.assertEqual(wb["Readme"]["B2"].value, "20, 30")
        self.assertEqual(wb["Readme"]["B3"].value, "example.org, another.org")
        self.assertNotIn("VPN", [cell.value for cell in wb["Interfaces"][audit.INTERFACES_HEADER_ROW]])
        wb.close()

    def test_missing_vpn_does_not_block_other_vpn(self):
        result, conn, _ = self.collect(arg_extra={"vpn": [999, 20]})
        self.assertIn("VRF 999", result["error"])
        self.assertEqual(len(result["interfaces"]), 2)
        self.assertEqual(result["interfaces"][0]["Row color"], "Neutral")
        self.assertIn("show ip arp vrf 20", conn.sent)
        self.assertNotIn("show ip arp vrf 999", conn.sent)
        summaries = [r for r in result["collection"] if r["Purpose"] == "VRF summary"]
        self.assertEqual([r["Status"] for r in summaries], ["failed", "success_with_entries"])

    def test_neighbor_matches_second_accepted_domain(self):
        result, _, _ = self.collect({"show cdp neighbors detail": CDP.replace("example.org", "another.org")},
                                    arg_extra={"domain": ["example.org", "another.org"]})
        self.assertEqual(result["interfaces"][0]["Classification"], "Our domain")
        self.assertEqual(result["interfaces"][0]["Row color"], "Green")

    def test_counts_remain_on_logical_interface(self):
        data = HEADER + arp("10.20.0.2", "aaaa.bbbb.0001") + arp("10.20.0.3", "aaaa.bbbb.0002")
        data += arp("10.21.0.2", "aaaa.bbbb.0003", "Gi0/0/1.21")
        result, conn, _ = self.collect({"show ip arp vrf 20": data})
        self.assertFalse(result["error"])
        self.assertEqual([r["Unique MAC count"] for r in result["interfaces"]], [2, 1])
        self.assertEqual([r["Row color"] for r in result["interfaces"]], ["Red", "Neutral"])
        self.assertEqual(result["interfaces"][0]["Classification"], "Likely third-party switch")
        self.assertEqual(result["interfaces"][1]["Classification"], "Unknown")
        self.assertIn("show lldp neighbors detail", conn.sent)
        self.assertIn("show cdp neighbors detail", conn.sent)

    def test_dedup_incomplete_local_and_overlapping_vrf(self):
        data = HEADER + arp("10.20.0.1", "0011.2233.4455", age="-")
        data += arp("10.20.0.2", "0011.2233.4455")  # local MAC
        data += arp("10.20.0.3", "aaaa.bbbb.0001") * 2
        data += arp("10.20.0.4", "aaaa.bbbb.0001", age="-")  # remote static retained
        data += arp("10.20.0.5", "aaaa.bbbb.0002")
        data += arp("10.20.0.99", "aaaa.bbbb.0003")  # local IP only in VPN 30: retain
        data += "Internet 10.20.0.9 0 Incomplete ARPA\n"
        result, _, _ = self.collect({"show ip arp vrf 20": data})
        row = result["interfaces"][0]
        self.assertEqual((row["ARP IP count"], row["Unique MAC count"]), (4, 3))
        self.assertEqual(row["Classification"], "Likely third-party switch")
        self.assertEqual(row["Row color"], "Red")
        self.assertEqual(result["arp"][-1]["Disposition"], "Incomplete")

    def test_empty_success_and_down_interface_retained(self):
        result, _, _ = self.collect()
        self.assertEqual(len(result["interfaces"]), 2)
        self.assertEqual([r["ARP IP count"] for r in result["interfaces"]], [0, 0])
        self.assertEqual(result["interfaces"][0]["Observed finding"], "0 hosts found, likely not a switch")
        self.assertEqual(next(r["Status"] for r in result["collection"] if r["Purpose"] == "arp"), "success_empty")

    def test_many_ips_one_mac_is_unknown(self):
        result, _, _ = self.collect({"show ip arp vrf 20": HEADER + "".join(arp(f"10.20.0.{i}", "aaaa.bbbb.0001") for i in range(2, 12))})
        row = result["interfaces"][0]
        self.assertEqual((row["ARP IP count"], row["Unique MAC count"]), (10, 1))
        self.assertEqual(row["Classification"], "Unknown")
        self.assertEqual(row["Observed finding"], "1 host found, likely not a switch")

    def test_parent_neighbors_without_arp(self):
        result, _, _ = self.collect({"show cdp neighbors detail": CDP, "show lldp neighbors detail": LLDP})
        for row in result["interfaces"]:
            self.assertEqual(row["Row color"], "Green")
            self.assertEqual(row["ARP IP count"], 0)
            self.assertIn("Physical parent", row["Match scope"])
        self.assertEqual(len(result["neighbors"]), 4)

    def test_different_domain_overrides_matching_neighbor(self):
        result, _, _ = self.collect({"show cdp neighbors detail": CDP,
                                    "show lldp neighbors detail": LLDP.replace("switch.example.org", "sw.other.org")})
        self.assertEqual(result["interfaces"][0]["Row color"], "Red")
        self.assertEqual(result["interfaces"][0]["Classification"], "Different advertised domain")
        self.assertEqual(result["interfaces"][0]["Neighbor"], "switch.example.org\nsw.other.org")
        self.assertIn("Cisco", result["interfaces"][0]["System description"])

    def test_unknown_name_amber(self):
        result, _, _ = self.collect({"show cdp neighbors detail": CDP.replace("switch.example.org", "switch")})
        self.assertEqual(result["interfaces"][0]["Classification"], "Neighbor domain undetermined")
        self.assertEqual(result["interfaces"][0]["Neighbor"], "switch")

    def test_blank_arp_is_not_zero(self):
        result, _, _ = self.collect({"show ip arp vrf 20": ""})
        self.assertIsNone(result["interfaces"][0]["ARP IP count"])
        self.assertEqual(result["interfaces"][0]["Row color"], "Amber")
        self.assertIn("parse_error", result["interfaces"][0]["Collection errors"])

    def test_fallback_unsupported_retained(self):
        result, _, _ = self.collect({"show ip arp vrf 20": "% Invalid input detected at '^' marker.",
                                    "show arp vrf 20": HEADER})
        arp_results = [r for r in result["collection"] if r["Purpose"].startswith("arp")]
        self.assertEqual([r["Status"] for r in arp_results], ["unsupported", "success_empty"])
        self.assertEqual(result["interfaces"][0]["Row color"], "Neutral")

    def test_discovery_failure_preserves_finding(self):
        result, _, _ = self.collect({"show cdp neighbors detail": CDP.replace("example.org", "other.org"),
                                    "show lldp neighbors detail": "% Invalid input detected at '^' marker."})
        row = result["interfaces"][0]
        self.assertEqual(row["Row color"], "Amber")
        self.assertEqual(row["Observed finding"], "Different advertised domain")

    def test_disabled_discovery_is_not_neutral_unknown(self):
        result, _, _ = self.collect({"show lldp": "% LLDP is not enabled"})
        row = result["interfaces"][0]
        self.assertEqual(row["Row color"], "Amber")
        self.assertEqual(row["Observed finding"], "Neighbor absence unverified")

    def test_timeout_stops_session_and_keeps_previous_output(self):
        conn = FakeConnection({"show cdp": TimeoutError("timed out")})
        collector = audit.Collector(conn, 1)
        first, _ = collector.get("version", lambda x: x)
        collector.run("cdp_status")
        last = collector.run("lldp_status")
        self.assertEqual(first.status, "success_with_entries")
        self.assertEqual(last.status, "failed")
        self.assertNotIn("show lldp", conn.sent)
        self.assertIn("17.15.06", collector.results[0].output)

    def test_unrecognized_and_malformed_output_fail(self):
        for parser in (audit.parse_arp, audit.parse_membership, audit.parse_vrfs, audit.parse_config):
            with self.assertRaises(ValueError):
                parser("unexpected text")
        with self.assertRaises(ValueError):
            audit.parse_arp(HEADER + arp("10.20.0.3", "bogus"))
        with self.assertRaises(ValueError):
            audit.parse_arp(HEADER + "unrecognized nonempty data")
        with self.assertRaises(ValueError):
            audit.parse_neighbors(CDP.replace("displayed : 1", "displayed : 2"), "CDP")

    def test_explicit_named_vrf(self):
        replacements = {
            "show vrf": "Name Default RD Protocols Interfaces\nLAN20 1:20 ipv4 Gi0/0/1.20\n Gi0/0/1.21",
            "show ip vrf interfaces": "Interface IP-Address VRF Protocol\nGi0/0/1.20 10.20.0.1 LAN20 up\nGi0/0/1.21 10.21.0.1 LAN20 down",
            "show sdwan running-config | section ^vrf definition": "vrf definition LAN20\n rd 1:20",
            "show sdwan running-config | section ^interface": CONFIG.replace("vrf forwarding 20", "vrf forwarding LAN20"),
            "show ip arp vrf LAN20": HEADER,
        }
        result, conn, _ = self.collect(replacements, {"vpn_vrf_map": {"20": "LAN20"}})
        self.assertFalse(result["error"])
        self.assertEqual(result["interfaces"][0]["VRF"], "LAN20")
        self.assertIn("show ip arp vrf LAN20", conn.sent)
        self.assertNotIn("show ip arp vrf 20", conn.sent)

    def test_missing_vrf_still_checks_neighbors(self):
        replacements = {
            "show vrf": "Name Default RD Protocols Interfaces\n30 1:30 ipv4 Gi0/0/1",
            "show ip vrf interfaces": "Interface IP-Address VRF Protocol\nGi0/0/1 10.30.0.1 30 up",
            "show sdwan running-config | section ^vrf definition": "vrf definition 30\n rd 1:30",
            "show sdwan running-config | section ^interface": CONFIG.replace("vrf forwarding 20", "vrf forwarding 30"),
        }
        result, conn, _ = self.collect(replacements)
        self.assertIn("not verified", result["error"])
        self.assertFalse(result["interfaces"])
        self.assertIn("show cdp neighbors detail", conn.sent)
        self.assertIn("show lldp neighbors detail", conn.sent)
        self.assertNotIn("show ip arp vrf 20", conn.sent)

    def test_configured_virtual_ip_excluded(self):
        config = CONFIG.replace(" ip address 10.20.0.1 255.255.255.0", " ip address 10.20.0.1 255.255.255.0\n standby 1 ip 10.20.0.254")
        result, conn, _ = self.collect({
            "show sdwan running-config | section ^interface": config,
            "show ip arp vrf 20": HEADER + arp("10.20.0.254", "0000.0c07.ac01") + arp("10.20.0.2", "aaaa.bbbb.0001"),
        })
        self.assertNotIn("show standby brief", conn.sent)
        self.assertNotIn("show vrrp brief", conn.sent)
        self.assertEqual(result["interfaces"][0]["ARP IP count"], 1)
        self.assertEqual(result["arp"][0]["Disposition"], "Router-owned IP")

    def test_failed_connection_has_collection_summary(self):
        detail = "Authentication failed\nCommon causes: incorrect credentials\nDevice settings: additional diagnostic text"
        with patch.object(audit.ssh, "ConnectHandler", side_effect=RuntimeError(detail)):
            # collect's inner patch deliberately owns ConnectHandler; call directly here.
            with tempfile.TemporaryDirectory() as folder, redirect_stdout(io.StringIO()) as console:
                args = argparse.Namespace(vpn=20, domain="example.org", vrf=None, device_type="cisco_ios", timeout=1,
                                          per_cmd_timeout=1, output_dir=Path(folder), prefix="audit", append=None)
                result = audit.audit_device({"hostname": "r1", "connect_host": "192.0.2.1", "username": "u", "password": "p"}, args)
                self.assertIn("Authentication failed", result["collection"][0]["Collection errors"])
                self.assertEqual(result["collection"][0]["Status"], "failed")
                self.assertFalse(result["interfaces"])
                self.assertIn("[error] r1 | 192.0.2.1: Authentication failed", console.getvalue())
                self.assertNotIn("Common causes", console.getvalue())
                self.assertNotIn("[done]", console.getvalue())
                self.assertIn(detail, result["collection"][0]["Collection errors"])
                self.assertIn(detail, next(Path(folder).glob("*.txt")).read_text())

    def test_cli_prompts_and_writes_report(self):
        from openpyxl import load_workbook
        with tempfile.TemporaryDirectory() as folder:
            conn = FakeConnection()
            with patch.object(audit.ssh, "ConnectHandler", return_value=conn), \
                 patch.object(audit.ssh, "_load_devices", return_value=[{"hostname": "r1", "connect_host": "192.0.2.1", "username": "u", "password": "p"}]), \
                 patch("builtins.input", side_effect=["20", "example.org"]) as prompt, redirect_stdout(io.StringIO()):
                status = audit.main(["--out", folder, "--append", "review"])
            self.assertEqual(status, 0)
            self.assertEqual(prompt.call_count, 2)
            path = Path(folder) / "vpn-audit-review.xlsx"
            self.assertTrue(path.is_file())
            wb = load_workbook(path)
            self.assertEqual(wb["Interfaces"].max_row, audit.INTERFACES_HEADER_ROW + 2)
            wb.close()
            self.assertTrue(list(Path(folder).glob("*.txt")))

    def test_cli_multiple_prompts_continue_after_missing_vrf(self):
        from openpyxl import load_workbook
        with tempfile.TemporaryDirectory() as folder:
            conn = FakeConnection()
            with patch.object(audit.ssh, "ConnectHandler", return_value=conn) as connect, \
                 patch.object(audit.ssh, "_load_devices", return_value=[{"hostname": "r1", "connect_host": "192.0.2.1", "username": "u", "password": "p"}]), \
                 patch("builtins.input", side_effect=["999,20,20", ".EXAMPLE.ORG,another.org,example.org"]), redirect_stdout(io.StringIO()):
                status = audit.main(["--out", folder, "--append", "multi", "--threads", "2"])
            self.assertEqual(status, 1)  # VRF 999 fails, but VRF 20 is exported.
            connect.assert_called_once()
            wb = load_workbook(Path(folder) / "vpn-audit-multi.xlsx")
            self.assertEqual(wb["Interfaces"].max_row, audit.INTERFACES_HEADER_ROW + 2)
            self.assertEqual(wb["Readme"]["B2"].value, "999, 20")
            self.assertEqual(wb["Readme"]["B3"].value, "example.org, another.org")
            self.assertEqual(wb["Interfaces"]["C9"].value, "20")
            wb.close()

    def test_command_manifest_never_connects_or_prompts(self):
        with patch.object(audit.ssh, "ConnectHandler") as connect, patch("builtins.input") as prompt, redirect_stdout(io.StringIO()) as out:
            self.assertEqual(audit.main(["--list-commands"]), 0)
        connect.assert_not_called()
        prompt.assert_not_called()
        self.assertIn("show ip arp vrf <VRF>", out.getvalue())

    def test_excel_values_colors_and_untrusted_text(self):
        from openpyxl import load_workbook
        result, _, args = self.collect({"show cdp neighbors detail": CDP})
        result["neighbors"][0]["Neighbor name"] = "=1+1"
        result["collection"].append({"Status": "failed", "Collection errors": "Example failed command"})
        path = args.output_dir / "report.xlsx"
        audit.write_workbook(path, [result], args)
        wb = load_workbook(path)
        self.addCleanup(wb.close)
        self.assertEqual(wb.sheetnames, ["Interfaces", "ARP Details", "Neighbors", "Collection", "Command Manifest", "Readme"])
        for sheet in ("Interfaces", "ARP Details", "Neighbors", "Collection"):
            header_row = audit.INTERFACES_HEADER_ROW if sheet == "Interfaces" else 1
            self.assertNotIn("VPN", [cell.value for cell in wb[sheet][header_row]])
            self.assertIn("VRF", [cell.value for cell in wb[sheet][header_row]])
        self.assertEqual(wb["Interfaces"]["H9"].value, 0)
        self.assertEqual(wb["Interfaces"]["H9"].data_type, "n")
        self.assertEqual(wb["Interfaces"]["F8"].value, "Neighbor")
        self.assertEqual(wb["Interfaces"]["H8"].value, "ARP IP count")
        self.assertEqual(wb["Interfaces"]["G8"].value, "Observed finding")
        self.assertEqual(wb["Interfaces"]["F9"].value, "switch.example.org")
        self.assertEqual(wb["Interfaces"]["G9"].value, "Our domain")
        self.assertEqual(wb["Interfaces"]["I8"].value, "Unique MAC count")
        self.assertEqual(wb["Interfaces"]["I9"].value, 0)
        self.assertEqual(wb["Interfaces"]["I9"].number_format, "#,##0")
        self.assertEqual(wb["Interfaces"]["A9"].fill.fgColor.rgb, "00C6EFCE")
        self.assertEqual(wb["Neighbors"]["H2"].value, "=1+1")
        self.assertEqual(wb["Neighbors"]["H2"].data_type, "s")
        self.assertEqual(wb["Interfaces"].freeze_panes, "F9")
        self.assertEqual(wb["Interfaces"].auto_filter.ref, "A8:Q10")
        self.assertEqual(wb["Interfaces"]["A1"].value, "Color meaning")
        for row, color in enumerate(("Green", "Red", "Neutral", "Amber"), 2):
            self.assertEqual(wb["Interfaces"].cell(row, 1).fill.fgColor.rgb, "00" + audit.COLORS[color])
        self.assertIn("2+", wb["Interfaces"]["B3"].value)
        self.assertIn("0–1", wb["Interfaces"]["B4"].value)
        self.assertEqual(wb["Command Manifest"].max_row, len(audit.COMMANDS) + 1)
        self.assertEqual(wb["Collection"].cell(wb["Collection"].max_row, 1).fill.fgColor.rgb, "00FFEB9C")


if __name__ == "__main__":
    unittest.main()
