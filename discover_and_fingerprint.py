#!/usr/bin/env python3
"""
discover_and_fingerprint.py (hostname + robust XML + wrapped PDF)

Usage:
    python3 discover_and_fingerprint.py
or
    python3 discover_and_fingerprint.py -i ip_list.txt -o results_dir

Outputs:
  - results_dir/results.csv
  - results_dir/report.pdf
  - results_dir/nmap_discovery.xml
  - results_dir/detailed_scans/*.xml
  - results_dir/logs/*.stderr.txt
"""
import os
import sys
import argparse
import subprocess
import xml.etree.ElementTree as ET
import csv
import datetime
import shutil
from dateutil import tz
from reportlab.platypus import SimpleDocTemplate, Paragraph, Table, TableStyle, Spacer
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.units import mm

# ---------- Configuration ----------
COMMON_PORTS = "22,80,443,3389,161"
DETAIL_SCRIPTS = "banner,snmp-info,http-title"
MIN_XML_BYTES = 200  # minimal bytes for a usable nmap XML

# ---------- Utilities ----------
def run_cmd(cmd, capture_output=True):
    """Run command and return (stdout, stderr, rc). Print debug summary."""
    print("RUN:", " ".join(cmd))
    p = subprocess.run(cmd, stdout=subprocess.PIPE if capture_output else None,
                       stderr=subprocess.PIPE if capture_output else None, text=True)
    stdout = p.stdout or ""
    stderr = p.stderr or ""
    if p.returncode != 0:
        print(f"WARNING: command returned rc={p.returncode}")
        if stderr:
            print("nmap stderr (truncated):")
            print("\n".join(stderr.splitlines()[:30]))
    return stdout, stderr, p.returncode

def ensure_dir(p):
    if not os.path.exists(p):
        os.makedirs(p, exist_ok=True)

def check_nmap():
    if shutil.which("nmap") is None:
        print("ERROR: nmap not found in PATH. Install nmap and retry.")
        sys.exit(1)

def is_root():
    try:
        return os.geteuid() == 0
    except AttributeError:
        return False

def xml_file_ok(path):
    return os.path.isfile(path) and os.path.getsize(path) >= MIN_XML_BYTES

def save_log(outdir, name, content):
    ensure_dir(os.path.join(outdir, 'logs'))
    path = os.path.join(outdir, 'logs', name)
    with open(path, 'w', encoding='utf-8') as f:
        f.write(content or '')
    return path

# ---------- XML helpers with namespace tolerance ----------
def findall_ns(elem, tag_localname):
    return elem.findall('.//{*}' + tag_localname)

def find_ns(elem, tag_localname):
    return elem.find('.//{*}' + tag_localname)

# ---------- Parse discovery XML for up hosts ----------
def parse_nmap_xml_for_up_hosts(xmlfile):
    if not xml_file_ok(xmlfile):
        print(f"DEBUG: discovery XML '{xmlfile}' missing/too small ({os.path.getsize(xmlfile) if os.path.exists(xmlfile) else 'nofile'})")
        return {}
    try:
        tree = ET.parse(xmlfile)
    except ET.ParseError as e:
        print(f"ERROR: parse error for {xmlfile}: {e}")
        return {}
    root = tree.getroot()
    up_hosts = {}
    for host in findall_ns(root, 'host'):
        status = host.find('{*}status')
        state = status.get('state') if status is not None else 'unknown'
        addr = None
        vendor = None
        for a in findall_ns(host, 'address'):
            addrtype = a.get('addrtype')
            if addrtype in ('ipv4', 'ipv6'):
                addr = a.get('addr')
            if a.get('vendor'):
                vendor = a.get('vendor')
        if state == 'up' and addr:
            up_hosts[addr] = {'vendor': vendor, 'raw': ET.tostring(host, encoding='unicode')}
    return up_hosts

# ---------- Parse detailed nmap XML (extract hostname too) ----------
def parse_detailed_nmap_xml(xmlfile):
    """
    Return dict: ip -> info where info contains:
      'ip','mac_vendor','hostname','ports' (list), 'os', 'script' (dict)
    """
    if not xml_file_ok(xmlfile):
        return {}
    try:
        tree = ET.parse(xmlfile)
    except ET.ParseError as e:
        print(f"ERROR: parse error for {xmlfile}: {e}")
        return {}
    root = tree.getroot()
    hosts = {}
    for host in findall_ns(root, 'host'):
        ip = None
        mac_vendor = None
        hostnames = []
        # addresses
        for a in findall_ns(host, 'address'):
            if a.get('addrtype') in ('ipv4', 'ipv6'):
                ip = a.get('addr')
            if a.get('addrtype') == 'mac' and a.get('vendor'):
                mac_vendor = a.get('vendor')
        # hostnames (nmap puts them under <hostnames><hostname name="..." /> )
        hostnames_node = host.find('{*}hostnames')
        if hostnames_node is not None:
            for hn in host.findall('.//{*}hostname'):
                if hn.get('name'):
                    hostnames.append(hn.get('name'))
        hostname = ",".join(hostnames) if hostnames else None

        info = {'ip': ip, 'mac_vendor': mac_vendor, 'hostname': hostname, 'ports': [], 'os': None, 'script': {}}
        # os
        osnode = find_ns(host, 'os')
        if osnode is not None:
            osmatch = osnode.find('{*}osmatch')
            if osmatch is not None and osmatch.get('name'):
                info['os'] = osmatch.get('name')
        # ports
        ports_node = find_ns(host, 'ports')
        if ports_node is not None:
            for p in ports_node.findall('{*}port'):
                portnum = p.get('portid')
                proto = p.get('protocol')
                state_node = p.find('{*}state')
                state = state_node.get('state') if state_node is not None else None
                serviceNode = p.find('{*}service')
                svcname = serviceNode.get('name') if serviceNode is not None else None
                banner = serviceNode.get('product') if serviceNode is not None and serviceNode.get('product') else None
                info['ports'].append({'port': portnum, 'proto': proto, 'state': state, 'service': svcname, 'banner': banner})
                # port-level scripts
                for s in p.findall('{*}script'):
                    info['script'][s.get('id')] = s.get('output')
        # hostscript-level scripts
        hostscript = find_ns(host, 'hostscript')
        if hostscript is not None:
            for s in hostscript.findall('{*}script'):
                info['script'][s.get('id')] = s.get('output')
        hosts[ip] = info
    return hosts

# ---------- Heuristics (unchanged logic, compact) ----------
def heuristic_guess_type(dinfo):
    pv = (dinfo.get('mac_vendor') or '').lower()
    osname = (dinfo.get('os') or '').lower()
    portset = set([p['port'] for p in dinfo.get('ports', []) if p.get('state') in ('open', 'open|filtered')])
    scripts_and_banners = " ".join([ (v or "") for v in dinfo.get('script', {}).values() ] + [ (p.get('banner') or "") for p in dinfo.get('ports', []) ]).lower()
    guesses = []
    if '161' in portset or 'snmp' in scripts_and_banners:
        guesses.append('network-device (snmp)')
    if 'windows' in osname:
        guesses.append('Windows endpoint/server')
    if any(k in osname for k in ('linux','centos','ubuntu','debian','unix')):
        guesses.append('Linux/Unix server or endpoint')
    if '3389' in portset or any(p['service']=='ms-wbt-server' for p in dinfo.get('ports', [])):
        guesses.append('Windows (RDP)')
    if any((p.get('service') == 'ssh' or p.get('port') == '22') for p in dinfo.get('ports', [])):
        guesses.append('Likely Linux/Unix (SSH)')
    if any(p.get('port') in ('80','443') for p in dinfo.get('ports', [])):
        guesses.append('HTTP server / appliance web UI')
    if 'fortigate' in scripts_and_banners or 'fortios' in scripts_and_banners or 'fortinet' in pv:
        guesses.append('Fortinet firewall')
    if 'printer' in scripts_and_banners or 'ipp' in scripts_and_banners:
        guesses.append('Printer')
    if not guesses:
        guesses.append('Unknown')
    out = []
    for g in guesses:
        if g not in out:
            out.append(g)
    return "; ".join(out)

# ---------- Output helpers ----------
def write_csv(rows, csvfile):
    keys = ['ip', 'hostname', 'alive', 'icmp_blocked', 'type_guess', 'os', 'mac_vendor', 'open_ports', 'scan_xml']
    with open(csvfile, 'w', newline='', encoding='utf-8') as f:
        w = csv.DictWriter(f, fieldnames=keys)
        w.writeheader()
        for r in rows:
            w.writerow({k: r.get(k, '') for k in keys})

def make_pdf_report(rows, outpdf):
    doc = SimpleDocTemplate(outpdf, pagesize=A4, rightMargin=15*mm, leftMargin=15*mm, topMargin=15*mm, bottomMargin=15*mm)
    styles = getSampleStyleSheet()
    normal = styles['BodyText']
    normal.wordWrap = 'CJK'
    title_style = styles['Title']
    story = []
    story.append(Paragraph("Network Discovery Report", title_style))
    story.append(Paragraph("Generated: " + datetime.datetime.now(tz=tz.tzlocal()).isoformat(), styles['Normal']))
    story.append(Spacer(1, 8))

    hdr = ['IP', 'Hostname', 'Alive', 'ICMP Blocked?', 'Type guess', 'OS', 'MAC Vendor', 'Open ports']
    table_data = [hdr]
    for r in rows:
        table_data.append([
            Paragraph(r['ip'] or '', normal),
            Paragraph(r.get('hostname') or '', normal),
            Paragraph(str(r['alive']), normal),
            Paragraph(str(r['icmp_blocked']), normal),
            Paragraph(r.get('type_guess') or '', normal),
            Paragraph(r.get('os') or '', normal),
            Paragraph(r.get('mac_vendor') or '', normal),
            Paragraph(r.get('open_ports') or '', normal),
        ])

    page_w, page_h = A4
    usable_w = page_w - (15*mm*2)
    # allocate reasonably sized columns; type/os bigger
    col_widths = [
        30*mm,  # IP
        55*mm,  # Hostname
        15*mm,  # Alive
        20*mm,  # ICMP Blocked
        70*mm,  # Type guess
        50*mm,  # OS
        40*mm,  # MAC vendor
        usable_w - (30*mm + 55*mm + 15*mm + 20*mm + 70*mm + 50*mm + 40*mm)
    ]
    col_widths = [w if w > 15*mm else 20*mm for w in col_widths]

    t = Table(table_data, colWidths=col_widths, repeatRows=1)
    t.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#cfeefb')),
        ('GRID', (0,0), (-1,-1), 0.4, colors.grey),
        ('VALIGN', (0,0), (-1,-1), 'TOP'),
        ('ALIGN', (2,0), (3,-1), 'CENTER'),
        ('LEFTPADDING', (0,0), (-1,-1), 3),
        ('RIGHTPADDING', (0,0), (-1,-1), 3),
    ]))
    story.append(t)
    doc.build(story)

# ---------- Main flow ----------
def main():
    parser = argparse.ArgumentParser(description="Discover alive hosts and fingerprint them (hostname included).")
    parser.add_argument('-i', '--input', default='ip_list.txt', help='Input file (one IP per line). Default: ip_list.txt')
    parser.add_argument('-o', '--out', default='results_dir', help='Output directory. Default: results_dir')
    parser.add_argument('--yes-root', action='store_true', help='Suppress root-warning if not root')
    args = parser.parse_args()

    check_nmap()
    if not is_root() and not args.yes_root:
        print("WARNING: You are not running as root/administrator. Some nmap features (ARP discovery, accurate OS detection) may be less effective.")
        print("If you want to proceed anyway and suppress this message next time, re-run with --yes-root.")
        print("Continuing without root...")

    ipfile = args.input
    outdir = args.out
    ensure_dir(outdir)
    ensure_dir(os.path.join(outdir, 'detailed_scans'))
    ensure_dir(os.path.join(outdir, 'logs'))

    if not os.path.isfile(ipfile):
        print(f"ERROR: Input file '{ipfile}' not found. Create one IP per line and retry.")
        sys.exit(1)

    with open(ipfile) as f:
        ips = [line.strip() for line in f if line.strip()]

    # Discovery scan
    discovery_xml = os.path.join(outdir, "nmap_discovery.xml")
    cmd = ["nmap", "-sn", "-PE", "-PS"+COMMON_PORTS, "-PA", "-oX", discovery_xml, "-iL", ipfile]
    stdout, stderr, rc = run_cmd(cmd)
    if rc != 0:
        save_log(outdir, "nmap_discovery.stderr.txt", stderr)
        print("nmap discovery returned error - saved stderr to logs/")

    if not xml_file_ok(discovery_xml):
        print("ERROR: discovery XML missing or too small. See logs. Continuing with per-IP probes.")
        up_hosts = {}
    else:
        up_hosts = parse_nmap_xml_for_up_hosts(discovery_xml)

    print("Discovery - hosts reported up:", list(up_hosts.keys()))

    results = []
    for ip in ips:
        print("Processing", ip)
        entry = {'ip': ip, 'hostname': '', 'alive': False, 'icmp_blocked': False, 'type_guess': '', 'os': None, 'mac_vendor': None, 'open_ports': '', 'scan_xml': ''}
        if ip in up_hosts:
            entry['alive'] = True
            xmlout = os.path.join(outdir, 'detailed_scans', f"{ip.replace(':','_')}.xml")
            cmd = ["nmap", "-sS", "-sV", "-O", "--script="+DETAIL_SCRIPTS, "-p", COMMON_PORTS, "-oX", xmlout, ip]
            stdout, stderr, rc = run_cmd(cmd)
            if rc != 0:
                save_log(outdir, f"{ip}_detailed.stderr.txt", stderr)
            if not xml_file_ok(xmlout):
                print(f"WARNING: detailed XML for {ip} missing/too small. Will fallback to -Pn probe.")
                xmlout_pn = os.path.join(outdir, 'detailed_scans', f"{ip.replace(':','_')}_fallback_pn.xml")
                run_cmd(["nmap", "-Pn", "-sS", "-p", COMMON_PORTS, "-oX", xmlout_pn, ip])
                if xml_file_ok(xmlout_pn):
                    xmlout = xmlout_pn
            entry['scan_xml'] = xmlout if os.path.exists(xmlout) else ''
            dinfo = parse_detailed_nmap_xml(xmlout).get(ip, {}) if xml_file_ok(xmlout) else {}
            entry['mac_vendor'] = dinfo.get('mac_vendor')
            entry['hostname'] = dinfo.get('hostname')
            entry['os'] = dinfo.get('os')
            entry['open_ports'] = ",".join([p['port'] for p in dinfo.get('ports', []) if p['state'] in ('open', 'open|filtered')])
            entry['type_guess'] = heuristic_guess_type(dinfo) if dinfo else 'Unknown'
        else:
            # Not found in discovery; do -Pn quick probe
            xmlout = os.path.join(outdir, 'detailed_scans', f"{ip.replace(':','_')}_pn.xml")
            stdout, stderr, rc = run_cmd(["nmap", "-Pn", "-sS", "-p", COMMON_PORTS, "-oX", xmlout, ip])
            if rc != 0:
                save_log(outdir, f"{ip}_pn.stderr.txt", stderr)
            if xml_file_ok(xmlout):
                dinfo = parse_detailed_nmap_xml(xmlout).get(ip, {})
                has_open = any(p['state'] == 'open' for p in dinfo.get('ports', []))
                if has_open:
                    entry['alive'] = True
                    entry['icmp_blocked'] = True
                    entry['scan_xml'] = xmlout
                    entry['mac_vendor'] = dinfo.get('mac_vendor')
                    entry['hostname'] = dinfo.get('hostname')
                    entry['os'] = dinfo.get('os')
                    entry['open_ports'] = ",".join([p['port'] for p in dinfo.get('ports', []) if p['state'] in ('open', 'open|filtered')])
                    entry['type_guess'] = heuristic_guess_type(dinfo)
                else:
                    entry['scan_xml'] = xmlout
            else:
                print(f"No XML produced for {ip} (pn probe). Check logs.")
        results.append(entry)

    # Write CSV
    csvfile = os.path.join(outdir, "results.csv")
    write_csv(results, csvfile)
    print("Wrote CSV:", csvfile)

    # Write PDF
    pdffile = os.path.join(outdir, "report.pdf")
    make_pdf_report(results, pdffile)
    print("Wrote PDF:", pdffile)

    print("Detailed XMLs in:", os.path.join(outdir, 'detailed_scans'))
    print("Logs in:", os.path.join(outdir, 'logs'))
    print("Done.")

if __name__ == "__main__":
    main()
