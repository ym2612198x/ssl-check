# ssl-check
Wrapper for cURL and SSLscan for bulk checks with clean output

usage: `sslcheck.py [-h] -i INPUT -o OUTPUT [-s] [-t] [-2] [-3] [-c] [-p] [-a] [-d]`
```
options:
  -h, --help            show this help message and exit
  -i INPUT, --input INPUT
                        List of IPs to check (can be a file with one IP per line, single IP or IP range) (default: None)
  -o OUTPUT, --output OUTPUT
                        Output file (default: None)
  -s, --hsts            Check for HSTS header (default: False)
  -t, --tls             Check for TLSv1 and TLSv1.1 (default: False)
  -2, --sslv2           Check for SSLv2 (default: False)
  -3, --sslv3           Check for SSLv3 (default: False)
  -c, --certs           Check certs (default: False)
  -p, --csp             Check for CSP (default: False)
  -a, --all             Run all checks (default: False)
  -d, --debug           Debug mode (default: False)
```
