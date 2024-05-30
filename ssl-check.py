import os
import subprocess
import argparse
import requests
import ipaddress
from urllib3.exceptions import InsecureRequestWarning
from urllib.parse import urlparse
from http.client import HTTPConnection, HTTPSConnection


requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)


ap = argparse.ArgumentParser(formatter_class=argparse.ArgumentDefaultsHelpFormatter, description='Wrapper for cURL and SSLscan for bulk checks with clean output')
ap.add_argument('-i', '--input', required=True, help='List of IPs to check (can be a file with one IP per line, single IP or IP range)')
ap.add_argument('-o', '--output', required=True, help='Output file')
ap.add_argument('-s', '--hsts', help='Check for HSTS header', action="store_true")
ap.add_argument('-t', '--tls', help='Check for TLSv1 and TLSv1.1', action="store_true")
ap.add_argument('-2', '--sslv2', help='Check for SSLv2', action="store_true")
ap.add_argument('-3', '--sslv3', help='Check for SSLv3', action="store_true")
ap.add_argument('-c', '--certs', help='Check certs', action="store_true")
ap.add_argument('-p', '--csp', help='Check for CSP', action="store_true")
ap.add_argument('-a', '--all', help='Run all checks', action="store_true")
ap.add_argument('-d', '--debug', help='Debug mode', action="store_true")
args = ap.parse_args()
if args.all:
    args.hsts = True
    args.csp = True
    args.certs = True
    args.sslv2 = True
    args.sslv3 = True
    args.tls = True
input_file = args.input
output_file = args.output


RST = '\033[0;39m'
INFO = '\033[36m'
BAD = '\033[31m'
GOOD = '\033[34m'
DETAIL = '\033[33m'
OTHER = '\033[30m'


all_hsts = []
all_tls = []
all_sslv2 = []
all_sslv3 = []
all_rc4 = []
all_cbc = []
all_csp = []


def banner(args):

    print(
    f"""{BAD}

    ███████╗███████╗██╗       ██████╗██╗  ██╗███████╗ ██████╗██╗  ██╗
    ██╔════╝██╔════╝██║      ██╔════╝██║  ██║██╔════╝██╔════╝██║ ██╔╝
    ███████╗███████╗██║█████╗██║     ███████║█████╗  ██║     █████╔╝ 
    ╚════██║╚════██║██║╚════╝██║     ██╔══██║██╔══╝  ██║     ██╔═██╗ 
    ███████║███████║███████╗ ╚██████╗██║  ██║███████╗╚██████╗██║  ██╗
    ╚══════╝╚══════╝╚══════╝  ╚═════╝╚═╝  ╚═╝╚══════╝ ╚═════╝╚═╝  ╚═╝
    {DETAIL}v2.0

    {RST}"""
    )
    print(f"{INFO}[*] Input:\t{DETAIL}{input_file}{RST}")
    print(f"{INFO}[*] Output:\t{DETAIL}{output_file}{RST}")

    checks = ""
    if args.all:
        checks = "all"
    else:
        for x in vars(args):
            if x != 'input' and x != 'output':
                y = getattr(args, x)
                if y:
                    checks = checks + x + " "
    print(f"{INFO}[*] Checks:\t{DETAIL}{checks}{RST}")


def get_hosts(input_file):

    hosts = []
    hosts_x = []
    # check if a file exists with that name
    if os.path.exists(input_file):
        with open(input_file, "r") as f:
            for host in f:
                hosts_x.append(host.strip())
        for x in hosts_x:
            if ".0/" in x:
                expanded = ipaddress.IPv4Network(x, strict=False)
                for ex in expanded:
                    hosts.append(str(ex))
            else:
                hosts.append(x.strip())

    # if the file doesnt exist, assume we've just been given one host
    # multiple host separated by commas or a CIDR range
    else:
        # if we've got multiple entries
        if "," in input_file:
            hosts_multiple_entries = input_file.split(",")
            for entry in hosts_multiple_entries:
                entry = entry.strip()
                # if we've got a cidr range in the entries
                if ".0/" in entry:
                    expanded = ipaddress.IPv4Network(entry, strict=False)
                    for ex in expanded:
                        hosts.append(str(ex))
                else:
                    hosts.append(entry)
        # if its just a cidr range, expand it and add them to 'host_list'
        elif ".0/" in input_file:
            hosts = ipaddress.IPv4Network(input_file.strip(), strict=False)
        # if its single, just add a single item to 'host_list'
        else:
            hosts.append(input_file)
    return hosts


def scan_hosts(hosts):
    
    for host in hosts:
        # if all option has been chosen
        if args.all:
            print("")
            # check if host is up before checking
            is_it_up = check_alive(host)
            if is_it_up:
                check_tls(host)
                check_sslv2(host)
                check_sslv3(host)
                check_certs(host)
                check_csp(host)
                check_hsts(host)
        # otherwise, do invidivual chosen checks
        else:
            print("")
            # check if host is up before checking
            is_it_up = check_alive(host)
            if is_it_up:
                if args.tls:
                    check_tls(host)
                if args.sslv2:
                    check_sslv2(host)
                if args.sslv3:
                    check_sslv3(host)
                if args.certs:
                    check_certs(host)
                if args.csp:
                    check_csp(host)
                if args.hsts:
                    check_hsts(host)
                else:
                    pass


def check_alive(host):

    result = subprocess.run(f"curl -m 1 -k --silent -fail --show-error https://{host}", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    output = result.stderr.decode('utf-8')
    print(f"{INFO}[*] {DETAIL}{host}")
    if "Connection timed out" in output or "Failed to connect to" in output:
        print(f"{BAD}[-] Host is down{RST}")
        print(output)
        return False
    else:
        print(f"{GOOD}[+] Host is up{RST}")
        print(output)
        return True


def check_csp(host):

    data = {"URL": "https://" + host}
    r = requests.post("https://csper.io/api/evaluations", json=data)

    if "no policies found at URL" in r.text:
        print(f"{BAD}[-] No CSP found{RST}")
        all_csp.append(host)
    else:
        print(f"{GOOD}[+] CSP found{RST}")
    debug_print(r.text)

def check_hsts(host):

    stream = os.popen(f"curl --connect-timeout 5 -L -s -k -I https://{host}")
    output = stream.read().lower()
    if "strict-transport-security" in output:
        print(f"{GOOD}[+] HSTS is enabled{RST}")
    # if we dont get anything the first time, try the other curl command
    else:
        stream = os.popen(f"curl --connect-timeout 5 -s -D- -L https://{host}")
        output = stream.read().lower()
        if "strict-transport-security" in output:
            print(f"{GOOD}[+] HSTS is enabled{RST}")
        else:
            print(f"{BAD}[-] HSTS is not enabled{RST}")
            all_hsts.append(host)
    debug_print(output)

def check_tls(host):

    stream = os.popen(f"sslscan --connect-timeout=5 --no-cipher-details --no-compression --no-fallback --no-groups --no-heartbleed --no-renegotiation --no-check-certificate --no-ciphersuites --tlsall --no-colour {host}")
    output = stream.read()
    # if both are disabled
    if "TLSv1.0   disabled" in output and "TLSv1.1   disabled" in output:
        print(f"{GOOD}[+] TLSv1.0 and TLSv1.1 are disabled{RST}")
    # if 1.0 is enabled but 1.1 is disabled
    elif "TLSv1.0   enabled" in output and "TLSv1.1   disabled" in output:
        print(f"{BAD}[-] TLSv1.0 is enabled but TLSv1.1 is disabled{RST}")
        host = host.rstrip() + " - TLSv1"
        all_tls.append(host)
    # if 1.1 is enabled but 1.0 is disabled
    elif "TLSv1.1   enabled" in output and "TLSv1.0   disabled" in output:
        print(f"{BAD}[-] TLSv1.1 is enabled but TLSv1.0 is disabled{RST}")
        host = host.rstrip() + " - TLSv1.1"
        all_tls.append(host)
    # if both are enabled
    elif "TLSv1.0   enabled" in output and "TLSv1.1   enabled" in output:
        print(f"{BAD}[-] TLSv1.0 and TLSv1.1 are enabled{RST}")
        host = host.rstrip() + " - TLSv1.0, TLSv1.1"
        all_tls.append(host)
    debug_print(output)


def check_sslv2(host):

    stream = os.popen(f"sslscan --connect-timeout=5 --no-cipher-details --no-compression --no-fallback --no-groups --no-heartbleed --no-renegotiation --no-check-certificate --no-ciphersuites --ssl2 --no-colour {host}")
    output = stream.read()
    if "SSLv2     disabled" in output:
        print(f"{GOOD}[+] SSLv2 is disabled{RST}")
    elif "SSLv2     enabled" in output:
        print(f"{BAD}[-] SSLv2 is enabled{RST}")
        all_sslv2.append(host)
    debug_print(output)


def check_sslv3(host):

    stream = os.popen(f"sslscan --connect-timeout=5 --no-cipher-details --no-compression --no-fallback --no-groups --no-heartbleed --no-renegotiation --no-check-certificate --no-ciphersuites --ssl3 --no-colour {host}")
    output = stream.read()
    if "SSLv3     disabled" in output:
        print(f"{GOOD}[+] SSLv3 is disabled{RST}")
    elif "SSLv3     enabled" in output:
        print(f"{BAD}[-] SSLv3 is enabled{RST}")
        all_sslv3.append(host)
    debug_print(output)


def check_certs(host):

    stream = os.popen(f"sslscan --connect-timeout=5 --no-compression --no-fallback --no-groups --no-heartbleed --no-renegotiation --no-colour {host}")
    output = stream.read()
    if "RC4" in output:
        print(f"{BAD}[-] Host allows RC4{RST}")
        all_rc4.append(host)
    if "DES-CBC" in output:
        print(f"{BAD}[-] Host allows DES-CBC{RST}")
        all_cbc.append(host)
    elif "Certificate information cannot be retrieved." in output:
        print(f"{BAD}[-] tFailed to get cert info")
    else:
        print(f"{GOOD}[+] Certs are OK{RST}")
    debug_print(output)


def write_hosts(output_file):

    f = open(output_file, "w")
    if args.csp:
        f.write("Hosts without CSP\n")
        for line in all_csp:
            f.write(line + "\n")
        f.write("\n")
    if args.hsts:
        f.write("Hosts without HSTS\n")
        for line in all_hsts:
            f.write(line + "\n")
        f.write("\n")
    if args.tls:
        f.write("Hosts with TLS issues\n")
        for line in all_tls:
            f.write(line + "\n")
        f.write("\n")
    if args.sslv2:
        f.write("Hosts with SSLv2\n")
        for line in all_sslv2:
            f.write(line + "\n")
        f.write("\n")
    if args.sslv3:
        f.write("Hosts with SSLv3\n")
        for line in all_sslv3:
            f.write(line + "\n")
        f.write("\n")
    if args.certs:
        f.write("Hosts with cert issues\n")
        issues = {}
        for line in all_rc4:
            issues[line] = " - RC4"
        for line in all_cbc:
            # if the entry is already in there for RC4:
            if line in issues:
                # update the entry to include both
                issues[line] = " - RC4, DES-CBC"
            # otherwise
            else:
                # add it to the dict with just DES-CBC
                issues[line] = " - DES-CBC"
            f.write(line.rstrip() + issues[line] + "\n")
        f.write("\n")
    f.close()


def debug_print(message):

    if args.debug:
        print(message)
    return


# main
banner(args)
hosts = get_hosts(input_file)
scan_hosts(hosts)
write_hosts(output_file)
print(f"{INFO}\n[*] Finished{RST}")
