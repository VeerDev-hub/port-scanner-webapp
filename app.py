from flask import Flask, request, jsonify, render_template
import socket
import threading
import requests
import csv
import json
import os
import platform
import subprocess

app = Flask(__name__)

common_ports = {
    20: "FTP Data",
    21: "FTP Control",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    26: "RSFTP",
    37: "Time Protocol",
    42: "Host Name Server",
    43: "WHOIS",
    53: "DNS",
    67: "DHCP (Server)",
    68: "DHCP (Client)",
    69: "TFTP",
    70: "Gopher",
    79: "Finger",
    80: "HTTP",
    88: "Kerberos",
    110: "POP3",
    111: "RPC",
    113: "Ident",
    119: "NNTP (Usenet)",
    123: "NTP",
    135: "MSRPC",
    137: "NetBIOS Name",
    138: "NetBIOS Datagram",
    139: "NetBIOS Session",
    143: "IMAP",
    161: "SNMP",
    162: "SNMP Trap",
    179: "BGP",
    194: "IRC",
    389: "LDAP",
    443: "HTTPS",
    445: "SMB",
    465: "SMTP over SSL",
    514: "Syslog",
    515: "LPD (Printer)",
    520: "RIP",
    587: "SMTP (Mail Submission)",
    631: "IPP",
    636: "LDAPS",
    873: "RSYNC",
    902: "VMware ESXi",
    989: "FTPS (Data)",
    990: "FTPS (Control)",
    993: "IMAPS",
    995: "POP3S",
    1080: "SOCKS Proxy",
    1194: "OpenVPN",
    1352: "Lotus Notes",
    1433: "MSSQL",
    1434: "MSSQL Monitor",
    1521: "Oracle DB",
    1723: "PPTP VPN",
    1812: "RADIUS Auth",
    1813: "RADIUS Accounting",
    1900: "SSDP",
    2049: "NFS",
    2052: "Cloudflare SSL Proxy",
    2053: "DNS over TLS (DoT)",
    2082: "cPanel",
    2083: "cPanel SSL",
    2086: "WHM/cPanel (Non-SSL)",
    2087: "WHM/cPanel (SSL)",
    2095: "cPanel Webmail (Non-SSL)",
    2096: "cPanel Webmail (SSL)",
    2181: "Apache Zookeeper",
    2375: "Docker API",
    2376: "Docker API SSL",
    2483: "Oracle DB (TCP)",
    2484: "Oracle DB (SSL)",
    3306: "MySQL",
    3389: "RDP",
    3690: "SVN",
    4000: "ICQ",
    4190: "ManageSieve",
    4333: "MSQL",
    4662: "eMule",
    5000: "UPnP",
    5432: "PostgreSQL",
    5672: "RabbitMQ",
    5900: "VNC",
    5984: "CouchDB",
    6000: "X11",
    6379: "Redis",
    6443: "Kubernetes API",
    6667: "IRC SSL",
    7000: "Kubernetes API Alt",
    7001: "WebLogic",
    7070: "RTSP",
    8080: "HTTP Proxy",
    8081: "HTTP Proxy Alt",
    8443: "HTTPS Alt",
    8880: "Alternate HTTP",
    9000: "PHP-FPM",
    9090: "OpenShift Console",
    9200: "Elasticsearch",
    9418: "Git",
    9999: "Minecraft",
    10000: "Webmin",
    11211: "Memcached",
    27017: "MongoDB",
    32768: "NFS",
    49152: "Dynamic Start",
    65535: "Dynamic End"
}


def get_geolocation(ip):
    url = f"https://ipinfo.io/{ip}/json"
    response = requests.get(url, headers={"User-Agent": "Mozilla/5.0"})
    
    if response.status_code == 200:
        data = response.json()
        return {
            "ip": data.get("ip", "Unknown"),
            "city": data.get("city", "Unknown"),
            "region": data.get("region", "Unknown"),
            "country": data.get("country", "Unknown"),
            "loc": data.get("loc", "Unknown"),
            "org": data.get("org", "Unknown"),
            "timezone": data.get("timezone", "Unknown"),
        }
    return None

def tcp_handshake(ip, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.5)
        sock.connect((ip, port))
        return True
    except:
        return False
    finally:
        sock.close()

def detect_os(ip):
    """ Perform OS detection using TTL value from a ping response """
    try:
        if platform.system().lower() == "windows":
            result = subprocess.run(["ping", "-n", "1", ip], capture_output=True, text=True)
        else:
            result = subprocess.run(["ping", "-c", "1", ip], capture_output=True, text=True)
        
        output = result.stdout
        ttl_value = None

        for line in output.split("\n"):
            if "TTL=" in line or "ttl=" in line:
                ttl_value = int(line.split("TTL=")[-1].split()[0]) if "TTL=" in line else int(line.split("ttl=")[-1].split()[0])

        if ttl_value:
            if ttl_value <= 64:
                return "Linux/Unix-based OS"
            elif 65 <= ttl_value <= 128:
                return "Windows OS"
            elif ttl_value > 128:
                return "Network Device (Router/Switch)"
            else:
                return "Unknown OS"
    except:
        return "OS detection failed"
    return "Unknown OS"


def detect_firewall(ip, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        sock.sendto(b"\x00" * 40, (ip, port))
        response = sock.recv(1024)
        if not response:
            return "Possible Firewall Detected"
    except:
        return "Possible Firewall Detected"
    finally:
        sock.close()
    return "No Firewall Detected"

def scan_port(ip, port, results):
    if tcp_handshake(ip, port):
        firewall_status = detect_firewall(ip, port)
        results.append({
            "port": port,
            "service": common_ports.get(port, "Unknown"),
            "status": "Open",
            "firewall": firewall_status
        })

@app.route("/")
def home():
    return render_template("index.html")

@app.route("/scan", methods=["POST"])
def scan():
    """ Perform a port scan on the given target """
    data = request.json
    target = data.get("target")
    ports_to_scan = int(data.get("ports", 100))

    try:
        socket.inet_aton(target)
        target_ip = target
    except socket.error:
        try:
            target_ip = socket.gethostbyname(target)
        except:
            return jsonify({"error": "Invalid IP or Domain"}), 400

    geolocation = get_geolocation(target_ip)
    os_detected = detect_os(target_ip)

    results = []
    threads = []
    for port in range(1, ports_to_scan + 1):
        thread = threading.Thread(target=scan_port, args=(target_ip, port, results))
        threads.append(thread)
        thread.start()
    
    for thread in threads:
        thread.join()

    return jsonify({"ip": target_ip, "geolocation": geolocation, "os": os_detected, "results": results})


@app.route("/")
def index():
    return render_template("index.html")

def get_location():
    user_ip = request.headers.get('X-Forwarded-For', request.remote_addr)
    location_data = get_geolocation(user_ip)
    return jsonify(location_data)

@app.route("/export", methods=["POST"])
def export_results():
    data = request.json
    results = data.get("results", [])
    file_type = data.get("type", "json")

    if file_type == "json":
        return jsonify(results)
    elif file_type == "csv":
        csv_data = "port,service,status,firewall\n"
        for entry in results:
            csv_data += f"{entry['port']},{entry['service']},{entry['status']},{entry['firewall']}\n"
        return csv_data, 200, {"Content-Type": "text/csv"}
    elif file_type == "txt":
        txt_data = "Port Scan Results:\n"
        for entry in results:
            txt_data += f"Port {entry['port']} ({entry['service']}) - {entry['status']} | {entry['firewall']}\n"
        return txt_data, 200, {"Content-Type": "text/plain"}
    else:
        return jsonify({"error": "Invalid export type"}), 400

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
