from flask import Flask, request, jsonify, render_template
import socket
import threading
import requests
import csv
import json
import os
import platform
import subprocess
import re

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
    65535: "Dynamic End",
    2000: "Cisco SCCP (Skinny Call Control Protocol) – Used for VoIP communication.",
    5060: "SIP (Session Initiation Protocol) – Used for VoIP calling (Zoom, Skype, etc.).",
    6160: "Sometimes used for custom applications, potential security risk if unknown.",
    6162: "Used for internal communication in some applications, could be malware-controlled."
}

def extract_domain(target):
    """Extract domain name from a URL if needed"""
    target = target.lower()
    if target.startswith("http://") or target.startswith("https://"):
        target = re.sub(r"https?://", "", target)  # Remove http:// or https://
    target = target.split("/")[0]  # Remove anything after a /
    return target

def get_geolocation(ip):
    url = f"https://ipinfo.io/{ip}/json"
    try:
        response = requests.get(url, headers={"User-Agent": "Mozilla/5.0"}, timeout=3)
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
    except:
        pass
    return {"error": "Geolocation lookup failed"}

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
                ttl_value = int(re.search(r"TTL=(\d+)", line, re.IGNORECASE).group(1))
                break
        
        if ttl_value:
            if ttl_value <= 64:
                return "Linux/Unix-based OS"
            elif 65 <= ttl_value <= 128:
                return "Windows OS"
            elif ttl_value > 128:
                return "Network Device (Router/Switch)"
        return "Unknown OS"
    except:
        return "OS detection failed"

def scan_port(ip, port, results):
    """Scan a port to check if it's open and fetch its description"""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(0.5)
            if sock.connect_ex((ip, port)) == 0:
                port_desc = common_ports.get(port, "Unknown Service")
                results.append({"port": port, "service": port_desc, "status": "Open"})
    except:
        pass


@app.route("/")
def home():
    return render_template("index.html")

@app.route("/scan", methods=["POST"])
def scan():
    """Perform a port scan on the given target"""
    data = request.json
    target = data.get("target")
    ports_to_scan = int(data.get("ports", 100))
    
    if not target:
        return jsonify({"error": "No target specified"}), 400
    
    target = extract_domain(target)
    
    try:
        target_ip = socket.gethostbyname(target)
    except:
        return jsonify({"error": "Invalid domain or IP"}), 400
    
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

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
