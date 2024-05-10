import nmap
import re
from rich import print

# Scan avec null packets pour la découverte d'hôtes (-sN)
def nmap_ping_scan(subnet):
    nm = nmap.PortScanner()
    nm.scan(hosts=subnet, arguments='-sn')
    live_hosts = []
    for host in nm.all_hosts():
        if nm[host].state() == 'up':
            live_host_info = {'host': host}
            live_hosts.append(live_host_info)
    return live_hosts

# Scan de version (-sV) + script nmap pour la récupération d'information HTTP intéressante
def nmap_service_scan(hosts):
    nm = nmap.PortScanner()
    for host_info in hosts:
        host = host_info['host']
        result = nm.scan(hosts=host, arguments='-sV -p21,3000,8080,9080 --script http-enum')  
        if nm[host].state() == 'up':
            services = nm[host]['tcp']
            host_info['services'] = {}
            for port, service_info in services.items():
                name = service_info.get('name', '')
                product = service_info.get('product', '')
                version = service_info.get('version', '')
                http_server_header = service_info.get('script', {}).get('http-server-header', '')
                http_enum = service_info.get('script', {}).get('http-enum', '')
                host_info['services'][port] = {
                    'name': name,
                    'product': product,
                    'version': version,
                    'http_server_header': http_server_header,
                    'http_enum': http_enum
                   }
                if name == 'ftp' and product == 'vsftpd' and version == '2.3.4':  
                    print(f"[yellow][!][/yellow] ⚙️ Service vsftpd 2.3.4 détecté sur [yellow]{host}:{port}[/yellow] semble vulnérable")
                if product == 'OpenResty web app server' and 'APISIX/2.11.0' in http_server_header:  
                    print(f"[yellow][!][/yellow] ⚙️ Service Apisix détecté sur [yellow]{host}:{port}[/yellow] semble vulnérable")
                if name == 'http' and 'Jetty(11.0.14)' in http_server_header:
                    print(f"[yellow][!][/yellow] ⚙️ Service Metabase Jetty détecté sur [yellow]{host}:{port}[/yellow] semble vulnérable")

        host_info['scan_output'] = result  # On sauvegarde l'output du scan
    return hosts
