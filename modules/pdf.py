import os
from weasyprint import HTML
from rich import print

def generate_pdf_report(subnet, live_hosts, pdf_filename):
    # Initialisation du contenu HTML avec l'en-tête
    html_content = f"""
    <h1 style="font-size: 24px;">Rapport d'audit pour le sous-réseau : {subnet} 📋</h1>
    <h2>Table des matières</h2>
    <ul>
        <li><a href="#retr">Hôtes retrouvés 🔎</a></li>
        <li><a href="#live_hosts">Hôtes vulnérables ⚠️</a></li>
    </ul>
    <hr>
    <h2 id="retr">Hôtes retrouvés 🔎</h2>
    <table border="1">
        <tr>
            <th>Hôtes trouvés lors du scan</th>
        </tr>
    """
    # Ajouter chaque hôte actif à la catégorie Portée dans un tableau
    for host_info in live_hosts:
        host = host_info['host']
        html_content += f"<tr><td>{host}</td></tr>"
    html_content += """
    </table>
    <div style='page-break-after: always;'></div>    
    <h2 id="live_hosts">Hôtes vulnérables ⚠️</h2>
    """
    # Ajouter uniquement les hôtes actifs avec des vulnérabilités au contenu HTML
    for host_info in live_hosts:
        host = host_info['host']
        services = host_info.get('services', {})
        for port, service in services.items():
            if service['name'] == 'ftp' and service['product'] == 'vsftpd' and service['version'] == '2.3.4':
                html_content += f"""
                <h3>- Hôte : {host}</h3>
                <ul>
                    <li>Port : {port}, Protocole : {service['name']}, Service : {service['product']} {service['version']}</li>
                </ul>
                <h4>CVE-2011-2523</h4>
                <p>Cette backdoor permet aux attaquants d'exécuter du code à distance en tant que root.</p>
                <h4>Étapes de Remédiation :</h4>
                <p>1. Appliquer la denière mise à jour de vsftpd.</p>
                <p>2. Restreindre l'accès réseau aux services vulnérables.</p>
                """
            if service['product'] == 'OpenResty web app server' and 'APISIX/2.11.0' in service['http_server_header']:
                html_content += f"""
                <h3>- Hôte : {host}</h3>
                <ul>
                    <li>Port : {port}, Protocole : {service['name']}, Service : {service['product']} {service['http_server_header']}</li>
                </ul>
                <h4>CVE-2020-13945</h4>
                <p>Cette vulnérabilité permet aux attaquants d'avoir une éxecution de code à distance.</p>
                <h4>Étapes de Remédiation :</h4>
                <p>1. Mettre à jour Apache APISIX vers la dernière version.</p>
                <p>2. Restreindre l'accès réseau aux services vulnérables.</p>
                """
            if service['name'] == 'http' and 'Jetty(11.0.14)' in service['http_server_header']:
                html_content += f"""
                <h3>- Hôte : {host}</h3>
                <ul>
                    <li>Port : {port}, Protocole : {service['name']}, Service : Jetty {service['http_server_header']}</li>
                </ul>
                <h4>CVE-2023-38646</h4>
                <p>Cette vulnérabilité permet aux attaquants d'effectuer une injection de commande non authentifié.</p>
                <h4>Étapes de Remédiation :</h4>
                <p>1. Mettre à jour Metabase vers la dernière version.</p>
                <p>2. Restreindre l'accès réseau aux services vulnérables.</p>
                """
    
    # Définir le nom et le chemin du fichier PDF
    pdf_path = os.path.join(os.getcwd(), f"{pdf_filename}")
    # Générer le PDF à partir du contenu HTML
    HTML(string=html_content).write_pdf(pdf_path)
    print("")
    print(f"[green bold][+][/green bold] Rapport d'audit généré : [green bold]{pdf_path}[/green bold]")
    print("")
