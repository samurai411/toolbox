# PENTEST TOOLBOX V1 🛠️

Cet outil a été conçu pour faciliter les tests de pénétration en automatisant certaines tâches courantes et en fournissant une interface conviviale pour l'exploitation des vulnérabilités.

![](https://github.com/samurai411/toolbox/blob/main/exploit.gif)

## Installation ⚙️

Clonez ce dépôt sur votre machine locale:
``` bash
git clone https://github.com/samurai411/toolbox.git
```

##### Debian 🍥

Installez les paquets nmap, netcat et procps:
``` sh
sudo apt install nmap procps netcat-traditional python3-pip libpango-1.0-0 libpangoft2-1.0-0 -y
```

Installez les dépendances pour Metasploit:
``` sh
sudo apt install curl gpgv2 autoconf bison build-essential postgresql libaprutil1 libgmp3-dev libpcap-dev openssl libpq-dev libreadline6-dev libsqlite3-dev libssl-dev locate libsvn1 libtool libxml2 libxml2-dev libxslt-dev wget libyaml-dev ncurses-dev  postgresql-contrib xsel zlib1g zlib1g-dev curl -y
```

Entrez la commande suivante pour ajouter le dépôt Metasploit and installer le framework:
``` sh
curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > msfinstall && chmod 755 msfinstall && ./msfinstall
```

Initial setup de Metasploit:
``` sh
msfconsole
```
##### Arch Linux

Installez les différents paquets dont Metasploit:
``` sh
sudo pacman -S metasploit nmap procps-ng netcat python3-pip
```
Initial setup de Metasploit:
``` sh
msfconsole
```

Ensuite installez les dépendances Python en exécutant la commande suivante dans le répertoire du projet:
``` bash
pip install -r requirements.txt
```

## Utilisation

Exécutez le script principal main.py en spécifiant le sous-réseau que vous souhaitez scanner (-s), l'adresse et le port (-l et -p) sur lesquels vous souhaitez écouter pour le reverse shell (Si vous exploitez une CVE qui en utilise un).
La fonction d'output servira à donner un nom à votre rapport d'audit. 
``` bash
python3 toolbox.py -h
usage: python main.py -s [SUBNET] -h [HELP]

TOOLBOX V1 🧰

options:
  -s SUBNET, --subnet SUBNET
                        Sous-réseau à scanner pour les hôtes actifs
  -l LHOST, --lhost LHOST
                        Adresse local pour le reverse shell
  -p LPORT, --lport LPORT
                        Port local pour le reverse shell
  -P MSF_PORT, --msf_port MSF_PORT
                        Port MetasploCréation d'une vidéo GIFit RPC
  -mp MSF_PASS, --msf_pass MSF_PASS
                        Pass for Metasploit RPC
  -e, --exploit         Exploiter les CVEs
  -o OUTPUT, --output OUTPUT
                        Spécifier le nom du rapport PDF
  -h, --help            Affiche les options disponibles
```

## Fonctionnalités

- Découverte automatique des hôtes actifs dans un sous-réseau donné.
- Analyse des services exécutés sur les hôtes découverts.
- Génération d'un rapport PDF contenant les résultats de l'analyse.
- Exploitation automatisée des vulnérabilités détectées (CVE-2011-2523, CVE-2020-13945, CVE-2023-38646).

## Architecture

![](https://github.com/samurai411/toolbox/blob/main/archi.png)

## Gestion de projet

![](https://github.com/samurai411/toolbox/blob/main/gantt.png)

## Contribution

Les contributions sont les bienvenues! Si vous souhaitez proposer des améliorations, des corrections de bugs ou de nouvelles fonctionnalités, n'hésitez pas à ouvrir une issue ou à soumettre une pull request.


