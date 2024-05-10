import subprocess
import os
from rich import print

# On vérifie si Metasploit RPC est lancé ou non
def is_msfrpcd_running():
    output = subprocess.check_output(["ps", "aux"]).decode("utf-8")
    if "msfrpcd" not in output:
        print("[bold yellow][!] msfrpcd n'est pas en cours d'exécution. Démarrage de Metasploit RPC.[/bold yellow]")
        os.system('msfrpcd -P msf') 
    elif "msfrpcd" in output:
        print("[bold green][+] msfrpcd est en cours d'exécution.[/bold green]")

