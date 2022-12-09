import subprocess, sys

print("---------BLACKLIST-------")
p = subprocess.Popen(["powershell.exe", 
              "ruta_con_archivo_powershell_blacklist.ps1"], 
              stdout=sys.stdout)
p.communicate()
