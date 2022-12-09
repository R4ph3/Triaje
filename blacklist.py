import subprocess, sys

print("---------BLACKLIST-------")
p = subprocess.Popen(["powershell.exe", 
              "C:\\Users\\rafael.barber\\Desktop\\Analizador\\blacklist.ps1"], 
              stdout=sys.stdout)
p.communicate()