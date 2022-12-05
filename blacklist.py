import pydnsbl

print("----------BLACKLIST---------")
ip_checker = pydnsbl.DNSBLIpChecker()

text_file = "target-ips.txt"
f = open(text_file)
for i in f:
    i = str.rstrip(i)
    print(ip_checker.check(str(i)))

f.close()
