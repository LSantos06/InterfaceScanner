import sys
from datetime import datetime
from scapy.all import srp, conf, ARP, Ether

# Prompt #

try:
    # Interface a ser escaneada
    interface = "enp0s3"
    print("[*] Interface: enp0s3")

    # IP(s) a ser(em) escaneado(s)
    ips = "192.168.2.0/24"
    print("[*] Range of IPs: 192.168.2.0/24")

# Saida do prompt
except KeyboardInterrupt:
    print("\n[*] User Requested Shutdown")
    print("[*] Quitting...")
    sys.exit(1)

# Escaneamento em si #

print("\n[*] Scanning...")

# Marcação para duração do escaneamento
start_time = datetime.now()

# Inicio do escaneamento
conf.verb = 0
ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ips), timeout=2, iface=interface, inter=0.1)

# Resultado #

print("IP      \tMAC\t                Vendor\n")

for snd, rcv in ans:

    # Printa o IP e o MAC
    print(rcv.sprintf("%ARP.psrc%\t%Ether.src%"), end='\t')

    # Obtem a porcao do vendor do endereco MAC (retirando os :)
    vendor = rcv.sprintf("%Ether.src%")
    vendor = vendor.replace(":", "")

    # Procura e printa o Vendor
    with open('oui.txt', 'r') as file:
        for line in file:

            # Procura os digitos reservados para o Vendor no arquivo e obtem a linha
            if vendor.upper()[:6] in line:

                # Posicao do Vendor na linha
                print(line[22:-1])
                break

    # Fecha o arquivo de Vendors
    file.close()

    # Printa as portas abertas

# Marcação para duração do escaneamento
stop_time = datetime.now()

# Duração do escaneamento
total_time = stop_time - start_time

print("\n[*] Scan Complete!")
print("[*] Scan Duration: %s" % total_time)