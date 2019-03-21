import sys
import time
import multiprocessing
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
from prettytable import PrettyTable


def scan(port):
    
    global openp
    
    src_port = RandShort()
    p = IP(dst=ip)/TCP(sport=src_port, dport=port, flags='S')
    resp = sr1(p, timeout=2)
    
    if str(type(resp)) == "<class 'NoneType'>":
        return -1
    
    elif resp.haslayer(TCP):
    
        if resp.getlayer(TCP).flags == 0x12:
            send_rst = sr(IP(dst=ip)/TCP(sport=src_port, dport=port, flags='AR'), timeout=1)
            return port
            

def is_up(ip):
    p = IP(dst=ip)/ICMP()
    resp = sr1(p, timeout=10)
    if resp == None:
        return False
    elif resp.haslayer(ICMP):
        return True

# Prompt #
if __name__ == '__main__':

    try:
        # Interface a ser escaneada
        interface = "enp0s3"
        print("[*] Interface: enp0s3")

        # IP(s) a ser(em) escaneado(s)
        ips = "192.168.2.0/24"
        print("[*] Range of IPs: 192.168.2.0/24")

    # Saida do Prompt
    except KeyboardInterrupt:
        print("\n[*] User Requested Shutdown")
        print("[*] Quitting...")
        sys.exit(1)

    # Escaneamento em si #

    print("\n[*] Scanning...")

    # Marcação para duração do escaneamento
    start_time = time.time()

    # Inicio do escaneamento
    conf.verb = 0
    ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ips), timeout=2, iface=interface, inter=0.1)

    # Resultado #

    # Tabela com os resultados
    table = PrettyTable(['IP', 'MAC', 'MAC Vendor', 'Online', 'Open Ports'])

    for snd, rcv in ans:

        # Printa o IP e o MAC
        ip = rcv.sprintf("%ARP.psrc%")
        mac = rcv.sprintf("%Ether.src%")

        # Obtem a porcao do vendor do endereco MAC (retirando os :)
        vendor = rcv.sprintf("%Ether.src%")
        vendor = vendor.replace(":", "")

        # Procura e printa o Vendor
        with open('oui.txt', 'r') as file:
            for line in file:

                # Procura os digitos reservados para o Vendor no arquivo e obtem a linha
                if vendor.upper()[:6] in line:

                    # Posicao do Vendor na linha
                    mac_vendor = line[22:-1]
                    break

        # Fecha o arquivo de Vendors
        file.close()

        # Printa as portas abertas
        conf.verb = 0
        closed = 0
        start_time = time.time()
        ports = range(1, 1024)
        pool = multiprocessing.Pool(processes=multiprocessing.cpu_count()*10)

        list_open_ports = []

        online = is_up(ip)

        if online:
            results = [pool.apply_async(scan, (port,)) for port in ports]
            
            for result in filter(lambda i : i.get() != None, results):

                if result.get() > 0:
                    list_open_ports.append(str(result.get()))

            open_ports = ' '.join(list_open_ports)

        else:
            open_ports = " "

        table.add_row([str(ip), str(mac), str(mac_vendor), str(online), str(open_ports)])

        print(table)

    # Marcação para duração do escaneamento
    stop_time = time.time()

    # Duração do escaneamento
    total_time = stop_time - start_time

    print("\n[*] Scan Complete!")
    print("[*] Scan Duration: %s" % total_time)