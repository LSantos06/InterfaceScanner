# -*- coding: utf-8 -*-
"""Escaneador de interface.

Este modulo realizar o escaneamento de uma dada interface, printando dados como:
Endereco IP; Endereco MAC; Empresa que possui o endereco MAC; E portas abertas de
cada host da rede.

Example:
    Para executar o codigo, basta utiliza-lo como argumento do interpretador python (como superuser):

        $ sudo python interface_scanner.py

Todo:
    * 

.. _Google Python Style Guide:
   http://google.github.io/styleguide/pyguide.html

"""

import sys
import time
import multiprocessing
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
from prettytable import PrettyTable


def scan(port):
    """Realiza o teste de uma porta do host.

    Envia um pacote TCP para verificar se a porta do host esta aberta,
    retornando um codigo de erro caso a mesma esteja fechada, e o 
    numero da porta se a porta esta aberta.

    Args:
        port (int): Porta a ser testada.

    Returns:
        port (int): Numero da porta se a mesma esta aberta.

    """

    # Envia o pacote de teste e armazena o resultado
    #   Porta de origem aleatoria
    #   Pacote em si
    #   Envio do pacote    
    src_port = RandShort()
    p = IP(dst=ip)/TCP(sport=src_port, dport=port, flags='S')
    resp = sr1(p, timeout=2)
    
    # Se não obteve pacote de resposta retorna codigo de erro
    if str(type(resp)) == "<class 'NoneType'>":
        return -1
    
    # Pacote de resposta bem sucedido
    elif resp.haslayer(TCP):
    
        # Se a porta esta aberta
        #   Envia pacote de reset
        #   Retorna o numero da porta 
        if resp.getlayer(TCP).flags == 0x12:
            send_rst = sr(IP(dst=ip)/TCP(sport=src_port, dport=port, flags='AR'), timeout=1)
            return port
            

def is_up(ip):
    """Verifica se o host esta online.

    Envia um pacote ICMP para verificar se o host esta online.

    Args:
        ip (int): Porta a ser testada.

    Returns:
        bool: Representa o estado online do host testado.

    """

    # Envia o pacote de teste e armazena o resultado
    #   Pacote em si
    #   Envio do pacote    
    p = IP(dst=ip)/ICMP()
    resp = sr1(p, timeout=10)
    
    # Se nao obteve resposta
    #   Retorna Falso
    if resp == None:
        return False

    # Se obteve resposta
    #   Retorna Verdadeiro
    elif resp.haslayer(ICMP):
        return True


if __name__ == '__main__':

    # Interface a ser escaneada
    interface = input("[*] Interface: ")

    # Range de IPs a serem escaneados
    ips = input("[*] Range of IPs: ")

    # Inicio do escaneamento
    #   Marcacao temporal do inicio do escaneamento
    print("\n[*] Scanning...")
    start_time = time.time()

    # Escaneamento ARP
    #   Configuracao de verbose
    #   Separacao dos ARPs em respondidos e nao respondidos
    conf.verb = 0
    ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ips), timeout=2, iface=interface, inter=0.1)

    # Tabela com os resultados
    table = PrettyTable(['IP', 'MAC', 'MAC Vendor', 'Online', 'Open Ports'])

    # Percorre ARPs respondidos
    for snd, rcv in ans:

        # Armazenamento do Endereco IP
        ip = rcv.sprintf("%ARP.psrc%")

        # Armazenamento do Endereco MAC
        mac = rcv.sprintf("%Ether.src%")

        # Armazenamento do Vendor MAC
        #   Obtem o endereco MAC
        #   Obtem a porcao do vendor do endereco MAC (retirando os :)
        vendor = rcv.sprintf("%Ether.src%")
        vendor = vendor.replace(":", "")
        # Abre o arquivo de Vendors MAC
        with open('oui.txt', 'r') as file:
            # Percorre cada linha do arquivo
            for line in file:
                # Obtem a linha com os 6 digitos reservados para o Vendor do endereco MAC
                if vendor.upper()[:6] in line:
                    # Obtem o Vendor do endereco MAC
                    mac_vendor = line[22:-1]
                    break
        # Fecha o arquivo de Vendors MAC
        file.close()

        # Armazenamento das portas abertas
        #   Portas a serem escaneadas para o host
        #   Multiprocessamento no teste das portas para maior velocidade
        #   Lista de portas abertas para o host
        #   Resultado da verificacao do status do host (Online ou Offline)
        ports = range(1, 1024)
        pool = multiprocessing.Pool(processes=multiprocessing.cpu_count()*10)
        list_open_ports = []
        online = is_up(ip)
        # Se o host esta online
        if online:
            # Armazena o resultado do escaneamento das portas em uma lista
            results = [pool.apply_async(scan, (port,)) for port in ports]
            # Percorre a lista de resultado, filtrando os valores não None
            for result in filter(lambda i : i.get() != None, results):
                # Obtem as portas sem codigo de erro
                if result.get() > 0:
                    # Armazena as portas abertas em uma lista
                    list_open_ports.append(str(result.get()))
            # Transforma a lista de portas abertas em uma string para impressao
            open_ports = ' '.join(list_open_ports)
        # Se o host esta offline
        else:
            # String vazia para impressao
            open_ports = " "

        # Tabela de impressao
        #   Adiciona a linha com todas as infos do host em uma tabela de impresao
        #   Imprime a tabela
        table.add_row([str(ip), str(mac), str(mac_vendor), str(online), str(open_ports)])
        print(table)

    # Duração do escaneamento
    #   Marcacao temporal do fim do escaneamento
    #   Calculo da duracao total do escaneamento
    stop_time = time.time()
    total_time = stop_time - start_time
    print("\n[*] Scan Complete!")
    print("[*] Scan Duration: %s" % total_time)
