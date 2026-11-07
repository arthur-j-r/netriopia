from scapy.all import *
from scapy.layers.inet import IP
from concurrent.futures import ThreadPoolExecutor  
import socket
import threading
conf.use_pcap = True


count = 0
lista_catalogados = []
def find_iface():
    try:
        with open("iface.txt", "r") as f:
            iface = f.read().strip()
            if iface in interfaces:
                return iface
    except FileNotFoundError:
        interfaces = get_if_list()     
        for iface in interfaces:
            if "Loopback" in iface:
                continue  
            try:
                pacotes = sniff(iface=iface, filter="ip", timeout=3, count=3)
                if len(pacotes) > 0:
                    with open("iface.txt", "w") as f:
                        f.write(iface)
                    return iface
                else:
                    print(f"[-] Nenhum tráfego detectado nesta interface neste intervalo.")
            except Exception as e:
                print(f"[-] Erro ao testar esta interface: {e}")

        print("[+] Varredura concluída.")
def processar_pacote(pacote):
    global count
    global lista_catalogados
    if IP in pacote:
        if not pacote[IP].src.startswith("192.168."):
            if not pacote[IP].src in lista_catalogados:
                lista_catalogados.append(pacote[IP].src)
                print(f'-> Pacote capturado: {pacote[IP].src} -> {pacote[IP].dst}')
                count += 1
def reverse_dns_lookup():
    global lista_catalogados
    lista_hostnames = {}

    def resolver(ip):
        try:
            return ip, socket.gethostbyaddr(ip)[0]
        except socket.herror:
            return ip, "Desconhecido"
        except Exception:
            return ip, "Erro"

    with ThreadPoolExecutor(max_workers=10) as executor:
        resultados = executor.map(resolver, lista_catalogados)
        for ip, hostname in resultados:
            lista_hostnames[ip] = hostname
            
    return lista_hostnames

if __name__ == "__main__":
    interface_correta = find_iface()
    sniff(iface=interface_correta, prn=processar_pacote, filter="ip",stop_filter = lambda x: count == 10)
    lista_hostnames = reverse_dns_lookup()
    for ip, hostname in lista_hostnames.items():
        print(f"-> IP: {ip} -> Hostname: {hostname}")

    print("-> Captura finalizada com sucesso!")