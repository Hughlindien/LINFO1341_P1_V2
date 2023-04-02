import subprocess
import re
import pyshark

cap= pyshark.FileCapture('../Captures/test_1_messages.pcapng', only_summaries=False)

def addr_private(addr):
    if addr[:7] == "192.168":
        return True
    else:
        return False

box_private = set()

for pkt in cap:
    for i in pkt.layers:
        if i.layer_name == 'ip':
            ip_layer = pkt[i.layer_name]
            if ip_layer.dst == "192.168.129.79" or ip_layer.dst == "192.168.129.255": # Trouvée avec la commane ifconfig -a
                if addr_private(ip_layer.addr):
                    box_private.add(ip_layer.src)
print("====================")

print(f"adresse privée de la passerelle NAT : {box_private}") # Vérification avec la commande arp -a