import pyshark

#cap= pyshark.FileCapture('../captures/test1v2.pcapng', only_summaries=False) # messages
#cap= pyshark.FileCapture('../captures/test_2_v2.pcapng', only_summaries=False) # fichiers
#cap= pyshark.FileCapture('../captures/test2v2.pcapng', only_summaries=False)
#cap= pyshark.FileCapture('../captures/test_3_v2.pcapng', only_summaries=False) # vidéos
#cap= pyshark.FileCapture('../captures/test3v2.pcapng', only_summaries=False)
#cap= pyshark.FileCapture('../captures/test_4_v2.pcapng', only_summaries=False) # vocal
cap= pyshark.FileCapture('../captures/test4v2.pcapng', only_summaries=False)

def add_dic(dico, elem):
    if dico.get(elem):
        dico[elem] += 1
    else:
        dico[elem] = 1
    return

def addr_private(addr):
    if addr[:7] == "192.168":
        return True
    else:
        return False

def nat_addr(addr):
    box = ""
    for pkt in cap:
        for i in pkt.layers:
            if i.layer_name == 'ip':
                ip_layer = pkt[i.layer_name]
                if ip_layer.dst == addr:
                    if addr_private(ip_layer.addr):
                        box = ip_layer.src
    return box


# Adresse privée trouvée avec la commane ifconfig -a (192.168.129.79 ou 192.168.0.100 )
# Adresse privée de la passerelle NAT trouvée avec la commande arp -a

"""
box_private = nat_addr("192.168.129.79")
print(f"Adresse privée IPv4 de la passerelle NAT : {box_private}")
print("====================")
"""

class_type = dict()
method_type = dict()
error_type = dict()
version_type = dict()
transport = dict()
port_src_udp = dict()
port_dst_udp = dict()
port_src_tcp = dict()
port_dst_tcp = dict()


for pkt in cap:
    for i in pkt.layers:
        if i.layer_name == 'ip':
            ip_layer = pkt[i.layer_name]
            for j in pkt.layers:
                if j.layer_name == 'stun':

                    name_transport = pkt.transport_layer
                    trans_layer = pkt[pkt.transport_layer]
                    add_dic(transport, name_transport)

                    if name_transport == 'UDP':
                        add_dic(port_src_udp, trans_layer.port)
                        add_dic(port_dst_udp, trans_layer.dstport)
                    else:
                        add_dic(port_src_tcp, trans_layer.port)
                        add_dic(port_dst_tcp, trans_layer.dstport)

                    stun_layer = pkt[j.layer_name]

                    name_class = stun_layer.type_class.showname_value
                    name_method = stun_layer.type_method.showname_value
                    add_dic(class_type, name_class)
                    add_dic(method_type, name_method)

                    if stun_layer.type_class.show != '0x0000':
                        name_version = stun_layer.network_version.showname_value
                        add_dic(version_type, name_version)

                    if stun_layer.type_class.show == '0x0011':
                        add_dic(error_type, stun_layer.att_error_reason)

print("====================")
print("Protocole de transport utilisé: ", transport)
print("Version stun utilisées: ", version_type)
print("Types des requêtes stun : ", class_type)
print("Méthodes des requêtes stun : ", method_type)
print("Types d'erreurs : ", error_type)
print("Port sources stun sur udp : ", port_src_udp)
print("Port de destination stun sur udp : ", port_dst_udp)
print("Port sources stun sur tcp : ", port_dst_tcp)
print("Port de destination stun sur tcp : ", port_dst_tcp)
print("====================")
