import subprocess
import re
import matplotlib.pyplot as plt
import numpy as np
import pyshark

#cap= pyshark.FileCapture('../captures/test1v2.pcapng', only_summaries=False) # messages
#cap= pyshark.FileCapture('../captures/test_2_v2.pcapng', only_summaries=False) # fichiers
#cap= pyshark.FileCapture('../captures/test2v2.pcapng', only_summaries=False)
#cap= pyshark.FileCapture('../captures/test_3_v2.pcapng', only_summaries=False) # vidéos
#cap= pyshark.FileCapture('../captures/test3v2.pcapng', only_summaries=False)
#cap= pyshark.FileCapture('../captures/test_4_v2.pcapng', only_summaries=False) # vocal
cap= pyshark.FileCapture('../captures/test4v2.pcapng', only_summaries=False)

# Adresse privée trouvée avec la commane ifconfig -a (192.168.129.79 ou 192.168.0.100)
# Adresse public trouvée avec la commane curl ifconfig.me (87.67.106.9 ou 85.201.100.227)
# Adresse privée de la passerelle NAT trouvée avec la commande arp -a (192.168.128.1 ou ?)
def addr_private(addr):
    if addr[:7] == "192.168":
        return True
    else:
        return False

def extract_domain(dom):
    domain = dom.split("//")[-1].split("/")[0]
    if '.' in domain:
        domain = '.'.join(domain.split('.')[-2:])
    return domain

def add_dic(dico, elem):
    if dico.get(elem):
        dico[elem] += 1
    else:
        dico[elem] = 1
    return

def whois_reg(dic_info, dic_final):
    for key in dic_info.keys():
        try:
            if key == '87.67.106.9' or key == '85.201.100.227':
                #add_dic(dic_final, "hosts address")
                pass

            out = subprocess.check_output(["whois", key], universal_newlines=True)
            reg = re.search(r"OrgName:\s*(.+)", out)
            reg2 = re.search(r"org-name:\s*(.+)", out)
            if reg:
                org_admin = reg.group(1)
                add_dic(dic_final, org_admin)
            if reg2:
                org_admin = reg2.group(1)
                add_dic(dic_final, org_admin)
            else:
                #add_dic(dic_final, "None")
                pass
        except:
            pass

def whois_country(dic_info, dic_final):
    for key in dic_info.keys():
        try:
            if key == '87.67.106.9' or key == '85.201.100.227':
                #add_dic(dic_final, "hosts address")
                pass

            out = subprocess.check_output(["whois", key], universal_newlines=True)
            reg = re.search(r"Country:\s*(.+)", out)
            reg2 = re.search(r"country:\s*(.+)", out)
            reg3 = re.search(r"pays:\s*(.+)", out)
            if reg:
                org_admin = reg.group(1)
                add_dic(dic_final, org_admin)
            if reg2:
                org_admin = reg2.group(1)
                add_dic(dic_final, org_admin)
            if reg3:
                org_admin = reg3.group(1)
                add_dic(dic_final, org_admin)

            else:
                #add_dic(dic_final, "None")
                pass
        except:
            pass

private_addr = dict()
admin_pub_addr = dict()
admin_country = dict()
public_addr = dict()

for pkt in cap:
    for i in pkt.layers:
        if i.layer_name == 'ip':
            addr_layer = pkt[i.layer_name]

            if addr_private(addr_layer.addr):
                add_dic(private_addr, addr_layer.addr)
            if addr_private(addr_layer.dst):
                add_dic(private_addr, addr_layer.dst)

            if not addr_private(addr_layer.addr):
                add_dic(public_addr, addr_layer.addr)
            if not addr_private(addr_layer.dst):
                add_dic(public_addr, addr_layer.dst)

        if i.layer_name == 'ipv6':
            addr_layer = pkt[i.layer_name]
            add_dic(public_addr, addr_layer.addr)
            add_dic(public_addr, addr_layer.dst)

whois_country(public_addr, admin_country)
whois_reg(public_addr, admin_pub_addr)

print("====================")
print("Adresses IPv4 privées : ", private_addr)
print("Adresses public : ", public_addr)
print("Registrant Organization adresses public: ", admin_pub_addr)
print("Pays pour les aresses IPv4/v6 : ", admin_country)
print("====================")


def pie_chart(dico, title, save=None):
    if len(dico) == 0:
        return

    sizes = []
    explode = [0.0 for _ in range(len(dico))]
    max_res = 0
    index = 0
    labels = dico.keys()

    for i, key in enumerate(dico.keys()):
        val = dico.get(key)
        sizes.append(val)
        if max_res < val:
            max_res = val
            index = i

    explode[index] = 0.1

    colors = plt.cm.tab20(np.linspace(0, 1, len(dico)))
    plt.figure(figsize=(12, 12))
    plt.title(title)
    plt.pie(sizes, explode=explode, labels=labels, shadow=False, colors=colors, autopct='%1.1f%%', startangle=140)
    plt.axis('equal')
    plt.savefig(f"../images/{save}.pdf")
    plt.show()

pie_chart(admin_country, "Pays d'enregistrement des adresses IP", save="country")
pie_chart(admin_pub_addr, "Organisations responsables des adresses IP", save="organisations")


