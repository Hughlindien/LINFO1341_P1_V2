import subprocess
import re
import pyshark

cap= pyshark.FileCapture('../captures/test1v2.pcapng', only_summaries=False) # messages
#cap= pyshark.FileCapture('../captures/test_2_v2.pcapng', only_summaries=False) # fichiers
#cap= pyshark.FileCapture('../captures/test2v2.pcapng', only_summaries=False)
#cap= pyshark.FileCapture('../captures/test_3_v2.pcapng', only_summaries=False) # vidéos
#cap= pyshark.FileCapture('../captures/test3v2.pcapng', only_summaries=False)
#cap= pyshark.FileCapture('../captures/test_4_v2.pcapng', only_summaries=False) # vocal
#cap= pyshark.FileCapture('../captures/test4v2.pcapng', only_summaries=False)


def add_dic(dico, elem):
    if dico.get(elem):
        dico[elem] += 1
    else:
        dico[elem] = 1
    return

def extract_domain(dom):
    domain = dom.split("//")[-1].split("/")[0]
    if '.' in domain:
        domain = '.'.join(domain.split('.')[-2:])
    return domain

def add_dico_time(dico, elem, time):
    if dico.get(elem):
        dico[elem].append(time)
    else:
        dico[elem] = []
        dico[elem].append(time)
    return

def add_dico_set(dico, elem, to_add):
    if dico.get(elem):
        dico[elem].add(to_add)
    else:
        dico[elem] = set()
        dico[elem].add(to_add)
    return

def get_dom_at_time(dico, elem, time):
    dom_time = [0 for _ in range(len(time))]
    for t in range(len(time)):
        dom_time[t] += dico.get(elem).count(time[t])
    return dom_time

def whois_reg(dic_info, dic_final):
    for key in dic_info.keys():
        out = subprocess.check_output(["whois", extract_domain(key)], universal_newlines=True)
        reg = re.search(r"Registrant Organization:\s*(.+)", out)
        if reg:
            org_admin = reg.group(1)
            add_dic(dic_final, org_admin)

        else:
            #add_dic(dic_final, "None")
            pass



time_array = []
quest = 0
rep= 0
err = 0
auth = 0
addr = 0
auth_rr = dict()
dom_qry_names = dict()
dom_resp_names = dict()
types_qry = dict()
types_resp = dict()
types_err = dict()
owner_resp = dict()
owner_auth = dict()
res_dom = dict()
deb_dns = dict()
soa_dic = dict()
secure_dic = dict()
trunc_dic = dict()
ttl_set = set()

for pkt in cap:

    if int(pkt.sniff_time.timestamp() - cap[0].sniff_time.timestamp()) not in time_array:
        time_array.append(int(pkt.sniff_time.timestamp() - cap[0].sniff_time.timestamp()))

    for i in pkt.layers:
        if i.layer_name == 'dns':

            dns_layer = pkt[i.layer_name]

            add_dico_time(deb_dns, 'dns', int(pkt.sniff_time.timestamp() - cap[0].sniff_time.timestamp()))

            add_dic(secure_dic, dns_layer.flags_checkdisable.showname_value)
            add_dic(trunc_dic, dns_layer.flags_truncated.showname_value)

            # Answer
            if int(dns_layer.flags_response) == 1:
                rep += 1

                addr += int(dns_layer.count_add_rr)

                if hasattr(dns_layer, 'resp_ttl'):
                    ttl_set.add(dns_layer.resp_ttl)

                # Error
                if int(dns_layer.flags_rcode) != 0:
                    err += 1
                    type_error = dns_layer.flags_rcode.showname_value
                    add_dic(types_err, type_error)
                    print(dns_layer.qry_name)

                if hasattr(dns_layer, 'resp_type'):
                    type_of = dns_layer.resp_type.showname_value
                    add_dic(types_resp, type_of)

                if int(dns_layer.count_auth_rr) != 0:
                    auth += 1

                    if hasattr(dns_layer, 'soa_mname'):
                        name_auth = dns_layer.soa_mname
                        name_admin = dns_layer.soa_rname
                        add_dic(auth_rr, name_admin)
                        add_dico_set(soa_dic, name_admin, name_auth)
                    else:
                        name_auth = dns_layer.ns.showname_value
                        add_dic(auth_rr, name_auth)

                if hasattr(dns_layer, 'resp_name') and (hasattr(dns_layer, 'a') or hasattr(dns_layer, 'aaaa')):
                    name = dns_layer.resp_name
                    add_dic(dom_resp_names, name)
                    add_dico_time(res_dom, name, int(pkt.sniff_time.timestamp() - cap[0].sniff_time.timestamp()))

            # Query
            else:
                quest+= 1

                type_of = dns_layer.qry_type.showname_value
                add_dic(types_qry, type_of)

                name = dns_layer.qry_name
                add_dic(dom_qry_names, name)

whois_reg(dom_resp_names, owner_resp)
whois_reg(auth_rr, owner_auth)

print("==========DNS==========")
print("Nombre total de paquets DNS: ", rep + quest)
print("Sécurité des paquets DNS : ", secure_dic)
print("Sécurité des paquets DNS : ", trunc_dic)

print("==========Query==========")
print("Nombre de questions : ", quest)
print("Noms de domaines à résoudre : ", dom_qry_names)
print("Types de requêtes présents : ", types_qry)


print("==========Answers==========")
print("Nombre de réponses : ", rep)
print("Nombre d'erreurs (réponses) : ", err)
print("Time To Live des réponses [s] : ", ttl_set)
print("Nombre de paquets qui ont un (ou plus) serveur autoritatif : ", auth)
print("Nombre de records additionnnels : ", addr)
print("Types d'erreurs présents : ", types_err)
print("Noms de domaines résolus : ", dom_resp_names)
print("Serveurs autoritatifs : ", auth_rr)
print("Requêtes soa : ", soa_dic)
print("Types de réponses présents : ", types_resp)
print("Registrant organizations pour les domaines résolus: ", owner_resp)
print("Registrant organizations pour les serveurs autoritatifs: ", owner_auth)
