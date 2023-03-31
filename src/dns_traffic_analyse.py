# https://docs.python.org/3/library/subprocess.html
# https://docs.python.org/3/library/re.html
# https://docs.python.org/3/index.html

import subprocess
import re
import pyshark

# Ouverture de la trace
cap= pyshark.FileCapture('../Captures/Test1_Message.pcapng', only_summaries=False)
#cap= pyshark.FileCapture('../Captures/test_3_appel.pcapng', only_summaries=False)
quest = 0 # Nombre de requêtes
rep= 0 # Nombre de réponses

type_A = 0 # IPv4
type_AAAA = 0 # IPv6

types_qry = dict() # Stock les types de requêtes présents

domains_names = dict() # Stock les noms de domaines à résoudre
domains_names_no_adr = dict() # Stock les noms de domaines dont on n'a pas obtenu l'adresse ip

auth_serv = dict() # Noms de serveurs autoritaires
count_auth_rr = 0 # Nombre de serveurs autoritaires

# Additionnal records
count_add_record = 0
count_pkt_add_record = 0
type_qry_add_record = dict() # Pour les demandes uniquement
name_qry_add_record = dict() # Pour les demandes uniquement

# Adresses ip
dico_ipv4 = dict()
dico_ipv6 = dict()

# Temps
pkt_time_array = []

# Organisations à qui appartiennent les noms de domaines
owner = dict()
registrant = dict()



# Rempli un dictionnaire avec les informations utiles (pour les noms de domaines)
def add_dico(dns_layer, dico, time=None, adresse=None):
    if dico.get(dns_layer.qry_name):
        dico[dns_layer.qry_name][2].add(adresse) # Ajoute l'adresse ip(v4 ou v6)
        dico[dns_layer.qry_name][1].append(time)  # Ajoute le moment où on a résolu le domaine
        dico[dns_layer.qry_name] = (dico[dns_layer.qry_name][0] + 1, dico[dns_layer.qry_name][1], dico[dns_layer.qry_name][2])  # Incrémente le nombre de fois qu'on résoud ce domaine
    else:
        domains_names[dns_layer.qry_name] = (1, [sniff_time], set())
        domains_names[dns_layer.qry_name][2].add(adresse)
    return

# Retourne deux array (temps et nombre de résolution d'un domaines)
def get_dom_at_time(lst, time):
    array_time = []
    array_dom = []
    i = -1
    for t in lst:
        if t in array_time:
            array_dom[i] += 1
        else:
            array_time.append(t)
            array_dom.append(1)
            i += 1
    for t in range(len(time)):
        if time[t] not in lst:
            array_time.insert(t, time[t])
            array_dom.insert(t, 0)
    return array_time, array_dom

def extract_domain(url):
    # extraire le nom de domaine sans le protocole (http, https)
    domain = url.split("//")[-1].split("/")[0]
    # extraire le nom de domaine sans le sous-domaine
    if '.' in domain:
        domain = '.'.join(domain.split('.')[-2:])
    # renvoyer le nom de domaine
    return domain

# Code principal
for pkt in cap:

    high = pkt.highest_layer # On regarde uniquement la couche la plus haute

    if high == 'DNS': # Si c'est une reqête DNS
        dns_layer = pkt[high]  # On regarde la requête DNS

        # Ajoute le type de requête à l'ensemble
        type_of = dns_layer.qry_type.showname_value
        if types_qry.get(type_of):
            types_qry[type_of] += 1
        else:
            types_qry[type_of] = 1

        # Additionnal record
        count_add_record += int(dns_layer.count_add_rr)
        if int(dns_layer.count_add_rr) != 0:
            count_pkt_add_record += 1

        # Serveur autoritaire
        count_auth_rr += int(dns_layer.count_auth_rr)
        if int(dns_layer.count_auth_rr) == 1:  # S'il y a un serveur autoritaire
            name_auth = dns_layer.soa_mname
            if  auth_serv.get(name_auth):
                auth_serv[name_auth].add(dns_layer.qry_name)
            else:
                auth_serv[name_auth] = set()
                auth_serv[name_auth].add(dns_layer.qry_name)

        if int(dns_layer.flags_response) == 1:  # Regarde si c'est une réponse
            rep += 1

            # Nombre de fois qu'on demande une résolution de domaine et quand
            pkt_hour = pkt.sniff_time.time().hour
            pkt_min = pkt.sniff_time.time().minute
            pkt_sec = pkt.sniff_time.time().second
            sniff_time = f"{pkt_hour}:{pkt_min}:{pkt_sec}"

            # Adresses
            if hasattr(dns_layer, 'a'):  # Récupère l'adresse ipv4
                type_A += 1

                add_dico(dns_layer, domains_names, time=sniff_time, adresse=dns_layer.a)

                # Ajoute au dico_ipv4
                if dico_ipv4.get(dns_layer.a):
                    dico_ipv4[dns_layer.a] += 1
                else:
                    dico_ipv4[dns_layer.a] = 1

            elif hasattr(dns_layer, 'aaaa'):  # Récupère l'adresse ipv6
                type_AAAA += 1

                add_dico(dns_layer, domains_names, time=sniff_time, adresse=dns_layer.aaaa)

                # Ajoute au dico_ipv6
                if dico_ipv6.get(dns_layer.aaaa):
                    dico_ipv6[dns_layer.aaaa] += 1
                else:
                    dico_ipv6[dns_layer.aaaa] = 1

            else:  # Si on n'obtient pas l'adresse (indique qu'il faut demander au serveur autoritaire)
                if domains_names_no_adr.get(dns_layer.qry_name):
                    domains_names_no_adr[dns_layer.qry_name] += 1
                else:
                    domains_names_no_adr[dns_layer.qry_name] = 1

        else:  # C'est une demande
            quest+= 1

            # Vérifie simpelement le nombre de records additionnels dans les demandes
            if int(dns_layer.count_add_rr) > 1:
                print("More than one add_rr")

            # Regarde le type et le de requête dans le record additionnel aisni que les noms de domaines
            elif int(dns_layer.count_add_rr) == 1:

                name_add_qry = dns_layer.resp_name
                if type_qry_add_record.get(name_add_qry):
                    type_qry_add_record[name_add_qry] += 1
                else:
                    type_qry_add_record[name_add_qry] = 1

                type_add_qry = dns_layer.resp_type.showname_value
                if name_qry_add_record.get(type_add_qry):
                    name_qry_add_record[ type_add_qry] += 1
                else:
                    name_qry_add_record[ type_add_qry] = 1

    # liste des temps
    packet_hour = pkt.sniff_time.time().hour
    packet_min = pkt.sniff_time.time().minute
    packet_sec = pkt.sniff_time.time().second
    if f"{packet_hour}:{packet_min}:{packet_sec}" not in pkt_time_array:
        pkt_time_array.append(f"{packet_hour}:{packet_min}:{packet_sec}")

# On regarde à qui appartient le nom de domaine
for key in domains_names.keys():

    out = subprocess.check_output(["whois", extract_domain(key)], universal_newlines=True)
    admin = re.search(r"Admin Organization:\s*(.+)", out)

    if admin :
        org_admin = admin.group(1)

        # Ajout dans le dictionnaire
        if owner.get(org_admin):
            owner[org_admin].add(key)
        else:
            if org_admin == 'REDACTED FOR PRIVACY': # On ira chercher dans les serveurs autoritaires
                pass
            else:
                owner[org_admin] = set()
                owner[org_admin].add(key)

    else :
        org_admin = None

# On regarde pour les domaines qui qui on un serveur autoritaire
for key in auth_serv.keys():

    out = subprocess.check_output(["whois", extract_domain(key)], universal_newlines=True)
    admin = re.search(r"Admin Organization:\s*(.+)", out)

    if admin :
        org_admin = admin.group(1)
        owner[org_admin] = auth_serv.get(key) # Toujours des administrateurs différents

    else :
        org_admin = None


# On regarde qui est registrant des noms de domaine
for key in domains_names.keys():

    out = subprocess.check_output(["whois", extract_domain(key)], universal_newlines=True)
    reg = re.search(r"Registrant Organization:\s*(.+)", out)

    if reg :
        org_reg = reg.group(1)

        # Ajout dans le dictionnaire
        if registrant.get(org_reg):
            registrant[org_reg].add(key)
        else:
            if org_reg == 'REDACTED FOR PRIVACY': # On ira chercher dans les serveurs autoritaires
                pass
            else:
                registrant[org_reg] = set()
                registrant[org_reg].add(key)

    else :
        org_reg = None

# On regarde pour les domaines qui qui on un serveur autoritaire
for key in auth_serv.keys():

    out = subprocess.check_output(["whois", extract_domain(key)], universal_newlines=True)
    reg = re.search(r"Registrant Organization:\s*(.+)", out)

    if reg :
        org_reg = reg.group(1)
        registrant[org_reg] = auth_serv.get(key) # Toujours des registrant différents

    else :
        org_reg = None

# Affiche les données
print("Nombre de questions : ", quest)
print("Nombre de réponses : ", rep)
print("Nombre total de paquets DNS: ", rep + quest)

print("Types de requêtes présents : ", types_qry)
print(f"Nombre d'adresses IPv4 obtenues : {type_A} (2 * {type_A} = {type_A * 2})")
print(f"Nombre d'adresses IPv6 obtenues : {type_AAAA} (2 * {type_AAAA} = {type_AAAA * 2})")
print(f"Adresses IPv4 obtenues : {dico_ipv4}")
print(f"Adresses IPv6 obtenues : {dico_ipv6}")

print("Domaines à résoudre: ", domains_names)
print("Domaines non résolus (non obtention de l'adresse) : ", domains_names_no_adr)

print("Nombre de serveurs autoritaires: ", count_auth_rr)
print("Serveurs autoritaires : ", auth_serv)

print(f"Nombre de records additionnels : {count_add_record}  répartis sur {count_pkt_add_record} paquets")
print(f"Types des queries dans les records additionel des demandes :", type_qry_add_record)
print(f"Noms des queries dans les records additionel des demandes :", name_qry_add_record)
print(f"Administrateur des domaines :", owner)
print(f"Registrant des domaines :", registrant)
print("==================")
