import matplotlib.pyplot as plt
import pyshark
import matplotlib.dates as mdates
from datetime import datetime

# Charger la capture Wireshark
capture = pyshark.FileCapture('../Captures/vidéo.pcapng', only_summaries=False)



#Q2.1.3 pt 1 et 2


# Dictionnaire pour stocker les protocoles de transport et leur nombre d'occurrences
transport_protocols = {}

# Initialiser une liste vide pour stocker les heures des paquets
timestamps = []

# Initialiser un dictionnaire pour stocker le nombre de connexions par nom de domaine
connection_counts = {}

# Parcourir tous les paquets de la capture
for pkt in capture:
    transport_protocol = pkt.transport_layer  # Récupérer le nom du protocole de transport

    # Si le protocole de transport est déjà dans le dictionnaire, augmenter le compteur de 1
    if transport_protocol in transport_protocols:
        transport_protocols[transport_protocol] += 1
    # Sinon, ajouter le protocole de transport avec un compteur initial de 1
    else:
        transport_protocols[transport_protocol] = 1
    try:
        # Vérifier si le paquet est une connexion TCP ou UDP
        if 'TCP' in pkt or 'UDP' in pkt:
            # Extraire l'adresse source et l'adresse destination
            src = pkt.ip.src.lower()
            dst = pkt.ip.dst.lower()
            # Concaténer les adresses pour former une chaîne unique représentant la connexion
            connection = f"{src} -> {dst}"
            # Incrémenter le compteur pour cette connexion
            connection_counts[connection] = connection_counts.get(connection, 0) + 1
            # Ajouter l'horodatage du paquet à la liste
            timestamps.append(float(pkt.sniff_time.timestamp()))
    except AttributeError:
        pass


# Afficher les protocoles de transport et leur nombre d'occurrences
print("Protocoles de transports utilisés:")
for protocol, count in transport_protocols.items():
    print(f"{protocol}: {count}")   

print(" ")           
# Afficher le nombre total de connexions établies
total_connections = sum(connection_counts.values())
print(f"Il y a {total_connections} connexions établies dans le fichier de capture.")

# Tracer un graphique du nombre de connexions établies en fonction du temps
plt.plot(timestamps, 'ro')
plt.xlabel('Temps (s)')
plt.ylabel('Nombre de connexions établies')
plt.title('Connexions établies en fonction du temps')
#plt.show()




#print("DNS")
# Initialiser un dictionnaire pour stocker le nombre de connexions par nom de domaine
#domain_counts = {}
# Parcourir tous les paquets de la capture
#for packet in capture:
#    try:
#        # Vérifier si le paquet contient une requête DNS
#        if "DNS" in packet and packet.dns.qry_name:
#            # Extraire le nom de domaine de la requête DNS
#            domain = packet.dns.qry_name.lower()
#            # Incrémenter le compteur pour ce nom de domaine
#            domain_counts[domain] = domain_counts.get(domain, 0) + 1
#    
#    except AttributeError:
#        pass
# Parcourir le dictionnaire de comptage de noms de domaine pour afficher les résultats
#for domain, count in domain_counts.items():
#    if count > 1:
#        print(f"Le domaine {domain} a été contacté {count} fois.")




#Q2.1.3 pt 3


# Initialiser un dictionnaire pour stocker les versions QUIC détectées
quic_versions = {}

# Parcourir tous les paquets du fichier
for packet in capture:
    # Vérifier si le paquet contient le protocole QUIC
    if packet.highest_layer == 'QUIC':

        # Récupérer la version QUIC utilisée
        try:
            version = packet.quic.version.raw_value
        except AttributeError:
            version = 'unknown'

        # Ajouter la version détectée au dictionnaire
        if version in quic_versions:
            quic_versions[version] += 1
        else:
            quic_versions[version] = 1

# Afficher les versions QUIC détectées et leur nombre d'occurrences
print("Versions QUIC détectées :")
for version, count in quic_versions.items():
    print(f"Il y a {count} traffic QUIC de version {version}")