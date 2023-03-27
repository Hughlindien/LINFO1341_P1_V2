# https://pythonspot.com/matplotlib-pie-chart/

from dns_traffic_analyse import *
import matplotlib.pyplot as plt
import numpy as np

# Trouve les index de début et de fin de l'appel
def start_end(time, deb, fin):
    start = 0
    end = 0
    for i in range(len(time)):
        if pkt_time_array[i] == deb:
            start = i
    for i in range(len(time)):
        if pkt_time_array[i] == fin:
            end = i
    return start, end

# Début/fin
start, end = start_end(pkt_time_array, "19:37:52", "19:38:42")

# Couleurs utilisées
colors = plt.cm.tab20(np.linspace(0, 1, len(domains_names)))

# Nombre de résolutions en fonction du temps
plt.figure(figsize=(30, 30))
plt.title("Nombre de résolutions des différents domaines en fonction du temps")
for i, key in enumerate(domains_names.keys()):
    plt.plot(get_dom_at_time(domains_names.get(key)[1], pkt_time_array)[0], get_dom_at_time(domains_names.get(key)[1], pkt_time_array)[1], color=colors[i], label=f"{key}")
plt.xlabel("Temps")
plt.ylabel("Nombre de résolutions")
plt.axvline(x=pkt_time_array[start] , color='red', linestyle="--", label="début/fin de l'appel")
plt.axvline(x=pkt_time_array[end] , color='red', linestyle="--")
plt.xticks(rotation=90, ha='right')
plt.legend()
plt.savefig("Images/dns_time_vid")
plt.show()



# Pie chart du nombre de résolutions
sizes = []
explode = [0.0 for _ in range(len(domains_names))]
max_res = 0
index = 0
labels = domains_names.keys()

# Proportion des éléments
for i, key in enumerate(domains_names.keys()):
    val = domains_names.get(key)[0]
    sizes.append(val)
    if max_res < val:
        max_res = val
        index = i

# Mise en évidence d'un élément
explode[index] = 0.1

plt.figure(figsize=(30, 20))
plt.title("Pie chart du nombre de résolutions des domaines")
colors = plt.cm.tab20(np.linspace(0, 1, len(domains_names)))
plt.pie(sizes, explode=explode, labels=labels, shadow=False, colors=colors,autopct='%1.1f%%', startangle=140)
plt.axis('equal')
plt.savefig("Images/dns_dom_vid")
plt.show()

# Pie chart des administrateurs des domaines
sizes = []
explode = [0.0 for _ in range(len(owner))]
max_res = 0
index = 0
labels = owner.keys()

# Proportion des éléments
for i, key in enumerate(owner.keys()):
    val = len(owner.get(key))
    sizes.append(val)
    if max_res < val:
        max_res = val
        index = i

# Mise en évidence d'un élément
explode[index] = 0.1

# Affichage du graphique
plt.figure(figsize=(30, 20))
plt.title("Pie chart des administrateurs des domaines")
colors = plt.cm.tab20(np.linspace(0, 1, len(owner)))
plt.pie(sizes, explode=explode, labels=labels, shadow=False, colors=colors,autopct='%1.1f%%', startangle=140)
plt.axis('equal')
plt.savefig("Images/dns_admin_vid")
plt.show()