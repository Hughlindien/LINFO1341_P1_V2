from dns_analyse import *
import matplotlib.pyplot as plt
import numpy as np


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
    plt.title(title)
    plt.pie(sizes, explode=explode, labels=labels, shadow=False, colors=colors, autopct='%1.1f%%', startangle=140)
    plt.axis('equal')
    # plt.savefig("../images/dns_owner")
    plt.show()



colors = plt.cm.tab20(np.linspace(0, 1, len(res_dom)))
plt.figure(figsize=(20, 20))
plt.title("Nombre de résolutions des différents domaines en fonction du temps")
for i, key in enumerate(res_dom.keys()):
    plt.plot(time_array, get_dom_at_time(res_dom,key,time_array), color=colors[i], label=f"{key}")
plt.xlabel("Temps [s]")
plt.ylabel("Nombre de résolutions")
plt.xticks(rotation=90, ha='right')
plt.legend()
#plt.savefig("../images/dns_time_res_vid")
plt.show()



pie_chart(dom_resp_names, "Noms de domaines résolus")
pie_chart(owner_resp, "Propriétaires des domaines résolus")
pie_chart(owner_auth, "Propriétaires des sereurs autoritatifs")



colors = plt.cm.tab20(np.linspace(0, 1, len(res_dom)))
plt.title("Nombre de paquets dns en fonction du temps")
plt.plot(time_array, get_dom_at_time(deb_dns,'dns',time_array), color=colors[i], label="paquets dns")
plt.xlabel("Temps [s]")
plt.ylabel("Nombre de paquets dns")
plt.xticks(rotation=90, ha='right')
plt.legend()
#plt.savefig("../images/dns_time_deb_fch")
plt.show()
