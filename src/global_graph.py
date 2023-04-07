import matplotlib.pyplot as plt
import numpy as np
import pyshark

def add_dico_time(dico, elem, time):
    if dico.get(elem):
        dico[elem].append(time)
    else:
        dico[elem] = []
        dico[elem].append(time)
    return

def get_dom_at_time(dico, elem, time):
    dom_time = [0 for _ in range(len(time))]
    for t in range(len(time)):
        if time[t] in dico.get(elem):
            for j in dico.get(elem):
                if j == time[t]:
                    dom_time[t] += 1
        else:
            dom_time[t] = 0
    return dom_time


names = ['../captures/test1v2.pcapng', '../captures/test2v2.pcapng', '../captures/test3v2.pcapng', '../captures/test4v2.pcapng']

"""
pkt_arrays = []
for name in names:
    cap = pyshark.FileCapture(name, only_summaries=False)
    pkt_array = []
    for packet in cap:
        transport_name = packet.transport_layer
        if transport_name is None:
            pkt_array.append("None")
        else:
            pkt_array.append(transport_name)
    pkt_arrays.append(pkt_array)
    cap.close()

for name in names:
    cap = pyshark.FileCapture(name, only_summaries=False)
    pkt_array = []
    for packet in cap:
        for j in packet.layers:
            pkt_array.append(j.layer_name)
    pkt_arrays.append(pkt_array)
    cap.close()

fig = plt.figure()
fig.set_size_inches(20,10)
plt.title("Histogramme des différents layers")
plt.xlabel('Layers')
plt.ylabel('Nombre de paquets')
plt.hist(pkt_arrays, bins = 30, edgecolor='blue', alpha=.75, label=["messages", "fichiers", "vidéo", "vocal"])
plt.grid(True)
plt.legend()
plt.savefig("../images/hist_layers.pdf")
plt.show()
"""

time_array = []
dic_lst = []
for name in names:
    deb = dict()
    cap = pyshark.FileCapture(name, only_summaries=False)
    for packet in cap:
        if int(packet.sniff_time.timestamp()) - int(cap[0].sniff_time.timestamp()) not in time_array:
            time_array.append(int(packet.sniff_time.timestamp()) - int(cap[0].sniff_time.timestamp()))
        add_dico_time(deb, 'paquets', int(packet.sniff_time.timestamp() - cap[0].sniff_time.timestamp()))
    dic_lst.append(deb)
    cap.close()

fct = ["messages", "fichiers", "vidéos", "vocal"]
colors = plt.cm.tab20(np.linspace(0, 1, len(dic_lst)))
plt.title("Nombre de paquets en fonction du temps")
for i in range(len(fct)):
    plt.plot(sorted(time_array), get_dom_at_time(dic_lst[i],'paquets',time_array), label=fct[i])
plt.xlabel("Temps [s]")
plt.ylabel("Nombre de paquets")
plt.xticks(rotation=90, ha='right')
plt.legend()
#plt.savefig("../images/time_deb")
plt.show()