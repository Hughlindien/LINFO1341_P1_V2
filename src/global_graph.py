import matplotlib.pyplot as plt
import numpy as np
import pyshark

names = ['../captures/test1v2.pcapng', '../captures/test2v2.pcapng', '../captures/test3v2.pcapng', '../captures/test4v2.pcapng']

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

"""
for name in names:
    cap = pyshark.FileCapture(name, only_summaries=False)
    pkt_array = []
    for packet in cap:
        for j in packet.layers:
            pkt_array.append(j.layer_name)
    pkt_arrays.append(pkt_array)
    cap.close()
"""

fig = plt.figure()
fig.set_size_inches(20,10)
plt.title("Histogramme des différents layers")
plt.xlabel('Layers')
plt.ylabel('Nombre de paquets')
plt.hist(pkt_arrays, bins = 10, edgecolor='blue', alpha=0.75, label=["messages", "fichiers", "vidéo", "vocal"])
plt.grid(True)
plt.legend()
plt.savefig("../images/hist_layers.pdf")
plt.show()