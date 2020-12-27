from network import NetworkTrace
import networkx as nx
import matplotlib.pyplot as plt
from device import DeviceProfile

"""
This class extracts the Packet Level Signature of remote control in IoT devices outlined in UC NDSS 2020 paper PINGPONG
"""


class GraphNetwork():

    def build_network(Network):
        MG = nx.MultiDiGraph()
        iot_nodes = []
        nodes = []
        for key in Network.mac_to_ip:
            for value in Network.mac_to_ip[key]:
                if key in Network.iot_devices.values():
                    # print(key)
                    iot_nodes.append(value)
                else:
                    nodes.append(value)
        MG.add_nodes_from(iot_nodes)
        MG.add_nodes_from(nodes)
        # print("test 1")
        tcp_edges = []
        udp_edges = []
        edges = []
        for node in Network.device_flows:
            for flow_direction in Network.device_flows[node]:
                # print(self.device_flows[node][flow_direction])
                for value in Network.device_flows[node][flow_direction]:
                    # edges.append(value[0:2])
                    # print(value)
                    edge = value[0:2]
                    if value[-1] == "TCP":
                        tcp_edges.append(edge)
                    elif value[-1] == "UDP":
                        udp_edges.append(edge)
                    else:
                        edges.append(edge)

        MG.add_edges_from(tcp_edges)
        MG.add_edges_from(udp_edges)
        # MG.add_edges_from(edges)
        pos = nx.spring_layout(MG)
        # print(iot_nodes)
        # for node in MG:
        #     if node in iot_nodes:
        nx.draw_networkx_nodes(MG, pos, node_color='red', node_size=25, nodelist=iot_nodes, label="IoT")
            # else:
        nx.draw_networkx_nodes(MG, pos, node_color='black',nodelist=nodes, node_size=25, label="Internet/Local Network")

        # nx.draw_networkx_edges(MG,pos, edgelist=tcp_edges, edge_color='blue', label="TCP")
        nx.draw_networkx_edges(MG, pos, edgelist=udp_edges, edge_color='black', label="UDP")
        nx.draw_networkx_edges(MG, pos, edgelist=edges, edge_color='green', label="Not sure yet")

        # plt.draw_networkx(MG)
        plt.savefig("udp-graphnetwork.png", bbox_inches='tight')
        plt.legend(loc='best')
        plt.show()
