from network import NetworkTrace
import networkx as nx
import matplotlib.pyplot as plt
from device import DeviceProfile
import math
import numpy as np
from sklearn.cluster import DBSCAN

"""
This class extracts the Packet Level Signature of remote control in IoT devices outlined in UC NDSS 2020 paper PINGPONG
"""

class PacketLevelSignature():

    def __init__(self, event_traffic):
        self.event_traffic = event_traffic
        self.process_events()

    def cluster_event_traffic(self, command):
        X = []
        for location in self.event_traffic[command]:
            for device_obj in self.event_traffic[command][location]:
                for flow in device_obj.distance:
                    X.extend(device_obj.distance[flow])
        eps = 10
        total_events = len(self.event_traffic[command])
        minPts = total_events - (0.1 * total_events)
        cluster = DBSCAN(eps=eps, min_samples=minPts, metric='precomputed').fit(X)

        def plot_cluster():
            core_samples_mask = np.zeros_like(cluster.labels_, dtype=bool)
            core_samples_mask[cluster.core_sample_indices_] = True
            labels = cluster.labels_
            unique_labels = set(labels)
            colors = [plt.cm.Spectral(each) for each in np.linspace(0, 1, len(unique_labels))]
            for k, col in zip(unique_labels, colors):
                if k == -1:
                    # Black used for noise.
                    col = [0, 0, 0, 1]
                class_member_mask = (labels == k)
                xy = X[class_member_mask & core_samples_mask]
                plt.plot(xy[:, 0], xy[:, 1], 'o', markerfacecolor=tuple(col),
                         markeredgecolor='k', markersize=14)
                xy = X[class_member_mask & ~core_samples_mask]
                plt.plot(xy[:, 0], xy[:, 1], 'o', markerfacecolor=tuple(col),
                         markeredgecolor='k', markersize=6)
            plt.savefig(command +" dbscanoutput.png")
            plt.show()

    def process_events(self):
        for command in self.event_traffic:
            for location in self.event_traffic[command]:
                for device_obj in self.event_traffic[command][location]:
                    self.preprocess_device_traffic(device_obj)


    def preprocess_device_traffic(self, device_obj):
        tcp_flows = self.get_bidirectional_tcp_flows(device_obj)
        bidirectional_traffic = self.order_pkts_in_bidirectional_flow(tcp_flows, device_obj)
        self.set_pkt_pairs(bidirectional_traffic, device_obj)
        self.set_pkt_sequences(device_obj)
        self.set_distance(device_obj)


    def get_bidirectional_tcp_flows(self, device_obj):
        tcp_flows = []
        device_obj.set_flow_pairs()
        for flow_tuple in device_obj.flow_pairs:
            if flow_tuple[0][4] == "TCP" and flow_tuple[1][4] == "TCP":
                tcp_flows.append(flow_tuple)

        return tcp_flows

    def order_pkts_in_bidirectional_flow(self, tcp_flows, device_obj):
        bidirectional_traffic = {flow_tuple: None for flow_tuple in tcp_flows}

        for flow_tuple in tcp_flows:
            input_pkts = device_obj.flows['incoming'][flow_tuple[0]]
            output_pkts = device_obj.flows['outgoing'][flow_tuple[1]]
            all_pkts = input_pkts + output_pkts
            bidirectional_traffic[flow_tuple] = sorted(all_pkts, key=lambda i: i['relative_timestamp'])
            # print(bidirectional_traffic[flow_tuple])

        return bidirectional_traffic

    def set_pkt_pairs(self, bidirectional_traffic, device_obj):
        connection_pkt_pairs = {connection: [] for connection in list(bidirectional_traffic.keys())}
        # test_dict = {connection: [] for connection in list(bidirectional_traffic.keys())}
        mac_address = device_obj.mac_address

        def get_direction(connection_traffic, pkt):
            if connection_traffic[pkt]['eth_src'] != mac_address:
                pkt_direction = "S-->C"
            elif connection_traffic[pkt]['eth_src'] == mac_address:
                pkt_direction = "C-->S"
            return pkt_direction

        for flow in bidirectional_traffic:
            connection_traffic = bidirectional_traffic[flow]
            pair_ordinals = []
            for pkt in range(0, len(connection_traffic)):
                # test_dict[flow].append(
                #     (connection_traffic[pkt]['ordinal'], connection_traffic[pkt]['tcp_data']['payload_len'])) # Logic validation purposes
                this_pkt_ordinal = connection_traffic[pkt]['ordinal']
                if this_pkt_ordinal in pair_ordinals:
                    """ if a packet is already in a pair, we don't form another pair with the same packet (implemented this way as the iteration step can vary
                    from 1 to 2 depending on packet directions in previous pair)
                    e.g if 2 packets are same direction p = (C-Pci, 0) or (S-Pci, 0) and Pci+1 is paired with Pci+2
                    which results in iteration step being 1. But if oppposite directions, iteration step = 2."""
                    continue

                this_pkt_direction = get_direction(connection_traffic, pkt)
                if pkt <= len(connection_traffic) - 2:
                    next_pkt_direction = get_direction(connection_traffic, pkt + 1)
                    next_pkt_ordinal = connection_traffic[pkt + 1]['ordinal']
                    this_pkt = this_pkt_direction[0:2] + str(connection_traffic[pkt]['tcp_data']['payload_len'])
                    next_pkt = next_pkt_direction[0:2] + str(connection_traffic[pkt + 1]['tcp_data']['payload_len'])
                    if this_pkt_direction != next_pkt_direction:
                        pair = (this_pkt, next_pkt)
                        pair_ordinals.append(
                            (connection_traffic[pkt]['ordinal'], connection_traffic[pkt + 1]['ordinal']))
                        connection_pkt_pairs[flow].append(pair)
                        pair_ordinals.append(this_pkt_ordinal)
                        pair_ordinals.append(next_pkt_ordinal)
                    else:
                        pair1 = (this_pkt, 0)
                        connection_pkt_pairs[flow].append(pair1)
                        pair_ordinals.append(this_pkt_ordinal)
                else:
                    pkt = this_pkt_direction[0:2] + str(connection_traffic[pkt]['tcp_data']['payload_len'])
                    pkt_pair = (pkt, 0)
                    connection_pkt_pairs[flow].append(pkt_pair)
                    pair_ordinals.append(this_pkt_ordinal)

        device_obj.pkt_pairs = connection_pkt_pairs

    def set_pkt_sequences(self, device_obj):
        try:
            assert device_obj.pkt_pairs is not None
        except AssertionError:
            print(AssertionError)
            print("PKT PAIRS NOT SET FOR DEVICE OBJ")
        device_obj.pkt_sequences = {connection: [] for connection in list(device_obj.pkt_pairs.keys())}

        for flow in device_obj.pkt_pairs:
            sequenced_pairs_index = []
            pkt_index = 0
            i = 0
            while i < len(device_obj.pkt_pairs[flow]):
                # print(sequenced_pairs_index)
                p1 = device_obj.pkt_pairs[flow][i]
                if i <= len(device_obj.pkt_pairs[flow]) - 2:
                    p2 = device_obj.pkt_pairs[flow][i + 1]
                if i == len(device_obj.pkt_pairs[flow]) - 1:
                    break
                if i in sequenced_pairs_index:
                    continue
                seq_len = 0
                p1_pkt = pkt_index
                if 0 in p1:
                    seq_len += 1
                    # i = 1
                    # pkt_index += 1
                if 0 not in p1:
                    seq_len += 2
                p2_pkt = p1_pkt + seq_len
                # check whether p1 is before p2
                if p1_pkt == p2_pkt - seq_len:
                    # print("sequence pairs:", p1, p2)
                    sequenced_pairs_index.append(i)
                    sequenced_pairs_index.append(i + 1)
                    step = 2
                    device_obj.pkt_sequences[flow].append((p1, p2))
                    if 0 in p2:
                        seq_len += 1
                    if 0 not in p2:
                        seq_len += 2
                else:
                    step = 1
                pkt_index += seq_len
                i = i + step

    def first_pkt_direction(self, pkt_pair):
        return pkt_pair[0][0:2]

    def second_pkt_direction(self, pkt_pair):
        if pkt_pair[1] == 0:
            return 0
        else:
            return pkt_pair[1][0:2]

    def set_distance(self, device_obj):
        DOUBLE_MAX = 1.7976931348623158E+308
        device_obj.distance = {connection:[] for connection in device_obj.pkt_sequences}
        for flow in device_obj.pkt_sequences:
            sequence = device_obj.pkt_sequences[flow]
            for pkt_seq in sequence:
                p1 = pkt_seq[0]
                p2 = pkt_seq[1]
                print(p1, p2)
                if self.first_pkt_direction(p1) != self.first_pkt_direction(p2) or self.second_pkt_direction(p1) != self.second_pkt_direction(p2):
                    device_obj.distance[flow].append(DOUBLE_MAX)
                else:
                    p1_len_1 = int(p1[0][2:])
                    if p1[1] == 0:
                        p1_len_2 = p1[1]
                    else:
                        p1_len_2 = int(p1[1][2:])
                    p2_len_1 = int(p2[0][2:])
                    if p2[1] == 0:
                        p2_len_2 = 0
                    else:
                        p1_len_2 = int(p2[1][2:])
                    device_obj.distance[flow].append(math.sqrt(math.pow(p1_len_1-p1_len_2,2) + math.pow(p2_len_1 - p1_len_2, 2)))


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
