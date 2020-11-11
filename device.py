# from network import NetworkTrace
import matplotlib.pyplot as plt
from scipy.interpolate import make_interp_spline, BSpline
import numpy as np
import itertools


class DeviceProfile:

    def __init__(self, device_name, mac_address, ip_addrs):
        self.device_name = device_name
        self.mac_address = mac_address
        self.ip_addresses = ip_addrs
        self.unique_ports = []
        self.domains_accessed = []
        self.flow_direction_rate = {
            "incoming": None,
            "outgoing": None
        }
        self.flow_rate = None
        self.flow_stats = None

    def update_profile(self, flows):
        # self.port_profile(device_traffic)
        print("update profile")
        
        # for flow_direction in flows:
        #     self.flow_rate = {flow: None for flow in flows[flow_direction]}
            # print(self.flow_rate)
            # self.flow_stats = {flow: {"size": None,
            #                           "duration": None,
            #                           "jitter": None,
            #                           "byte rate": None,
            #                           "pkt rate": None,
            #                           "avg packet size": None,
            #                           "mean packet size": None
            #                           } for flow in flows[flow_direction]}
            # print(self.flow_stats)
        # print(self.flow_rate)
        self.compute_flow_attributes(flows)
        # self.compare_flow_direction(flows)
        # self.get_flow_pairs(flows)

    def port_profile(self, device_traffic):
        """Port check"""
        for pkt in device_traffic:
            if pkt['protocol'] == "TCP":
                if pkt["ip_src"] in self.ip_addresses:
                    if pkt["tcp_data"]["src_port"] not in self.unique_ports:
                        self.unique_ports.append(pkt["tcp_data"]["src_port"])
                elif pkt["ip_dst"] in self.ip_addresses:
                    if pkt["tcp_data"]["dst_port"] not in self.unique_ports:
                        self.unique_ports.append(pkt["tcp_data"]["dst_port"])
            elif pkt["protocol"] == "UDP":
                if pkt["ip_src"] in self.ip_addresses:
                    if pkt["udp_data"]["src_port"] not in self.unique_ports:
                        self.unique_ports.append(pkt["udp_data"]["src_port"])
                elif pkt["ip_dst"] in self.ip_addresses:
                    if pkt["udp_data"]["dst_port"] not in self.unique_ports:
                        self.unique_ports.append(pkt["udp_data"]["dst_port"])

    def compute_flow_attributes(self, flows):
        avg_tcp_input_pkt_size = []
        avg_tcp_output_pkt_size = []
        avg_udp_input_pkt_size = []
        avg_udp_output_pkt_size = []
        input_udp_flow_duration = []
        input_tcp_flow_duration = []
        output_tcp_flow_duration = []
        output_udp_flow_duration = []
        tick = 40
        for flow_direction in flows:
            flow_keys = list(flows[flow_direction].keys())
            first_flow = flow_keys[0]
            last_flow = flow_keys[-1]
            first_pkt_time = flows[flow_direction][first_flow][0]['relative_timestamp'].total_seconds()
            if len(flow_keys) > 1:
                last_pkt_time = 0
                for i in range(0, len(flow_keys), 1):
                    if last_pkt_time < flows[flow_direction][flow_keys[i]][-1]['relative_timestamp'].total_seconds():
                        last_pkt_time = flows[flow_direction][flow_keys[i]][-1]['relative_timestamp'].total_seconds()
                flow_direction_duration = last_pkt_time - first_pkt_time
            else:
                last_pkt = flows[flow_direction][first_flow][-1]['relative_timestamp'].total_seconds()
                flow_direction_duration = last_pkt - first_pkt_time
            self.flow_direction_rate[flow_direction] = {key: [0, 0] for key in
                                                        range(0, int(flow_direction_duration) + 1, tick)}

            self.flow_rate = {flow: None for flow in flows[flow_direction]}
            # print(self.flow_rate)
            for flow in flows[flow_direction]:
                if len(flows[flow_direction][flow]) > 1:
                    start = flows[flow_direction][flow][0]['relative_timestamp'].total_seconds()
                    end = flows[flow_direction][flow][-1]['relative_timestamp'].total_seconds()
                    duration = end - start
                else:
                    duration = flows[flow_direction][flow][0]['relative_timestamp'].total_seconds()
                # self.flow_rate[flow] = {key: 0 for key in range(0, int(duration)+1, 10)}
                pkt_count = 0
                flow_size = 0
                pkt_size_list = []
                pkt_times = []
                for pkt in flows[flow_direction][flow]:
                    pkt_ts = pkt['relative_timestamp'].total_seconds()
                    pkt_times.append(pkt_ts)
                    if pkt['protocol'] == "TCP":
                        payload = pkt["tcp_data"]["payload_len"]
                        flow_size += payload
                        pkt_size_list.append(payload)
                    elif pkt["protocol"] == "UDP":
                        payload = pkt["udp_data"]["payload_len"]
                        flow_size += payload
                        pkt_size_list.append(payload)
                    for i in range(0, int(duration) + 1, tick):
                        # print(pkt['relative_timestamp'].total_seconds())
                        if i <= pkt_ts < i + 1:
                            # self.flow_rate[flow][i] += payload
                            self.flow_direction_rate[flow_direction][i][0] += 1
                            self.flow_direction_rate[flow_direction][i][1] += payload
                    pkt_count += 1

                avg_pkt_size = flow_size / pkt_count
                # self.flow_stats[flow]["size"] = flow_size
                # self.flow_stats[flow]["duration"] = duration
                # self.flow_stats[flow]["byte rate"] = flow_size / duration
                # self.flow_stats[flow]["pkt rate"] = pkt_count / duration
                # self.flow_stats[flow]["avg packet size"] = avg_pkt_size
                pkt_size_list = np.array(pkt_size_list)
                # self.flow_stats[flow]["mean packet size"] = pkt_size_list.mean()

                pair_count = 0
                d = 0
                for i in range(0,len(pkt_times)-1 , 1):
                    d += pkt_times[i + 1] - pkt_times[i]
                    pair_count += 1
                inter_pkt_arrival = d / pair_count
                test = d / (len(pkt_times) - 1)
                print("Inter-packet arrival",inter_pkt_arrival )
                print("test", test)
                # if len(pkt_size_list) > 0:
                #     avg_pkt_size = sum(pkt_size_list) / len(pkt_size_list)
                # else:
                #     avg_pkt_size = 0

                """"Lists for graphs"""
                if flow_direction == "incoming":
                    # input_rate.append(avg_flow_rate)
                    if flow[-1] == "TCP":
                        avg_tcp_input_pkt_size.append(avg_pkt_size)
                        input_tcp_flow_duration.append(duration)
                    elif flow[-1] == "UDP":
                        avg_udp_input_pkt_size.append(avg_pkt_size)
                        input_udp_flow_duration.append(duration)
                elif flow_direction == "outgoing":
                    # output_rate.append(avg_flow_rate)
                    if flow[-1] == "TCP":
                        avg_tcp_output_pkt_size.append(avg_pkt_size)
                        output_tcp_flow_duration.append(duration)
                    elif flow[-1] == "UDP":
                        avg_udp_output_pkt_size.append(avg_pkt_size)
                        output_udp_flow_duration.append(duration)
        print(self.flow_rate)
        # print(avg_input_pkt_size)
        # print(avg_output_pkt_size)
        tcp_stats = [avg_tcp_input_pkt_size, input_tcp_flow_duration, avg_tcp_output_pkt_size, output_tcp_flow_duration]
        udp_stats = [avg_udp_input_pkt_size, input_udp_flow_duration, avg_udp_output_pkt_size, output_udp_flow_duration]
        # print(self.flow_direction_rate)
        # self.plot_pkt_size(tcp_stats, udp_stats)
        self.compare_flow_direction()
        # self.get_flow_pairs(flows)

    def plot_pkt_size(self, tcp_flows, udp_flows):
        """
        :param tcp_flows: average input packet size, input flow duration, average output packet size, output flow duration
        :param udp_flows: same order as above but udp packets
        :function: Plots the categories
        """
        fig = plt.figure()
        ax = fig.add_subplot(1, 1, 1)
        transparency = 0.3
        ax.scatter(tcp_flows[1], tcp_flows[0], color="r", label="Incoming TCP Flows", alpha=transparency)
        ax.scatter(tcp_flows[2], tcp_flows[3], color='b', label="Outgoing TCP Flows", alpha=transparency)
        ax.scatter(udp_flows[1], udp_flows[0], color="g", label="Incoming UDP Flows", alpha=transparency)
        ax.scatter(udp_flows[2], udp_flows[3], color='y', label="Outgoing UDP Flows", alpha=0.25)
        ax.set_xlabel("Duration (seconds)")
        ax.set_ylabel("Average application packet size (Bytes)")
        plt.legend(loc='best')
        plt.savefig(self.device_name + ".png")
        plt.show()

    def plot_flow_throughput(self):
        fig = plt.figure()
        ax = fig.add_subplot(1, 1, 1)
        tcp_legend_control = 0
        udp_legend_control = 0
        for flow in self.flow_rate:
            # rate = np.linspace(np.array(list(self.flow_rate[flow].values())).min(),np.array(list(self.flow_rate[flow].values())).max(),300)
            rate = list(self.flow_rate[flow].values())
            duration = list(self.flow_rate[flow].keys())
            # spl = make_interp_spline(rate, duration, k =3)
            # duration_smooth = spl(rate)
            if flow[-1] == "TCP":
                if tcp_legend_control == 0:
                    ax.plot(duration, rate, color="b", label="TCP")
                    tcp_legend_control += 1
                else:
                    ax.plot(duration, rate, color="b")
            elif flow[-1] == "UDP":
                if udp_legend_control == 0:
                    ax.plot(duration, rate, color="r", label="UDP")
                    udp_legend_control += 1
                else:
                    ax.plot(duration, rate, color='r')
        ax.set_ylabel("Throughput")
        ax.set_xlabel("Time (seconds)")
        plt.legend(loc='best')
        plt.savefig("flow-thorughput.png")
        plt.show()

    def compare_flow_direction(self):
        fig = plt.figure()
        ax = fig.add_subplot(1, 1, 1)
        input_time_axis = list(self.flow_direction_rate["incoming"].keys())
        output_time_axis = list(self.flow_direction_rate["outgoing"].keys())
        input_pkt_rate = []
        input_byte_rate = []
        output_pkt_rate = []
        output_byte_rate = []
        for value in self.flow_direction_rate["incoming"].values():
            input_pkt_rate.append(value[0])
            input_byte_rate.append(value[1])
        for value in self.flow_direction_rate["outgoing"].values():
            output_pkt_rate.append(value[0])
            output_byte_rate.append(value[1])

        ax.plot(input_time_axis, input_byte_rate, label="input flows")
        ax.plot(output_time_axis, output_byte_rate, label="output flows")
        ax.set_ylabel("Rate of all flows (Bytes)")
        ax.set_xlabel("Time (seconds)")
        plt.legend(loc='best')
        plt.savefig(self.device_name + "flowdirectionpktrate.png")
        plt.show()

    def get_flow_pairs(self, flows):
        flow_paris = []  # List of flow pair tuples i.e. input and output stored as tuples
        related_flows = []
        for input in list(flows["incoming"].keys()):
            for output in list(flows["outgoing"].keys()):
                if output == (input[1], input[0], input[3], input[2], input[4]):
                    # self.plot_pairs(input, output)
                    flow_paris.append((input, output))

    def plot_pairs(self, input, output):
        fig = plt.figure()
        ax = fig.add_subplot(1, 1, 1)
        input_time = list(self.flow_rate[input].keys())
        input_rate = list(self.flow_rate[input].values())
        output_time = list(self.flow_rate[output].keys())
        output_rate = list(self.flow_rate[output].values())
        ax.plot(input_time, input_rate, label=str(input))
        ax.plot(output_time, output_rate, label=str(output))
        ax.set_ylabel("Flow rate (Bytes)")
        ax.set_xlabel("Time (seconds)")
        plt.legend(loc='best')
        plt.savefig(self.device_name + "flowpairs.png")
        plt.show()
