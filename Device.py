# from Dataset import NetworkTrace
import matplotlib.pyplot as plt
from scipy.interpolate import make_interp_spline, BSpline
import numpy as np
import statistics

class DeviceProfile:

    def __init__(self, device_name,mac_address, ip_addrs):
        self.device_name = device_name
        self.mac_address = mac_address
        self.ip_addresses = ip_addrs
        self.unique_ports = []
        self.domains_accessed = []
        self.flow_attributes = {
            "average input flow rate": [],
            "average input packet size": [],
            "average output flow rate": [],
            "average output packet size": [],
        }
        self.flow_rate = None

    def update_profile(self, flows):
        # self.port_profile(device_traffic)
        print("update profile")
        self.compute_flow_attributes(flows)

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
        # output_rate = []
        # input_rate = []
        # output_rate_time = []
        # input_rate_time = []
        print("computing")
        for flow_direction in flows:
            print(flow_direction)
            for flow_direction in flows:
                # self.flow_rate = {flow: None for flow in flows[flow_direction]}
                for flow in flows[flow_direction]:
                    if len(flows[flow_direction][flow]) > 1:
                        start = flows[flow_direction][flow][0]['relative_timestamp'].total_seconds()
                        end = flows[flow_direction][flow][-1]['relative_timestamp'].total_seconds()
                        duration = end - start
                    else:
                        duration = flows[flow_direction][flow][0]['relative_timestamp'].total_seconds()
                    # pkt_count = Network.device_flow_stats[self.mac_address]

                    # self.flow_rate[flow] = {key: 0 for key in range(0, int(duration)+1, 1)}
                    pkt_count = 0
                    flow_size = 0
                    pkt_size_list = []
                    for pkt in flows[flow_direction][flow]:
                        pkt_ts = pkt['relative_timestamp'].total_seconds()
                        if pkt['protocol'] == "TCP":
                            payload = pkt["tcp_data"]["payload_len"]
                            flow_size += payload
                            pkt_size_list.append(payload)
                        elif pkt["protocol"] == "UDP":
                            payload = pkt["udp_data"]["payload_len"]
                            flow_size += payload
                            pkt_size_list.append(payload)
                        # for i in range(0,int(duration) + 1, 1):
                        #     # print(pkt['relative_timestamp'].total_seconds())
                        #     if i <= pkt_ts and pkt_ts < i + 1:
                        #         self.flow_rate[flow][i] += payload
                        pkt_count += 1

                    # avg_pkt_size = flow_size / pkt_count
                    if len(pkt_size_list) > 0:
                        avg_pkt_size = sum(pkt_size_list) / len(pkt_size_list)
                    else:
                        avg_pkt_size = 0
                    # avg_flow_rate = flow_size / duration
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

        # print(avg_input_pkt_size)
        # print(avg_output_pkt_size)
        tcp_stats = [avg_tcp_input_pkt_size, input_tcp_flow_duration, avg_tcp_output_pkt_size, output_tcp_flow_duration]
        udp_stats = [avg_udp_input_pkt_size, input_udp_flow_duration, avg_udp_output_pkt_size, output_udp_flow_duration]
        print("plotting")
        self.plot_pkt_size(tcp_stats, udp_stats)


    def plot_pkt_size(self, tcp_flows, udp_flows):
        """
        :param tcp_flows: average input packet size, input flow duration, average output packet size, output flow duration
        :param udp_flows: same order as above but udp packets
        :function: Plots the categories
        """
        fig = plt.figure()
        ax = fig.add_subplot(1, 1, 1)
        transparency = 0.3
        ax.scatter(tcp_flows[1], tcp_flows[0], color="r", label="Incoming TCP Flows", alpha = transparency)
        ax.scatter(tcp_flows[2], tcp_flows[3], color='b', label="Outgoing TCP Flows", alpha = transparency)
        ax.scatter(udp_flows[1], udp_flows[0], color="g", label="Incoming UDP Flows", alpha = transparency)
        ax.scatter(udp_flows[2], udp_flows[3], color='y', label="Outgoing UDP Flows", alpha = 0.25)
        ax.set_xlabel("Duration (seconds)")
        ax.set_ylabel("Average application packet size (Bytes)")
        plt.legend(loc='best')
        plt.savefig(self.device_name+".png")
        plt.show()

    def plot_flow_thorughput(self ):
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
