# from network import NetworkTrace
import matplotlib.pyplot as plt
from matplotlib.pyplot import cm
from scipy.interpolate import make_interp_spline, BSpline
import numpy as np
import itertools


class DeviceProfile:

    def __init__(self, device_name, mac_address, ip_addrs, traffic):
        self.device_name = device_name
        self.mac_address = mac_address
        self.ip_addrs = ip_addrs
        self.unique_ports = []
        self.domains_accessed = []
        self.flow_direction_rate = {
            "incoming": None,
            "outgoing": None
        }
        self.flow_rate = None
        self.input_flow_stats = None
        self.output_flow_stats = None
        self.flow_pairs = []  # List of flow pair tuples i.e. input and output stored as tuples
        self.all_flow_tuples = None
        self.device_activity = None
        self.flows = traffic

    def update_profile(self, flows, malicious_pkts, benign_pkts):
        # self.port_profile(device_traffic)
        tick = 500
        # for flow_direction in flows:
            # self.flow_rate = {flow: None for flow in flows[flow_direction]}
        self.input_flow_stats = {flow: {"size": None,
                                  "duration": None,
                                  "jitter": None,
                                  "byte rate": None,
                                  "pkt rate": None,
                                  "avg packet size": None,
                                  "pkt count": None,
                                  "flow type": None
                                  } for flow in self.flows['incoming']}
        self.output_flow_stats = {flow: {"size": None,
                                        "duration": None,
                                        "jitter": None,
                                        "byte rate": None,
                                        "pkt rate": None,
                                        "avg packet size": None,
                                        "pkt count": None,
                                         "flow type": None
                                        } for flow in self.flows['outgoing']}
        self.all_flow_tuples = [*list(flows["incoming"].keys()), *list(flows["outgoing"].keys())]
        self.set_device_activity( tick)
        print(self.device_name)
        self.compute_flow_attributes(tick, malicious_pkts, benign_pkts)
        self.plot_device_traffic()
        self.compare_flow_direction_rate(True)
        self.plot_flow_type()
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

    def compute_flow_attributes(self,tick, malicious_pkts, benign_pkts):
        avg_tcp_input_pkt_size = []
        avg_tcp_output_pkt_size = []
        avg_udp_input_pkt_size = []
        avg_udp_output_pkt_size = []
        input_udp_flow_duration = []
        input_tcp_flow_duration = []
        output_tcp_flow_duration = []
        output_udp_flow_duration = []
        for flow_direction in self.flows:
            flow_keys = list(self.flows[flow_direction].keys())
            first_flow = flow_keys[0]
            last_flow = flow_keys[-1]
            first_pkt_time = self.flows[flow_direction][first_flow][0]['relative_timestamp'].total_seconds()
            if len(flow_keys) > 1:
                last_pkt_time = 0
                for flow_tuple in range(0, len(flow_keys), 1):
                    """Iterates through the last packet of each flow and finds the one with the latest timestamp"""
                    if last_pkt_time < self.flows[flow_direction][flow_keys[flow_tuple]][-1]['relative_timestamp'].total_seconds():
                        last_pkt_time = self.flows[flow_direction][flow_keys[flow_tuple]][-1]['relative_timestamp'].total_seconds()
                flow_direction_duration = last_pkt_time - first_pkt_time
            else:
                last_pkt = self.flows[flow_direction][first_flow][-1]['relative_timestamp'].total_seconds()
                flow_direction_duration = last_pkt - first_pkt_time
            self.flow_direction_rate[flow_direction] = {key: [0, 0] for key in
                                                        range(0, int(flow_direction_duration) + 1, tick)}
            self.flow_rate = {flow: None for flow in self.flows[flow_direction]}
            # print(self.flow_rate)
            for flow in self.flows[flow_direction]:
                if len(self.flows[flow_direction][flow]) > 1:
                    start = self.flows[flow_direction][flow][0]['relative_timestamp'].total_seconds()
                    end = self.flows[flow_direction][flow][-1]['relative_timestamp'].total_seconds()
                    duration = end - start
                else:
                    duration = self.flows[flow_direction][flow][0]['relative_timestamp'].total_seconds()
                # self.flow_rate[flow] = {key: 0 for key in range(0, int(duration)+1, 10)}
                pkt_count = 0
                flow_size = 0
                pkt_size_list = []
                pkt_times = []
                flow_type = None
                for pkt in self.flows[flow_direction][flow]:
                    if flow_type is None or flow_type == "benign":
                        if pkt['ordinal'] in malicious_pkts:
                            flow_type = "malicious"
                        else:
                            flow_type = "benign"
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
                            self.device_activity[i] += payload
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
                # pkt_size_list = np.array(pkt_size_list)
                # self.flow_stats[flow]["mean packet size"] = pkt_size_list.mean()

                # pair_count = 0
                d = 0
                for i in range(0,len(pkt_times)-1 , 1):
                    d += pkt_times[i + 1] - pkt_times[i]
                    # pair_count += 1
                if len(pkt_times) - 1 != 0:
                    inter_pkt_arrival = d / (len(pkt_times) - 1)
                else:
                    inter_pkt_arrival = 0
                # print(inter_pkt_arrival)
                # test = d / (len(pkt_times) - 1)
                # if inter_pkt_arrival != test:
                #     print("test doesn't work")
                # if len(pkt_size_list) > 0:
                #     avg_pkt_size = sum(pkt_size_list) / len(pkt_size_list)
                # else:
                #     avg_pkt_size = 0

                """"Lists for graphs"""
                if flow_direction == "incoming":
                    self.input_flow_stats[flow]["size"] = flow_size
                    self.input_flow_stats[flow]["duration"] = duration
                    self.input_flow_stats[flow]["byte rate"] = flow_size / duration
                    self.input_flow_stats[flow]["pkt rate"] = pkt_count / duration
                    self.input_flow_stats[flow]["avg packet size"] = avg_pkt_size
                    self.input_flow_stats[flow]["jitter"] = inter_pkt_arrival
                    self.input_flow_stats[flow]["pkt count"] = pkt_count
                    self.input_flow_stats[flow]["flow type"] = flow_type
                    # if flow[-1] == "TCP":
                    #     avg_tcp_input_pkt_size.append(avg_pkt_size)
                    #     input_tcp_flow_duration.append(duration)
                    # elif flow[-1] == "UDP":
                    #     avg_udp_input_pkt_size.append(avg_pkt_size)
                    #     input_udp_flow_duration.append(duration)
                elif flow_direction == "outgoing":
                    self.output_flow_stats[flow]["size"] = flow_size
                    self.output_flow_stats[flow]["duration"] = duration
                    self.output_flow_stats[flow]["byte rate"] = flow_size / duration
                    self.output_flow_stats[flow]["pkt rate"] = pkt_count / duration
                    self.output_flow_stats[flow]["avg packet size"] = avg_pkt_size
                    self.output_flow_stats[flow]["jitter"] = inter_pkt_arrival
                    self.output_flow_stats[flow]['pkt count'] = pkt_count
                    self.output_flow_stats[flow]['flow type'] = flow_type
                    # if flow[-1] == "TCP":
                    #     avg_tcp_output_pkt_size.append(avg_pkt_size)
                    #     output_tcp_flow_duration.append(duration)
                    # elif flow[-1] == "UDP":
                    #     avg_udp_output_pkt_size.append(avg_pkt_size)
                    #     output_udp_flow_duration.append(duration)

        # tcp_stats = [avg_tcp_input_pkt_size, input_tcp_flow_duration, avg_tcp_output_pkt_size, output_tcp_flow_duration]
        # udp_stats = [avg_udp_input_pkt_size, input_udp_flow_duration, avg_udp_output_pkt_size, output_udp_flow_duration]

        # self.plot_pkt_size(tcp_stats, udp_stats)
        print("Finish compute attributes")
        # self.get_flow_pairs(flows)
        # self.plot_jitter()

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

    def compare_flow_direction_rate(self, plot_byte):
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
        file_name = ""
        if plot_byte is True:
            ax.plot(input_time_axis, input_byte_rate, label="input flows")
            ax.plot(output_time_axis, output_byte_rate, label="output flows")
            file_name = file_name + "flowdirectionbyterate.png"
        else:
            ax.plot(input_time_axis, input_pkt_rate, label="input flows")
            ax.plot(output_time_axis, output_pkt_rate, label="output flows")
            file_name = file_name + "flowdirectionpktrate.png"
        ax.set_ylabel("Rate (Bytes)")
        ax.set_xlabel("Time (seconds)")
        plt.legend(loc='best')
        plt.savefig(self.device_name + file_name)
        plt.show()

    def get_flow_pairs(self, flows):

        related_flows = []
        for input in list(flows["incoming"].keys()):
            for output in list(flows["outgoing"].keys()):
                if output == (input[1], input[0], input[3], input[2], input[4]):
                    # self.plot_pairs(input, output)
                    self.flow_pairs.append((input, output))

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

    def plot_jitter(self):
        fig = plt.figure()
        ax = fig.add_subplot(1, 1, 1)
        in_jitter = []
        in_count = []
        out_jitter = []
        out_count = []
        n = len(self.flow_pairs)
        color = iter(cm.rainbow(np.linspace(0,1,n)))
        for flow_pair in self.flow_pairs:
            c = next(color)
            in_jitter.append(self.input_flow_stats[flow_pair[0]]["jitter"])
            in_count.append(self.input_flow_stats[flow_pair[0]]["pkt count"])
            out_jitter.append(self.output_flow_stats[flow_pair[1]]["jitter"])
            out_count.append(self.output_flow_stats[flow_pair[1]]["pkt count"])
            ax.scatter(self.input_flow_stats[flow_pair[0]]["pkt count"],self.input_flow_stats[flow_pair[0]]["jitter"],color=c)
            ax.scatter(self.output_flow_stats[flow_pair[1]]["pkt count"], self.output_flow_stats[flow_pair[1]]["jitter"],
                       color=c)
        ax.set_xlabel("No. of packets in flow")
        ax.set_ylabel("Avg jitter of packets (seconds)")
        plt.savefig(self.device_name+"jitter_of_flow_paris.png")
        self.fd_jitter(in_jitter, in_count, out_jitter, out_count)

    def fd_jitter(self, in_jitter, in_count, out_jitter, out_count):
        fig2 = plt.figure()
        ax2 = fig2.add_subplot(1, 1, 1)
        ax2.scatter(in_count, in_jitter, color='r', label="input flow")
        ax2.scatter(out_count, out_jitter, color='b', label="output flow")
        ax2.set_xlabel("No. of packets in flow")
        ax2.set_ylabel("Avg jitter of packets (seconds)")
        fig2.legend('best')
        plt.savefig(self.device_name+"jitter_of_flow_direction.png")
        self.plot_byte_rate()

    def plot_byte_rate(self):
        fig = plt.figure()
        ax = fig.add_subplot(1, 1, 1)
        in_byte = []
        in_pkt = []
        out_byte = []
        out_pkt = []

        n = len(self.flow_pairs)
        color = iter(cm.rainbow(np.linspace(0, 1, n)))
        for flow_pair in self.flow_pairs:
            c = next(color)
            in_byte.append(self.input_flow_stats[flow_pair[0]]["byte rate"])
            in_pkt.append(self.input_flow_stats[flow_pair[0]]["pkt count"])
            out_byte.append(self.output_flow_stats[flow_pair[1]]["byte rate"])
            out_pkt.append(self.output_flow_stats[flow_pair[1]]["pkt count"])
            ax.scatter(self.input_flow_stats[flow_pair[0]]["pkt count"],
                       self.input_flow_stats[flow_pair[0]]["byte rate"],
                       color=c)
            ax.scatter(self.output_flow_stats[flow_pair[1]]["pkt count"],
                       self.output_flow_stats[flow_pair[1]]["byte rate"],
                       color=c)
        ax.set_xlabel("Number of packets")
        ax.set_ylabel("Byte rate (Bytes per second)")
        plt.savefig(self.device_name + "rate_of_flow_paris.png")
        # plt.show()

    def fd_rate(self, in_byte, in_pkt, out_byte, out_pkt):
        fig2 = plt.figure()
        ax2 = fig2.add_subplot(1, 1, 1)
        ax2.scatter(in_byte, in_pkt, color='r', label="input flow")
        ax2.scatter(out_byte, out_pkt, color='b', label="output flow")
        ax2.set_xlabel("Packet rate (packets per second)")
        ax2.set_ylabel("Byte rate (Bytes per second)")
        fig2.legend('best')
        plt.savefig(self.device_name + "rate_of_flow_direction.png")
        self.plot_byte_rate()

    def set_device_activity(self,tick):
        first_pkt_time = 0
        last_pkt_time = 0
        count = 0
        print(self.all_flow_tuples)

        for flow in self.all_flow_tuples:
            count += 1
            direction = None
            if flow in self.flows["incoming"]:
                direction = "incoming"
            else:
                direction = "outgoing"
            if count == 0:
                first_pkt_time = self.flows[direction][flow][0]['relative_timestamp'].total_seconds()
                last_pkt_time = self.flows[direction][flow][-1]['relative_timestamp'].total_seconds()
            if self.flows[direction][flow][0]['relative_timestamp'].total_seconds() < first_pkt_time:
                first_pkt_time = self.flows[direction][flow][0]['relative_timestamp'].total_seconds()
            if self.flows[direction][flow][-1]['relative_timestamp'].total_seconds() > last_pkt_time:
                last_pkt_time = self.flows[direction][flow][-1]['relative_timestamp'].total_seconds()

        duration = last_pkt_time - first_pkt_time
        self.device_activity = {key: 0 for key in range(0, int(duration) +1, tick)}

    def plot_device_traffic(self):
        fig = plt.figure()
        ax = fig.add_subplot(1, 1, 1)
        ax.plot(list(self.device_activity.keys()), list(self.device_activity.values()), color='b')
        ax.set_ylabel("Rate (Bytes/sec)")
        ax.set_xlabel("Time (s)")
        plt.savefig(self.device_name+"traffic.png")
        # plt.show()

    def plot_flow_type(self):
        size = []
        time = []
        mal_size = []
        mal_time = []
        print("flow type plot")
        for flow in self.input_flow_stats:
            flow_size = self.input_flow_stats[flow]['size']
            duration = self.input_flow_stats[flow]['duration']
            print(self.input_flow_stats[flow]['flow type'])
            if self.input_flow_stats[flow]['flow type'] == 'malicious':
                mal_size.append(flow_size)
                mal_time.append(duration)
            else:
                size.append(flow_size)
                time.append(duration)
        for flow in self.output_flow_stats:
            flow_size = self.output_flow_stats[flow]['size']
            duration = self.output_flow_stats[flow]['duration']
            print(self.output_flow_stats[flow]['flow type'])
            if self.output_flow_stats[flow]['flow type'] == 'malicious':
                mal_size.append(flow_size)
                mal_time.append(duration)
            else:
                size.append(flow_size)
                time.append(duration)

        fig = plt.figure()
        ax = fig.add_subplot(1, 1, 1)
        ax.scatter(time, size, color = 'g',label='Benign Traffic')
        ax.scatter(mal_time, mal_size, color='k', label='Malicious Traffic')
        ax.set_xlabel("Flow duration (seconds)")
        ax.set_ylabel("Flow size (Bytes)")
        plt.legend(loc='best')
        plt.savefig(self.device_name+"traffictypes.png")
