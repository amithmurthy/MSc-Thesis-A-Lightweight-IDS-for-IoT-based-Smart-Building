# from network import NetworkTrace
import matplotlib.pyplot as plt
from matplotlib.pyplot import cm
from scipy.interpolate import make_interp_spline, BSpline
import numpy as np
import statistics
from sklearn.cluster import DBSCAN


class DeviceProfile:

    def __init__(self, device_name, mac_address, ip_addrs, traffic):
        self.device_name = device_name
        self.mac_address = mac_address
        self.ip_addrs = ip_addrs
        self.unique_ports = []
        # self.domains_accessed = []
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
        self.pkt_pairs = None
        self.pkt_sequences = None
        self.distance = None
        self.internet_output_flows = []
        self.internet_input_flows = []
        self.local_input_flows = []
        self.local_output_flows = []
        self.sampling_rate = 5

    def update_profile(self, malicious_pkts, benign_pkts, compute_attributes):
        # self.port_profile(device_traffic)
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
        self.all_flow_tuples = [*list(self.flows["incoming"].keys()), *list(self.flows["outgoing"].keys())]
        # self.set_device_activity(self.sampling_rate)
        # print(self.device_name)
        if compute_attributes is True:
            self.compute_flow_attributes(self.sampling_rate, malicious_pkts, benign_pkts)
        # self.plot_device_traffic()
        # self.compare_flow_direction_rate(True)
        # self.plot_flow_type()
        # self.set_flow_pairs()



    def sort_flow_location(self, network_obj):
        all_local_network_addresses = list(network_obj.iot_devices.values()) + list(network_obj.non_iot.values()) # mac addresses of local network devices
        # local traffic in pcap
        local_network_addresses = [addr for addr in all_local_network_addresses if addr in list(network_obj.mac_to_ip.keys())]

        for flow in list(self.input_flow_stats.keys()):
            for local_addr in local_network_addresses:
                # Checks if flow tuple ip src is from local network; loops through mac_to_ip mac keys to get related ip
                if flow[0] in network_obj.mac_to_ip[local_addr]:
                    # Only check ip src since dst is device address
                    self.local_input_flows.append(flow)
                else:
                    self.internet_input_flows.append(flow)
        for flow in list(self.output_flow_stats.keys()):
            for local_addr in local_network_addresses:
                if flow[1] in network_obj.mac_to_ip[local_addr]:
                    self.local_output_flows.append(flow)
                else:
                    self.internet_output_flows.append(flow)

    def compare_flow_location_traffic(self):
        attributes = ['input_size', 'input_duration', 'output_size', 'output_duration']
        local_traffic = {attr: [] for attr in attributes}
        internet_traffic = {attr: [] for attr in attributes}
        for flow in self.internet_input_flows:
            internet_traffic['input_size'].append(self.input_flow_stats[flow]['size'])
            internet_traffic['input_duration'].append(self.input_flow_stats[flow]['duration'])
        for flow in self.internet_output_flows:
            internet_traffic['output_size'].append(self.output_flow_stats[flow]['size'])
            internet_traffic['output_duration'].append(self.output_flow_stats[flow]['duration'])
        for flow in self.local_input_flows:
            local_traffic['input_size'].append(self.input_flow_stats[flow]['size'])
            local_traffic['input_duration'].append(self.input_flow_stats[flow]['duration'])
        for flow in self.local_output_flows:
            local_traffic['output_size'].append(self.output_flow_stats[flow]['size'])
            local_traffic['output_duration'].append(self.output_flow_stats[flow]['duration'])
        import tools
        # print('local',local_traffic)
        # print('internet',internet_traffic)
        ax = tools.get_ax()
        ax.set_title("Flow direction and location")
        ax.set_xlabel('Flow duration (s)')
        ax.set_ylabel('Flow size (bytes)')
        ax.scatter(local_traffic['input_duration'], local_traffic['input_size'], label='local input flow')
        ax.scatter(local_traffic['output_duration'], local_traffic['output_size'], label='local output flow')
        # ax.scatter(internet_traffic['input_duration'], internet_traffic['input_size'], label='internet input flow')
        # ax.scatter(internet_traffic['output_duration'], internet_traffic['output_size'], label='internet output flow')
        plt.legend(loc='best')
        plt.show()
        plt.savefig(self.device_name + ' flow_location_traffic.png')
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
            if len(flow_keys) == 0:
                continue
            try:
                first_flow = flow_keys[0]
                last_flow = flow_keys[-1]
            except IndexError:
                continue
            timestamp_type = None
            if type(self.flows[flow_direction][first_flow][0]['relative_timestamp']) is float:
                first_pkt_time = self.flows[flow_direction][first_flow][0]['relative_timestamp']
                timestamp_type = "float"
            else:
                first_pkt_time = self.flows[flow_direction][first_flow][0]['relative_timestamp'].total_seconds()

            if len(flow_keys) > 1:
                last_pkt_time = 0
                for flow_tuple in range(0, len(flow_keys), 1):
                    """Iterates through the last packet of each flow and finds the one with the latest timestamp"""
                    if timestamp_type:
                        if last_pkt_time < self.flows[flow_direction][flow_keys[flow_tuple]][-1]['relative_timestamp']:
                            last_pkt_time = self.flows[flow_direction][flow_keys[flow_tuple]][-1]['relative_timestamp']
                    else:
                        if last_pkt_time < self.flows[flow_direction][flow_keys[flow_tuple]][-1]['relative_timestamp'].total_seconds():
                            last_pkt_time = self.flows[flow_direction][flow_keys[flow_tuple]][-1]['relative_timestamp'].total_seconds()
                flow_direction_duration = last_pkt_time - first_pkt_time
            else:
                if timestamp_type:
                    last_pkt = self.flows[flow_direction][first_flow][-1]['relative_timestamp']
                else:
                    last_pkt = self.flows[flow_direction][first_flow][-1]['relative_timestamp'].total_seconds()
                flow_direction_duration = last_pkt - first_pkt_time
            self.flow_direction_rate[flow_direction] = {key: [0, 0] for key in range(0, int(flow_direction_duration) + 1, tick)}
            self.flow_rate = {flow: None for flow in self.flows[flow_direction]}
            # print(self.flow_rate)
            for flow in self.flows[flow_direction]:
                if len(self.flows[flow_direction][flow]) > 1:
                    if timestamp_type:
                        start = self.flows[flow_direction][flow][0]['relative_timestamp']
                        end = self.flows[flow_direction][flow][-1]['relative_timestamp']
                    else:
                        start = self.flows[flow_direction][flow][0]['relative_timestamp'].total_seconds()
                        end = self.flows[flow_direction][flow][-1]['relative_timestamp'].total_seconds()
                    duration = abs(end - start)
                else:
                    if timestamp_type:
                        duration = self.flows[flow_direction][flow][0]['relative_timestamp']
                    else:
                        duration = abs(self.flows[flow_direction][flow][0]['relative_timestamp'].total_seconds())
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
                    if timestamp_type:
                        pkt_ts = pkt['relative_timestamp']
                    else:
                        pkt_ts = pkt['relative_timestamp'].total_seconds()
                    pkt_times.append(pkt_ts)
                    payload = self.get_payload(pkt)
                    flow_size += payload
                    pkt_size_list.append(payload)
                    for i in range(0, int(duration) + 1, tick):
                        # print(pkt['relative_timestamp'].total_seconds())
                        # check to make sure pkt is added to right interval for device_activity
                        if (i <= pkt_ts < i + 1):
                            # self.flow_rate[flow][i] += payload
                            try:
                                assert i <= int(duration)
                                # self.device_activity[i] += payload
                                self.flow_direction_rate[flow_direction][i][0] += 1
                                self.flow_direction_rate[flow_direction][i][1] += payload
                            except KeyError or AssertionError:
                                pass
                    pkt_count += 1

                avg_pkt_size = flow_size / pkt_count
                # pair_count = 0
                d = 0
                for i in range(0,len(pkt_times)-1 , 1):
                    d += pkt_times[i + 1] - pkt_times[i]
                    # pair_count += 1
                if len(pkt_times) - 1 != 0:
                    inter_pkt_arrival = d / (len(pkt_times) - 1)
                else:
                    inter_pkt_arrival = 0

                """"Lists for graphs"""
                try:
                    if flow_direction == "incoming":
                        self.input_flow_stats[flow]["size"] = flow_size
                        self.input_flow_stats[flow]["duration"] = duration
                        self.input_flow_stats[flow]["avg packet size"] = avg_pkt_size
                        self.input_flow_stats[flow]["jitter"] = inter_pkt_arrival
                        self.input_flow_stats[flow]["pkt count"] = pkt_count
                        self.input_flow_stats[flow]["flow type"] = flow_type
                        self.input_flow_stats[flow]["byte rate"] = flow_size / duration if duration != 0 else flow_size
                        self.input_flow_stats[flow]["pkt rate"] = pkt_count / duration if duration != 0 else pkt_count
                        # if flow[-1] == "TCP":
                        #     avg_tcp_input_pkt_size.append(avg_pkt_size)
                        #     input_tcp_flow_duration.append(duration)
                        # elif flow[-1] == "UDP":
                        #     avg_udp_input_pkt_size.append(avg_pkt_size)
                        #     input_udp_flow_duration.append(duration)
                    elif flow_direction == "outgoing":
                        self.output_flow_stats[flow]["size"] = flow_size
                        self.output_flow_stats[flow]["duration"] = duration
                        self.output_flow_stats[flow]["avg packet size"] = avg_pkt_size
                        self.output_flow_stats[flow]["jitter"] = inter_pkt_arrival
                        self.output_flow_stats[flow]['pkt count'] = pkt_count
                        self.output_flow_stats[flow]['flow type'] = flow_type
                        self.output_flow_stats[flow]["byte rate"] = flow_size / duration if duration != 0 else flow_size
                        self.output_flow_stats[flow]["pkt rate"] = pkt_count / duration if duration != 0 else pkt_count
                        # if flow[-1] == "TCP":
                        #     avg_tcp_output_pkt_size.append(avg_pkt_size)
                        #     output_tcp_flow_duration.append(duration)
                        # elif flow[-1] == "UDP":
                        #     avg_udp_output_pkt_size.append(avg_pkt_size)
                        #     output_udp_flow_duration.append(duration)
                except ZeroDivisionError:
                    # print("duration", duration)
                    # print("flow size:",flow_size)
                    # print("pkt count", pkt_count)
                    print("ZeroDivision Error because flow duration is 0 - only 1 packet in flow")
                    pass


        # tcp_stats = [avg_tcp_input_pkt_size, input_tcp_flow_duration, avg_tcp_output_pkt_size, output_tcp_flow_duration]
        # udp_stats = [avg_udp_input_pkt_size, input_udp_flow_duration, avg_udp_output_pkt_size, output_udp_flow_duration]

        # self.plot_pkt_size(tcp_stats, udp_stats)
        # print("Finish compute attributes")
        # self.get_flow_pairs(flows)
        # self.plot_jitter()

    def get_payload(self, pkt):
        if pkt["protocol"] == "TCP":
            payload = pkt["tcp_data"]["payload_len"]
        elif pkt["protocol"] == "UDP":
            payload =  pkt["udp_data"]["payload_len"]
        elif pkt["protocol"] == "ICMP":
            payload =  pkt["icmp_data"]["payload_len"]
        else:
            payload =  pkt['payload_len']

        return payload

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

    def set_flow_pairs(self):
        related_flows = []
        for input in list(self.flows["incoming"].keys()):
            for output in list(self.flows["outgoing"].keys()):
                if output == (input[1], input[0], input[3], input[2], input[4]):
                    # self.plot_pairs(input, output)
                    self.flow_pairs.append((input, output))

    def plot_pairs(self, input, output):
        """
        :param input: input, output flow direction traffic
        :param output: plots traffic of bidirectional flow according to direction
        :return:
        """
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

    def plot_flow_pair_byte_rate(self):
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

    def set_device_activity(self):
        """Function creates vector elements which contain the amount of traffic sent/received (bytes) by the device
        into consecutive s-second samples (tick). """
        first_pkt_time = None
        last_pkt_time = None
        for flow in self.all_flow_tuples:
            direction = None
            if flow in self.flows["incoming"]:
                direction = "incoming"
            else:
                direction = "outgoing"
            # if count == 1:
            """Relative timestamp had a bug so first check is for fixed version"""
            if type(self.flows[direction][flow][0]['relative_timestamp']) is float:
                if first_pkt_time is None and last_pkt_time is None:
                    first_pkt_time = self.flows[direction][flow][0]['relative_timestamp']
                    last_pkt_time = self.flows[direction][flow][-1]['relative_timestamp']
                else:
                    if self.flows[direction][flow][0]['relative_timestamp'] < first_pkt_time:
                        first_pkt_time = self.flows[direction][flow][0]['relative_timestamp']
                    if self.flows[direction][flow][-1]['relative_timestamp'] > last_pkt_time:
                        last_pkt_time = self.flows[direction][flow][-1]['relative_timestamp']
            else:
                print('wrong timestamp logic')
                first_pkt_time = self.flows[direction][flow][0]['relative_timestamp'].total_seconds()
                last_pkt_time = self.flows[direction][flow][-1]['relative_timestamp'].total_seconds()
                if self.flows[direction][flow][0]['relative_timestamp'].total_seconds() < first_pkt_time:
                    first_pkt_time = self.flows[direction][flow][0]['relative_timestamp'].total_seconds()
                if self.flows[direction][flow][-1]['relative_timestamp'].total_seconds() > last_pkt_time:
                    last_pkt_time = self.flows[direction][flow][-1]['relative_timestamp'].total_seconds()

        # print("first pkt time", first_pkt_time)
        # print('last pkt time', last_pkt_time)
        duration = last_pkt_time - first_pkt_time
        print('duration', duration)
        self.device_activity = {key: 0 for key in range(0, int(duration) +self.sampling_rate, self.sampling_rate)}
        self.get_device_traffic_rate(first_pkt_time)
        print(self.device_activity)

    def get_first_and_last_flow(self, directiom):
        flows = list(self.flows[directiom].keys())
        print(type(self.flows))
        return flows[0], flows[-1]

    def get_device_traffic_rate(self, first_pkt_time):
        for flow_direction in self.flows:
            for flow in self.flows[flow_direction]:
                for pkt in self.flows[flow_direction][flow]:
                    # Hash pkt_timestamp into device_activity dictionary
                    time_interval_key = int(((pkt['relative_timestamp'] - first_pkt_time) // self.sampling_rate) * self.sampling_rate)
                    try:
                        self.device_activity[time_interval_key] += self.get_payload(pkt)
                    except KeyError as e:
                        # print("device activity dict key error")
                        print("key:", time_interval_key)
                        if time_interval_key > list(self.device_activity.keys())[-1]:
                            print('last device activity key smaller than error key', list(self.device_activity.keys())[-1])
                        print('pkt timestamp', pkt['relative_timestamp'])
                        print('last timestamp of flow',self.flows[flow_direction][flow][-1]['relative_timestamp'])
                        print(flow_direction, 'Flow tuple', flow)



    def plot_device_traffic(self, x=None, y=None):
        fig = plt.figure()
        ax = fig.add_subplot(1, 1, 1)
        if x is None and y is None:
            ax.plot(list(self.device_activity.keys()), list(self.device_activity.values()), color='b')
        else:
            ax.plot(x, y, color='k')
        ax.set_ylabel("Size (Bytes)")
        ax.set_xlabel("Time (s)")
        plt.savefig(self.device_name+"traffic.png")
        # plt.show()

    def plot_flow_type(self):
        """This function is to compare attack and benign flow traffic"""
        size = []
        time = []
        mal_size = []
        mal_time = []
        print("flow type plot")
        for flow in self.input_flow_stats:
            flow_size = self.input_flow_stats[flow]['size']
            duration = self.input_flow_stats[flow]['duration']
            # print(self.input_flow_stats[flow]['flow type'])
            if self.input_flow_stats[flow]['flow type'] == 'malicious':
                mal_size.append(flow_size)
                mal_time.append(duration)
            else:
                size.append(flow_size)
                time.append(duration)
        for flow in self.output_flow_stats:
            flow_size = self.output_flow_stats[flow]['size']
            duration = self.output_flow_stats[flow]['duration']
            # print(self.output_flow_stats[flow]['flow type'])
            if self.output_flow_stats[flow]['flow type'] == 'malicious':
                mal_size.append(flow_size)
                mal_time.append(duration)
            else:
                size.append(flow_size)
                time.append(duration)
        t=[]
        for value in time:
            t.append(value/3600)
        # for value in mal_time:

        fig = plt.figure()
        ax = fig.add_subplot(1, 1, 1)
        ax.scatter(t, size, color = 'g',label='Benign Traffic')
        # ax.scatter(mal_time, mal_size, color='k', label='Malicious Traffic')
        ax.set_xlabel("Flow duration (hours)")
        ax.set_ylabel("Flow size (bytes)")
        plt.legend(loc='best')
        plt.savefig(self.device_name+"traffictypes.png")

    def get_flow_jitter(self, flow):
        """This function is intended mainly for analysing command traffic => return pkt number and its associated jitter in the flow"""
        pkt_no = []
        pkt_jitter = []
        if len(flow) > 1:
            for i in range(0, len(flow) -1, 1):
                pkt_jitter.append((flow[i+1]['relative_timestamp'] - flow[i]['relative_timestamp']) * 1000) # in milliseconds
                pkt_no.append(i)

        return pkt_no, pkt_jitter

    def compare_command_flow_direction_jitter(self, input_pkt_no, input_jitter, output_pkt_no, output_jitter, save_folder, iteration, location):
        from tools import get_ax
        ax = get_ax()
        ax.plot(input_pkt_no, input_jitter, label='input flow')
        ax.plot(output_pkt_no, output_jitter, label='output flow')
        ax.set_ylabel("Jitter (ms)")
        ax.set_xlabel("packet number")
        plt.legend(loc="best")
        print(save_folder)
        plt.savefig(save_folder + location + "commandjitter" + str(iteration) + ".png")
        print("flow jitter comparison plotted")

    def create_traffic_volume_features(self):
        """Fuction transforms device_activity dictionary from s-second vectors to w-second windows to get extract mean
        standard deviation features in each window"""


        extracted_features = {}
        features = ['volume', 'mean', 'std']
        duration = list(self.device_activity.keys())[-1]
        w_window = 500

        #Initialise feature dictionary and fill values for new w-second window. reference section 5.1.3 https://arxiv.org/pdf/1708.05044.pdf
        for interval in range(0,list(self.device_activity.keys())[-1] + 1, w_window):
            extracted_features[interval] = {feature: [] if feature == 'volume' else None for feature in features}
        print(extracted_features.keys())
        step = w_window
        for time_window in self.device_activity:
            try:
                if time_window < w_window:
                    extracted_features[w_window]['volume'].append(self.device_activity[time_window])
                elif time_window == w_window:
                    extracted_features[w_window]['volume'].append(self.device_activity[time_window])
                    extracted_features[w_window]['mean'] = statistics.mean(extracted_features[w_window]['volume'])
                    extracted_features[w_window]['std'] = statistics.stdev(extracted_features[w_window]['volume'])
                    w_window += step
            except KeyError as e:
                if w_window > duration:
                    break
                else:
                    print("key error", e)
                    print("extracted_feature keys", extracted_features.keys())
                    print('sampling rate last key', duration)
        return extracted_features