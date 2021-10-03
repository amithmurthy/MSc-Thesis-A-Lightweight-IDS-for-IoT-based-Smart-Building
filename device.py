# from network import NetworkTrace
import matplotlib.pyplot as plt
from matplotlib.pyplot import cm
import matplotlib.ticker as ticker
from scipy.interpolate import make_interp_spline, BSpline
import numpy as np
from copy import deepcopy
import statistics
import math
import inspect
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
            self.flow_features = None
            self.internet_output_flows = []
            self.internet_input_flows = []
            self.local_input_flows = []
            self.local_output_flows = []
            self.internet_output_rate = None
            self.internet_output_pkt_rate = None
            self.internet_input_rate = None
            self.internet_input_pkt_rate = None
            self.local_input_rate = None
            self.local_input_pkt_rate = None
            self.local_output_rate = None
            self.local_output_pkt_rate = None
            self.sampling_rate = 10
            self.debug_count = 0
            self.internet_input_duration, self.internet_input_first_pkt = None, None
            self.internet_output_duration, self.internet_output_first_pkt = None, None
            self.local_input_duration, self.local_input_first_pkt = None, None
            self.local_output_duration, self.local_output_first_pkt = None, None
            self.attack_flows = None

        def update_profile(self, malicious_pkts, benign_pkts, compute_attributes=True, *attack_flows):
            """ Additional features/variables
            self.port_profile(self.flows)
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
                                            } for flow in self.flows['outgoing']}"""
            self.all_flow_tuples = [*list(self.flows["incoming"].keys()), *list(self.flows["outgoing"].keys())]
            # self.set_device_activity()
            self.attack_flows = attack_flows[0] if attack_flows else None
            # self.set_flow_direction_rate()
            # self.sort_flow_location()
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

            # print(inspect.currentframe().f_code.co_name)
            for flow in list(self.flows["incoming"].keys()):
                if flow == 0:
                    print('flow key is:', flow)
                for local_addr in local_network_addresses:
                    # Checks if flow tuple ip src is from local network; loops through mac_to_ip mac keys to get related ip. or eth_src if flow is arp
                    if flow[0] in network_obj.mac_to_ip[local_addr] or (flow[-1] == "ARP" and flow[0] in all_local_network_addresses):
                        # Only check ip src since dst is device address
                        self.local_input_flows.append(flow)
                    else:
                        self.internet_input_flows.append(flow)
            for flow in list(self.flows['outgoing'].keys()):
                if flow == 0:
                    print('flow is ', flow)
                for local_addr in local_network_addresses:
                    if flow[1] in network_obj.mac_to_ip[local_addr] or (flow[-1] == "ARP" and flow[0] in all_local_network_addresses):
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

        def get_flow_features(self, flow_pkts, s_rate, w_window, *attack_traffic_interval):
            """"First get throughput of each flow then extract mean/std features over w_window"""

            self.set_sampling_rate(s_rate)
            flow_throughput = self.get_flow_throughput(flow_pkts)

            if attack_traffic_interval:
                return self.extract_flow_features(flow_throughput, w_window, attack_traffic_interval[0])
            else:
                return self.extract_flow_features(flow_throughput, w_window)


        def get_flow_throughput(self, flow_pkts):
            """Function takes in list of packets (flow_pkts) and converts to relative time series vectors for each flow.
            Soting list of dict first instead of finding rel_start and duration manually increases efficiency.
            Sorted() with key-lookup (O(1)) on the list is O(n log n) rather than looping twice which is O(n^2)."""

            if len(flow_pkts) > 1:
                sorted_pkts = sorted(flow_pkts, key=lambda k: k['relative_timestamp'])
                try:
                    assert sorted_pkts[0]['relative_timestamp'] < sorted_pkts[-1]['relative_timestamp']
                except AssertionError:
                    print("ASSERTION ERROR, array not sorted!")
                    print([pkt['relative_timestamp'] for pkt in sorted_pkts])
                duration = int(math.ceil(sorted_pkts[-1]['relative_timestamp'] - sorted_pkts[0]['relative_timestamp']))
            else:
                if len(flow_pkts) == 1:
                    duration = 0
                    sorted_pkts = flow_pkts
                else:
                    print('check:', len(flow_pkts))

            time_series_vectors = {i: [] for i in range(0, duration + self.sampling_rate, self.sampling_rate)}
            for pkt in sorted_pkts:
                time_interval_key = int(((pkt['relative_timestamp'] - sorted_pkts[0][
                    'relative_timestamp']) // self.sampling_rate) * self.sampling_rate)
                time_series_vectors[time_interval_key].append(self.get_payload(pkt))

            return time_series_vectors

        def extract_flow_features(self, time_series_vectors, w_window, *attack_traffic_interval):
            duration = list(time_series_vectors.keys())[-1]
            extracted_features = {}
            attributes = ['byte_count'] # ADD pkt_count to this
            features = ['mean', 'std', 'volume']
            for interval in range(0, duration + 1, w_window):
                extracted_features[interval] = {attr: {feature: [] if feature == 'volume' else None for feature in features} for attr in attributes}
            step = w_window  # w_window
            key = 0
            for time_window in time_series_vectors:
                try:
                    if time_window < (key + step):
                        if time_window == list(time_series_vectors.keys())[-1]:
                            if len(time_series_vectors[time_window]) > 0:
                                # Add only if the s-window is not empty
                                extracted_features[key]['byte_count']['volume'].append(
                                    sum(time_series_vectors[time_window]))
                            self.compute_features(extracted_features[key]['byte_count'])
                        else:
                            extracted_features[key]['byte_count']['volume'].append(sum(time_series_vectors[time_window]))
                    elif time_window == (key + step):
                        extracted_features[key]['byte_count']['volume'].append(sum(time_series_vectors[time_window]))
                        self.compute_features(extracted_features[key]['byte_count'])
                        key += step
                except KeyError as e:
                    if key > duration:
                        print('w_window greater than device traffic duration')
                        break
                    else:
                        print("w_window key error", e)
                        print("extracted_feature keys", extracted_features.keys())
                        print('sampling rate last key', duration)
                #3# print('average tp:', sum(time_series_vectors[x]) / 10)
            # if len(extracted_features.keys()) == 1:
            #     print('debug count', self.debug_count)
            #     print('duration', duration)
            #     print(extracted_features)
            #     print(time_series_vectors)

            # print(extracted_features)
            vectors = {}

            if attack_traffic_interval:
                vectors['mean'], vectors['std'] = self.get_mean_and_std(extracted_features, 'byte_count')
            else:
                vectors['mean'], vectors['std'] = self.get_mean_and_std(extracted_features, 'byte_count')
            # return mean, std values over w_window
            return vectors

        def merge_flow_dict(self):
            """Unnests self.flows dictionary => new dict values points to value in original dict"""
            res = {**self.flows['incoming'], **self.flows['outgoing']}
            # t_key = list(self.flows['incoming'].keys())[0]
            # print("is merged dic value pointing to the same obj?",id(self.flows['incoming'][t_key]) == id(res[t_key]))
            return res


        def plot_attack_flows(self, attack_flows):
            """attack_flows:{(flow_tuple_id): attack_rate}"""

            for flow in attack_flows:
                # Not merging flow_table dict here because it isn't necessary for future operations
                if flow in self.flows['incoming']:
                    flow_pkts = self.flows['incoming'][flow]
                else:
                    flow_pkts = self.flows['outgoing'][flow]
                flow_tp = self.get_flow_throughput(flow_pkts)
                values = [sum(x) for x in list(flow_tp.values())]
                # Create a new plot for each flow so they are not plotted on same canvas
                from tools import get_ax
                from pathlib import Path
                ax = get_ax()
                ax.set_xlabel('Time (seconds)')
                ax.set_ylabel('Throughput (bytes)')
                ax.plot(list(flow_tp.keys()), values, label=attack_flows[flow] + str(flow))
                ax.set_title(attack_flows[flow])
                save_path = Path(r"C:\Users\amith\Documents\Uni\Masters\Graphs\flow_tp") / self.device_name /(flow[-1] + flow[0]+ str(flow[2]) + attack_flows[flow] + ".png")
                plt.savefig(str(save_path))
                plt.show()


        def identify_attack_flows(self, DeviceAttacks, date):
                print('identifying attack flows')
                flow_table = self.merge_flow_dict()

                def get_pkt_time(flow, position):
                    return flow_table[flow][position]['relative_timestamp']

                def get_attack_protocol(attack_type):
                    # attack_type = relevant_metadata[attack_window]['attack_type'].upper()
                    if "TCP" in attack_type:
                        return "TCP"
                    elif 'ARP' in attack_type:
                        return "ARP"
                    elif "SNMP" in attack_type or "UDP" in attack_type or "SSDP" in attack_type:
                        return "UDP"
                    else:
                        return "ICMP"

                def get_attack_direction(attack_type, protocol):
                    """:returns whether its a direct or reflection based attack"""
                    reflective_attack_protocols = ['SNMP', "SSDP"]
                    direct_attack_protocol = ["ARP"]
                    if "REFLECTION" in attack_type or protocol in reflective_attack_protocols:
                        # If reflective attack, the device is both src and destination
                        return 'bidirectional'
                    elif "DEVICE" in attack_type or attack_protocol in direct_attack_protocol:
                        # If direct attack -> device is the destination so "incoming" traffic
                        return "incoming"


                def get_attack_location_direction(attack_type, attack_protocol):
                    """:returns the location of attack traffic/flow"""
                    # local_protocol = ["ARP"]
                    # attack_rate = DeviceAttacks.get_attack_rate(attack_type)
                    attack_direction = get_attack_direction(attack_type, attack_protocol)
                    def compute_slice():
                        pos = None
                        if attack_direction == 'bidirectional':
                            pos = -5
                        elif attack_direction == 'incoming':
                            pos = -3
                        return pos

                    def get_location(input_string):
                        if "W" in input_string:
                            return "internet"
                        elif "L" in input_string:
                            return "local"

                    str_slice = compute_slice()
                    if attack_direction == 'bidirectional':
                        # Turn into key format
                        incoming_location = get_location(attack_type[str_slice:-2]) + "_inputs"
                        outgoing_location = get_location(attack_type[-2:]) + "_outputs"
                        return [incoming_location, outgoing_location]
                    else:
                        incoming_location = get_location(attack_type[str_slice:]) + "_inputs"
                        return incoming_location


                def get_flow_type(location_direction):
                    if location_direction == 'local_inputs':
                        return self.local_input_flows
                    elif location_direction == 'local_outputs':
                        return self.local_output_flows
                    elif location_direction == 'internet_inputs':
                        return self.internet_input_flows
                    elif location_direction == 'internet_outputs':
                        return self.internet_output_flows


                def parse_flows(attack_window, location_direction, attack_protocol):
                    import re
                    attack_features = DeviceAttacks.attack_metadata[attack_window]['attack_features']
                    ip = None
                    ports = None
                    if type(attack_features) is str:
                        ip = re.findall(r'[0-9]+(?:\.[0-9]+){3}', attack_features)
                        ports = re.findall("\d+", attack_features)
                        if len(ports) > 0:
                            ports = ports[:2]
                    print(ports)
                    # flows = get_flow_type(location_direction)
                    for flow in flow_table:
                        flow_start = get_pkt_time(flow, 0)
                        flow_end = get_pkt_time(flow, -1)
                        flow_protocol = flow[-1]
                        if flow_protocol == "ARP":
                            arp_flows.append(flow)
                        # print(flow_protocol)
                        if flow_protocol == attack_protocol:
                            # print('protocol match')
                            attack_start = int(attack_window[0])
                            attack_end = int(attack_window[-1])
                            if attack_start <= flow_start <= attack_end:
                                DeviceAttacks.attack_flow_tuples[attack_window].append(flow)
                                # print('------------------')
                                # print('flow time window:',flow_start, flow_end)
                                # print('attack time window', attack_start, attack_end)
                                # print(flow)
                                # print(attack_window, relevant_metadata[attack_window])
                                # print('------------------')
                            if ip is not None and len(ip) > 0 and ip[0] in flow:
                                if flow not in DeviceAttacks.attack_flow_tuples[attack_window]:
                                    DeviceAttacks.attack_flow_tuples[attack_window].append(flow)
                            if ports is not None and len(ports) > 0:
                                if ports[0] in flow or ports[1] in flow:
                                    if flow not in DeviceAttacks.attack_flow_tuples[attack_window]:
                                        DeviceAttacks.attack_flow_tuples[attack_window].append(flow)
                            # if flow_start <= attack_start and flow_end >= attack_end:
                                """Attack time is in between flow timestamp"""
                                # DeviceAttacks.attack_flow_tuples[attack_window].append(flow)
                        else:
                            continue

                # Loop through each flow in the flow table
                arp_flows = []
                # for flow in flow_table:
                #     flow_start = get_pkt_time(flow, 0)
                #     flow_end = get_pkt_time(flow, -1)
                #     flow_protocol = flow[-1]
                #     if flow_protocol == "ARP":
                #         arp_flows.append(flow)
                #     # print(flow_protocol)

                for attack_window in DeviceAttacks.relative_attack_timestamp[date]:
                    # Check if flow matches attack traffic protocol before checking whether its in attack_window
                    # print(attack_window)
                    # print(DeviceAttacks.relative_attack_timestamp[date])
                    attack_type = DeviceAttacks.attack_metadata[attack_window]['attack_type'].upper()
                    attack_protocol = get_attack_protocol(attack_type)
                    attack_location_direction = get_attack_location_direction(attack_type, attack_protocol)
                    print(attack_location_direction, attack_type)
                    if type(attack_location_direction) is list:
                        for flow_type in attack_location_direction:
                            parse_flows(attack_window, flow_type, attack_protocol)
                    else:
                        parse_flows(attack_window, attack_location_direction, attack_protocol)


                def handle_arp_flows(*visualise):

                    from tools import get_ax
                    if visualise:
                        ax = get_ax()
                    for flow in arp_flows:
                        tp = self.get_flow_throughput(flow_table[flow])
                        values = [sum(x) for x in list(tp.values())]
                        # print(tp)
                        if visualise:
                            # if flow[0] == '2c:27:d7:3b:e1:05':
                            # print(flow)
                            # print(len(flow_table[flow]))
                            # print(tp)
                            ax.plot(list(tp.keys()), values, label=flow[0])
                        if max(values) > 500:
                            DeviceAttacks.attack_flow_tuples[attack_window].append(flow)
                    if visualise:
                        plt.legend(loc='best')
                        plt. show()

                if len(arp_flows) > 0:
                    handle_arp_flows()

        def get_flow_tuple_features(self, *flow_filter):
            """This function loops through each flow in the device flow table and calculates features"""
            self.flow_features = {}

            def get_attack_interval(flow_tuple, DeviceAttacks):
                time_stamps = []
                for attack_timestamp in DeviceAttacks.attack_flow_tuples:
                    if flow_tuple in DeviceAttacks.attack_flow_tuples[attack_timestamp]:
                        time_stamps.append(attack_timestamp)

                return time_stamps

            if flow_filter:
                merged_flow_table = self.merge_flow_dict()
                flow_table = {}
                metadata = flow_filter[0]
                flows = metadata[0]
                DeviceAttacks = metadata[-1]
                for flow in flows:
                    try:
                        flow_table[flow] = merged_flow_table[flow]
                    except KeyError:
                        # print("key in merged flow table", flow in merged_flow_table)
                        # print("key in flow filter", flow in flow_filter[0])
                        # print("len of attack flows", len(flow_filter[0]))
                        continue
            else:
                flow_table = self.merge_flow_dict()
            count = 0



            for flow_tuple in flow_table:
                # self.debug_count += 1
                count += 1

                if count < math.inf:
                    if flow_filter:
                        attack_traffic_interval = get_attack_interval(flow_tuple, DeviceAttacks)
                        self.flow_features[flow_tuple] = self.get_flow_features(flow_table[flow_tuple],10,120,attack_traffic_interval)
                    else:
                        self.flow_features[flow_tuple] = self.get_flow_features(flow_pkts=flow_table[flow_tuple], s_rate=10, w_window=120)
                    # print('std',self.flow_features[flow_tuple]['std'])
                else:
                    break

        def compute_flow_attributes(self,tick, malicious_pkts, benign_pkts):
            # avg_tcp_input_pkt_size = []
            # avg_tcp_output_pkt_size = []
            # avg_udp_input_pkt_size = []
            # avg_udp_output_pkt_size = []
            # input_udp_flow_duration = []
            # input_tcp_flow_duration = []
            # output_tcp_flow_duration = []
            # output_udp_flow_duration = []

            print('computing attributes')
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
                        """Iterates through the last packet of each flow and finds the one with the largest timestamp"""
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
                # self.flow_direction_rate[flow_direction] = {key: [0, 0] for key in range(0, int(flow_direction_duration) + 1, tick)}
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

                    flow_type = None
                    if self.attack_flows is not None:
                        if flow in self.attack_flows:
                            flow_type = "attack"
                        else:
                            flow_type = 'benign'
                    else:
                        flow_type = 'benign'
                    self.flow_rate[flow] = {key: 0 for key in range(0, int(duration)+1, tick)}
                    pkt_count = 0
                    flow_size = 0
                    pkt_size_list = []
                    pkt_times = []
                    for pkt in self.flows[flow_direction][flow]:
                        if flow_type is None or flow_type == "benign":
                            if pkt['ordinal'] in malicious_pkts:
                                flow_type = "attack"
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
                        # flow_time_interval_key = int(((pkt['relative_timestamp'] - start) // tick) * tick)
                        # self.flow_rate[flow][flow_time_interval_key] += payload
                        # for i in range(0, int(duration) + 1, tick):
                        #     # print(pkt['relative_timestamp'].total_seconds())
                        #     # check to make sure pkt is added to right interval for dict (obtianing key)
                        #     if (i <= pkt_ts < i + 1):
                        #         self.flow_rate[flow][i] += payload
                        #         try:
                        #             assert i <= int(duration)
                        #             self.test_rate[i] += payload
                                    #  self.flow_direction_rate[flow_direction][i][0] += 1
                                     # self.flow_direction_rate[flow_direction][i][1] += payload
                                # except KeyError or AssertionError:
                                #     pass
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
                payload = pkt["udp_data"]["payload_len"]
            elif pkt["protocol"] == "ICMP":
                payload = pkt["icmp_data"]["payload_len"]
            else:
                payload = pkt['payload_len']
            if payload is None:
                payload = 0
            return payload

        def set_sampling_rate(self, sampling_rate):
            self.sampling_rate = sampling_rate

        def set_flow_direction_rate(self):

            def set_rate_and_get_first_pkt(flow_direction):
                # for flow_direction in self.flows:
                flow_keys = list(self.flows[flow_direction].keys())
                timestamp_type = "float"
                first_pkt_time = None
                last_pkt_time = None
                for flow in self.flows[flow_direction]:
                    """Iterates through the last packet of each flow and finds the one with the largest timestamp"""
                    if first_pkt_time is None and last_pkt_time is None:
                        first_pkt_time = self.flows[flow_direction][flow][0]['relative_timestamp']
                        last_pkt_time = self.flows[flow_direction][flow][-1]['relative_timestamp']
                    else:
                        if timestamp_type:
                            if last_pkt_time < self.flows[flow_direction][flow][-1]['relative_timestamp']:
                                last_pkt_time = self.flows[flow_direction][flow][-1]['relative_timestamp']
                            if first_pkt_time > self.flows[flow_direction][flow][0]['relative_timestamp']:
                                first_pkt_time = self.flows[flow_direction][flow][0]['relative_timestamp']
                        else:
                            if last_pkt_time < self.flows[flow_direction][flow][-1][
                                'relative_timestamp'].total_seconds():
                                last_pkt_time = self.flows[flow_direction][flow][-1][
                                    'relative_timestamp'].total_seconds()
                            if self.flows[flow_direction][flow][0][
                                    'relative_timestamp'].total_seconds() < first_pkt_time:
                                first_pkt_time = self.flows[flow_direction][flow][0]['relative_timestamp'].total_seconds()

                # flow_direction_duration = last_pkt_time - first_pkt_time
                flow_direction_duration = last_pkt_time - first_pkt_time
                self.flow_direction_rate[flow_direction] = {key: [0, 0] for key in range(0, int(flow_direction_duration) + self.sampling_rate, self.sampling_rate)}
                print("duration", flow_direction_duration)
                return first_pkt_time

            first_input_pkt_time = set_rate_and_get_first_pkt("incoming")
            first_output_pkt_time = set_rate_and_get_first_pkt("outgoing")

            # Set byte count according to flow_direction s-second sample window
            self.set_flow_direction_traffic_rate(direction="incoming", first_pkt_time=first_input_pkt_time)
            self.set_flow_direction_traffic_rate(direction='outgoing', first_pkt_time=first_output_pkt_time)
            print(self.flow_direction_rate['incoming'])
            print(self.flow_direction_rate['outgoing'])

        def set_flow_direction_traffic_rate(self, direction, first_pkt_time):

            for flow in self.flows[direction]:
                for pkt in self.flows[direction][flow]:
                    # Hash pkt_timestamp into flow_direction_rate dictionary
                    time_interval_key = int(((pkt['relative_timestamp'] - first_pkt_time) // self.sampling_rate) * self.sampling_rate)
                    try:
                        self.flow_direction_rate[direction][time_interval_key][1] += self.get_payload(pkt)
                        self.flow_direction_rate[direction][time_interval_key][0] += 1
                    except KeyError as e:
                        # print("device activity dict key error")
                        # print("key:", time_interval_key)
                        if time_interval_key > list(self.flow_direction_rate[direction].keys())[-1]:
                            print('last device activity key smaller than error key', list(self.flow_direction_rate[direction].keys())[-1])
                        print('pkt timestamp', pkt['relative_timestamp'])
                        # print('last timestamp of flow',self.flows[direction][flow][-1]['relative_timestamp'])
                        print(direction, 'Flow tuple', flow)

        def get_location_direction_rate(self, flow_filter, first_pkt_time, rate_dict, pkt_rate_dict, flow_direction):
            # print(inspect.currentframe().f_code.co_name)
            for flow in flow_filter:
                for pkt in self.flows[flow_direction][flow]:
                    time_interval_key = int(((pkt['relative_timestamp'] - first_pkt_time) // self.sampling_rate) * self.sampling_rate)
                    try:
                        pkt_rate_dict[time_interval_key] += 1
                        rate_dict[time_interval_key] += self.get_payload(pkt)
                    except KeyError as e:
                        print("location direction rate dict keky error")
                        print("key not in dict", time_interval_key)
                        print('last key in dict', list(rate_dict.keys())[-1])

        def set_location_direction_rates(self):
            """Function sets the relative duration of location and direction of traffic"""
            def extract_features(first_pkt_time, rel_duration, location_direction):
                if location_direction == 'internet_inputs':
                    self.internet_input_rate = {time_interval: 0 for time_interval in
                                                range(0, rel_duration + self.sampling_rate, self.sampling_rate)}
                    self.internet_input_pkt_rate = {time_interval: 0 for time_interval in
                                                    range(0, rel_duration + self.sampling_rate, self.sampling_rate)}
                    self.get_location_direction_rate(self.internet_input_flows, first_pkt_time, self.internet_input_rate,
                                                     self.internet_input_pkt_rate, "incoming")
                elif location_direction == 'internet_outputs':
                    self.internet_output_rate = {time_interval: 0 for time_interval in
                                                 range(0, rel_duration + self.sampling_rate, self.sampling_rate)}
                    self.internet_output_pkt_rate = {time_interval: 0 for time_interval in
                                                     range(0, rel_duration + self.sampling_rate, self.sampling_rate)}
                    self.get_location_direction_rate(self.internet_output_flows, first_pkt_time, self.internet_output_rate,
                                                     self.internet_output_pkt_rate, 'outgoing')
                elif location_direction == "local_inputs":
                    self.local_input_rate = {time_interval: 0 for time_interval in
                                             range(0, rel_duration + self.sampling_rate, self.sampling_rate)}
                    self.local_input_pkt_rate = {time_interval: 0 for time_interval in
                                                 range(0, rel_duration + self.sampling_rate, self.sampling_rate)}
                    self.get_location_direction_rate(self.local_input_flows, first_pkt_time, self.local_input_rate,
                                                     self.local_input_pkt_rate, "incoming")
                    assert set(self.local_input_rate.keys()) == set(self.local_input_pkt_rate.keys())
                elif location_direction == 'local_outputs':
                    self.local_output_rate = {time_interval: 0 for time_interval in
                                              range(0, rel_duration + self.sampling_rate, self.sampling_rate)}
                    self.local_output_pkt_rate = {time_interval: 0 for time_interval in
                                                  range(0, rel_duration + self.sampling_rate, self.sampling_rate)}
                    self.get_location_direction_rate(self.local_output_flows, first_pkt_time, self.local_output_rate,
                                                     self.local_output_pkt_rate, 'outgoing')

            if self.internet_input_rate is not None:
                self.internet_input_rate = {time_interval: 0 for time_interval in range(0, self.internet_input_duration + self.sampling_rate, self.sampling_rate)}
                self.internet_input_pkt_rate = {time_interval: 0 for time_interval in range(0, self.internet_input_duration + self.sampling_rate, self.sampling_rate)}
                extract_features(self.internet_input_first_pkt, self.internet_input_duration, 'internet_inputs')
                self.internet_output_rate = {time_interval: 0 for time_interval in range(0, self.internet_output_duration + self.sampling_rate, self.sampling_rate)}
                self.internet_output_pkt_rate = {time_interval: 0 for time_interval in range(0, self.internet_output_duration + self.sampling_rate, self.sampling_rate)}
                extract_features(self.internet_output_first_pkt, self.internet_output_duration, 'internet_outputs')
                self.local_input_rate = {time_interval: 0 for time_interval in range(0, self.local_input_duration + self.sampling_rate, self.sampling_rate)}
                self.local_input_pkt_rate = {time_interval: 0 for time_interval in range(0, self.local_input_duration + self.sampling_rate, self.sampling_rate)}
                extract_features(self.local_input_first_pkt, self.local_input_duration, 'local_inputs')
                self.local_output_rate = {time_interval: 0 for time_interval in range(0, self.local_output_duration + self.sampling_rate, self.sampling_rate)}
                self.local_output_pkt_rate = {time_interval: 0 for time_interval in range(0, self.local_output_duration + self.sampling_rate, self.sampling_rate)}
                extract_features(self.local_output_first_pkt, self.local_output_duration, 'local_outputs')
                # print('internet_outputs', self.internet_output_rate.items())
                print('new sampling rate data structures set', self.sampling_rate)

            else:
                internet_input_first_pkt_time, internet_input_relative_duration = self.get_duration_and_first_pkt_time(self.internet_input_flows, "incoming")
                extract_features(internet_input_first_pkt_time,internet_input_relative_duration, "internet_inputs")
                internet_output_first_pkt_time, internet_output_relative_duration = self.get_duration_and_first_pkt_time(self.internet_output_flows, "outgoing")
                # self.internet_output_rate = {time_interval: 0 for time_interval in range(0, internet_output_relative_duration + self.sampling_rate, self.sampling_rate)}
                extract_features(internet_output_first_pkt_time, internet_output_relative_duration, 'internet_outputs')
                # self.get_location_direction_rate(self.internet_output_flows, internet_output_first_pkt_time, self.internet_output_rate, "outgoing")
                local_input_first_pkt_time, local_input_relative_duration = self.get_duration_and_first_pkt_time(self.local_input_flows, "incoming")
                extract_features(local_input_first_pkt_time, local_input_relative_duration, 'local_inputs')
                # self.local_input_rate = {time_interval:0 for time_interval in range(0, local_input_relative_duration + self.sampling_rate, self.sampling_rate)}
                # self.get_location_direction_rate(self.local_input_flows, local_input_first_pkt_time, self.local_input_rate, "incoming")
                local_output_first_pkt_time, local_output_relative_duration = self.get_duration_and_first_pkt_time(self.local_output_flows, "outgoing")
                extract_features(local_output_first_pkt_time, local_output_relative_duration, 'local_outputs')
                # self.local_output_rate = {time_interval: 0 for time_interval in range(0, local_output_relative_duration + self.sampling_rate, self.sampling_rate)}
                # self.get_location_direction_rate(self.local_output_flows, local_output_first_pkt_time, self.local_output_rate, "outgoing")
                self.internet_input_duration, self.internet_input_first_pkt = internet_input_relative_duration, internet_input_first_pkt_time
                self.internet_output_duration, self.internet_output_first_pkt = internet_output_relative_duration , internet_output_first_pkt_time
                self.local_input_duration, self.local_input_first_pkt = local_input_relative_duration, local_input_first_pkt_time
                self.local_output_duration, self.local_output_first_pkt = local_output_relative_duration, local_output_first_pkt_time

                ##Check duration##
                if list(self.local_input_rate.keys())[-1] != list(self.local_output_rate.keys())[-1]:
                    print("local inputs and outputs rate have different durations",list(self.local_input_rate.keys())[-1] , list(self.local_output_rate.keys())[-1])

                if list(self.internet_input_rate.keys())[-1] != list(self.internet_output_rate.keys())[-1]:
                    print("internet inputs and outputs have different durations", list(self.internet_input_rate.keys())[-1], list(self.internet_output_rate.keys())[-1])
                print('data structure set', self.sampling_rate)

        def get_duration_and_first_pkt_time(self, filter, direction):
            first_pkt_time = None
            last_pkt_time = None
            for flow in filter:
                first_flow_pkt_time = self.flows[direction][flow][0]['relative_timestamp']
                last_flow_pkt_time = self.flows[direction][flow][-1]['relative_timestamp']
                if first_pkt_time is None and last_pkt_time is None:
                    first_pkt_time = first_flow_pkt_time
                    last_pkt_time = last_flow_pkt_time
                else:
                    first_pkt_time = first_pkt_time if first_pkt_time < first_flow_pkt_time else first_flow_pkt_time
                    last_pkt_time = last_pkt_time if last_pkt_time > last_flow_pkt_time else last_flow_pkt_time
            return first_pkt_time, int(last_pkt_time-first_pkt_time)

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

        @staticmethod
        def convert_to_KB(byte_list):
            return [x / 1000 for x in byte_list]

        @staticmethod
        def convert_to_min(second_count):
            return [x / 60 for x in second_count]

        @staticmethod
        def convert_to_K(pkt_counts):
            return [x / 1000 for x in pkt_counts]

        def plot_location_direction_rate(self, *date, ):
            fig = plt.figure()
            ax = fig.add_subplot(1, 1, 1)
            from pathlib import Path
            # save_path = Path(r'C:\Users\amith\Documents\Uni\Masters\Graphs\traffic_segregation')
            save_path = Path(r"C:\Users\amith\Documents\Uni\Masters\Graphs\flow_tp")
            ax.plot(self.convert_to_min(list(self.internet_input_rate.keys())), self.convert_to_KB(list(self.internet_input_rate.values())), label='Internet inputs', color='r')
            ax.plot(self.convert_to_min(list(self.internet_output_rate.keys())), self.convert_to_KB(list(self.internet_output_rate.values())), label='Internet outputs', color='b')
            ax.plot(self.convert_to_min(list(self.local_input_rate.keys())), self.convert_to_KB(list(self.local_input_rate.values())), label='Local inputs', color='m')
            ax.plot(self.convert_to_min(list(self.local_output_rate.keys())), self.convert_to_KB(list(self.local_output_rate.values())), label="Local outputs", color='c')
            ax.set_xlabel('Time (minutes)')
            ax.set_ylabel('Byte count (KB)')
            for item in ([ax.title, ax.xaxis.label, ax.yaxis.label] +
                         ax.get_xticklabels() + ax.get_yticklabels()):
                item.set_fontsize(11)
            plt.legend(bbox_to_anchor=(0., 1.02, 1., .102), loc=3,
                       ncol=2, mode="expand", prop={'size':12},borderaxespad=0.)
            trace_file = date[0] if date else ""
            plt.savefig(save_path / (self.device_name + trace_file + "flow_byte_rates.png"))
            plt.show()

        def plot_location_direction_pkt_rate(self, *date):
            from tools import stretch_xaxis
            stretch_xaxis(plt)
            plt.xticks(fontsize=1)
            fig = plt.figure()
            tick_spacing = 2000
            ax = fig.add_subplot(1, 1, 1)
            from pathlib import Path
            # save_path = Path(r'C:\Users\amith\Documents\Uni\Masters\Graphs\pkt_rate')
            save_path = Path(r"C:\Users\amith\Documents\Uni\Masters\Graphs\flow_tp")
            # print(self.internet_input_pkt_rate)
            ax.plot(list(self.internet_input_pkt_rate.keys()), list(self.internet_input_pkt_rate.values()), label='Internet inputs', color='r')
            ax.plot(list(self.internet_output_pkt_rate.keys()), list(self.internet_output_pkt_rate.values()), label='Internet outputs', color='b')
            ax.plot(list(self.local_input_pkt_rate.keys()), list(self.local_input_pkt_rate.values()), label='Local inputs', color='m')
            ax.plot(list(self.local_output_pkt_rate.keys()), list(self.local_output_pkt_rate.values()), label="Local outputs", color='c')
            ax.xaxis.set_major_locator(ticker.MultipleLocator(tick_spacing))
            ax.set_xlabel('Time (minutes)')
            ax.set_ylabel('Packet count')
            for item in ([ax.title, ax.xaxis.label] +
                         ax.get_xticklabels() + ax.get_yticklabels()):
                item.set_fontsize(12.5)
            ax.yaxis.label.set_fontsize(12)
            plt.legend(bbox_to_anchor=(0., 1.02, 1., .102), loc=3,
                       ncol=2, mode="expand", prop={'size': 12}, borderaxespad=0.)
            trace_file = date[0] if date else ""
            save_folder = save_path / self.device_name
            if save_folder.is_dir():
                plt.savefig(str(save_folder / (trace_file + "flow_pkt_rates.png")))
            else:
                save_folder.mkdir()
                plt.savefig(str(save_folder/(trace_file + "flow_pkt_rates.png")))
            plt.show()


        def plot_flow_for_attack_window(self,pkt_rate_dict, label, date):
            from tools import stretch_xaxis, get_graph_save_folder
            stretch_xaxis(plt)
            plt.xticks(fontsize=1)
            fig = plt.figure()
            ax = fig.add_subplot(1,1,1)
            ax.plot(list(pkt_rate_dict.keys()), list(pkt_rate_dict.values()), label=label, color='b')
            save_folder = str(get_graph_save_folder(self.device_name) / (date + label + ".png"))
            tick_spacing = 2000
            ax.set_ylabel('Packet count')
            ax.set_xlabel("Time (seconds)")
            ax.xaxis.set_major_locator(ticker.MultipleLocator(tick_spacing))
            plt.legend(loc='best')
            plt.savefig(save_folder)

        def plot_flow_throughput(self):
            fig = plt.figure()
            ax = fig.add_subplot(1, 1, 1)
            tcp_legend_control = 0
            udp_legend_control = 0
            attack_legend_control = 0
            benign_legend_control = 0
            y_max = 0
            for flow in self.flow_rate:
                # rate = np.linspace(np.array(list(self.flow_rate[flow].values())).min(),np.array(list(self.flow_rate[flow].values())).max(),300)
                rate = list(self.flow_rate[flow].values())
                duration = list(self.flow_rate[flow].keys())
                y_max = max(rate) if max(rate) > y_max else y_max
                if flow[-1] == "TCP":
                    if '58.182.245.89' in flow and '192.168.1.241' in flow and 37356 in flow:
                        print(self.flow_rate[flow])
                        print("flow id", flow)
                #     if tcp_legend_control == 0:
                #         ax.plot(duration, rate, color="b", label="TCP")
                #         tcp_legend_control += 1
                #     else:
                #         ax.plot(duration, rate, color="b")
                # elif flow[-1] == "UDP":
                #     if udp_legend_control == 0:
                #         ax.plot(duration, rate, color="r", label="UDP")
                #         udp_legend_control += 1
                #     else:
                #         ax.plot(duration, rate, color='r')
                if flow in self.attack_flows:
                    if attack_legend_control == 0:
                        ax.plot(duration, rate, color='r', label="Attack")
                        attack_legend_control += 1
                    else:
                        ax.plot(duration, rate, color='r')
                else:
                    if benign_legend_control == 0:
                        ax.plot(duration, rate, color='b', label="Benign")
                        benign_legend_control += 1
                    else:
                        ax.plot(duration, rate, color='b')
            ax.set_ylim(0, y_max)
            ax.set_title("Flow Rates")
            ax.set_ylabel("Throughput")
            ax.set_xlabel("Time (seconds)")
            plt.legend(loc='best')
            plt.savefig(self.device_name+"flow-type-thorughput.png")
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
            # self.plot_byte_rate()

        def set_device_activity(self, *args):
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
            if args:
                return duration
            self.device_activity = {key: 0 for key in range(0, int(duration) +self.sampling_rate, self.sampling_rate)}
            self.get_device_traffic_rate(first_pkt_time)

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
            ax.set_ylabel("Rate (Bytes)")
            ax.set_xlabel("Time (s)")
            plt.savefig(self.device_name+"traffic.png")
            # plt.show()

        def plot_flow_type(self, *plot_name):
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
                if self.input_flow_stats[flow]['flow type'] == 'attack':
                    mal_size.append(flow_size)
                    mal_time.append(duration/3600)
                else:
                    size.append(flow_size)
                    time.append(duration/3600)
            for flow in self.output_flow_stats:
                flow_size = self.output_flow_stats[flow]['size']
                duration = self.output_flow_stats[flow]['duration']
                # print(self.output_flow_stats[flow]['flow type'])
                if self.output_flow_stats[flow]['flow type'] == 'attack':
                    mal_size.append(flow_size)
                    mal_time.append(duration/3600)
                else:
                    size.append(flow_size)
                    time.append(duration/3600)

            # t=[]
            # for value in time:
            #     t.append(value/3600)
            # for value in mal_time:
            plot_name = plot_name[0] if plot_name else ""
            fig = plt.figure()
            ax = fig.add_subplot(1, 1, 1)
            ax.scatter(time, size, color = 'b',label='Benign')
            ax.scatter(mal_time, mal_size, color='r', label='Attack')
            ax.set_xlabel("Flow duration (hours)")
            ax.set_ylabel("Flow size (bytes)")
            plt.legend(loc='best')
            plt.savefig(self.device_name+plot_name+"traffictypes.png")
            plt.show()

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

        def get_rate_type_data_struct(self, traffic_rate_type):
            if traffic_rate_type == "bidirectional":
                return self.device_activity
            elif traffic_rate_type == "input":
                return self.flow_direction_rate['incoming']
            elif traffic_rate_type == "output":
                return self.flow_direction_rate['outgoing']
            elif traffic_rate_type == "internet_inputs":
                return self.internet_input_rate, self.internet_input_pkt_rate
            elif traffic_rate_type == "internet_outputs":
                return self.internet_output_rate, self.internet_output_pkt_rate
            elif traffic_rate_type == "local_inputs":
                return self.local_input_rate, self.local_input_pkt_rate
            elif traffic_rate_type == "local_outputs":
                return self.local_output_rate, self.local_output_pkt_rate

        def compute_features(self, attribute_dict):
            if len(attribute_dict['volume']) > 0:
                attribute_dict['mean'] = sum(attribute_dict['volume']) / len(attribute_dict['volume'])
                attribute_dict['std'] = None if len(attribute_dict['volume']) < 2 else statistics.stdev(attribute_dict['volume'])
            else:
                pass
                # print(self.debug_count)
                # print(attribute_dict['volume'])

        def test(self):
            """Fuction transforms device_activity dictionary from s-second vectors to w-second windows to get extract mean
            standard deviation features in each window"""

            extracted_features = {}
            features = ['volume', 'mean', 'std']
            duration = list(self.device_activity.keys())[-1]
            w_window = 500

            # Initialise feature dictionary and fill values for new w-second window. reference section 5.1.3 https://arxiv.org/pdf/1708.05044.pdf
            for interval in range(0, list(self.device_activity.keys())[-1] + 1, w_window):
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

        def create_traffic_volume_features(self, traffic_rate_type, w_window):
            """Fuction transforms device_activity/flow_direction_rate dictionary from s-second vectors to w-second windows to get extract mean
            standard deviation features in each window"""
            if traffic_rate_type == "bidirectional":
                device_rate_dict = self.device_activity
                pkt_rate_dict = None
            elif traffic_rate_type == "input":
                device_rate_dict = self.flow_direction_rate['incoming']
            elif traffic_rate_type == "output":
                device_rate_dict = self.flow_direction_rate['outgoing']
            elif traffic_rate_type == "internet_inputs":
                device_rate_dict = self.internet_input_rate
                pkt_rate_dict = self.internet_input_pkt_rate
            elif traffic_rate_type == "internet_outputs":
                device_rate_dict = self.internet_output_rate
                pkt_rate_dict = self.internet_output_pkt_rate
            elif traffic_rate_type == "local_inputs":
                device_rate_dict = self.local_input_rate
                pkt_rate_dict = self.local_input_pkt_rate
            elif traffic_rate_type == "local_outputs":
                device_rate_dict = self.local_output_rate
                pkt_rate_dict = self.local_output_pkt_rate




            extracted_features = {}
            attributes = ['byte_count', 'pkt_count']
            features = ['volume', 'mean', 'std']
            duration = list(device_rate_dict.keys())[-1]
            if pkt_rate_dict is not None:
                assert set(device_rate_dict.keys()) == set(pkt_rate_dict.keys())
            # w_window = w_window[0] if w_window else 500
            # Initialise feature dictionary and fill values for new w-second window. reference section 5.1.3 https://arxiv.org/pdf/1708.05044.pdf
            for interval in range(0, duration + 1, w_window):
                extracted_features[interval] = {attr: {feature: [] if feature == 'volume' else None for feature in features} for attr in attributes}
            step = w_window
            test = 0
            for time_window in device_rate_dict:
                if traffic_rate_type != 'incoming' or traffic_rate_type != "outgoing" or traffic_rate_type != 'bidirectional':
                    # structure of flow_direction_rate dictionary (its values are tuples) is different to device_activity
                    byte_count = device_rate_dict[time_window]
                    pkt_count = pkt_rate_dict[time_window]
                else:
                    # time_window value = (pkt_count, byte_count) -> we get byte_count
                    byte_count = device_rate_dict[time_window][1]
                try:
                    if time_window < (test + step):
                        extracted_features[test]['byte_count']['volume'].append(byte_count)
                        extracted_features[test]['pkt_count']['volume'].append(pkt_count)
                    elif time_window == (test + step):
                        extracted_features[test]['byte_count']['volume'].append(byte_count)
                        extracted_features[test]['pkt_count']['volume'].append(pkt_count)
                        self.compute_features(extracted_features[test]['byte_count'])
                        self.compute_features(extracted_features[test]['pkt_count'])
                        test += step
                except KeyError as e:
                    if test > duration:
                        print('w_window greater than device traffic duration')
                        break
                    else:
                        print("w_window key error", e)
                        print("extracted_feature keys", extracted_features.keys())
                        print('sampling rate last key', duration)
            return extracted_features

        def get_mean_and_std(self, rate_vectors, rate_type, *attack_timestamp):
            """Takes in a flow rate vector dict and returns the mean and std"""
            mean = []
            std = []
            attack_windows = None

            if attack_timestamp:
                attack_windows = attack_timestamp[0][0]
                print(attack_windows)

            def append_data(interval):
                mean_i = rate_vectors[interval][rate_type]['mean']
                std_i = rate_vectors[interval][rate_type]['std']
                if mean_i is not None:
                    mean.append(mean_i)
                if std_i is not None:
                    # If std is none => undefined due to flow packet volume being less than 2. Need two data points to calculate std.
                    std.append(std_i)

            def check_interval(interval):
                """Return whether flow interval is in attack window"""
                for extraction_interval in attack_windows:
                    if extraction_interval[0] <= interval <= extraction_interval[1]:
                        return True

            for interval in rate_vectors:
                if attack_windows is not None:
                    if check_interval(interval):
                        append_data(interval)
                    else:
                        continue
                else:
                    # mean_i = rate_vectors[interval][rate_type]['mean']
                    # std_i = rate_vectors[interval][rate_type]['std']
                    append_data(interval)

            return mean, std

        def get_total_byte_count(self, feature_vectors, rate_type):
            """Rate type is either byte_count or pkt count"""
            count_total = []
            for time_window in feature_vectors:
                count_total.append(sum(feature_vectors[time_window][rate_type]['volume']))
            # print(byte_count_total)
            return count_total


        def merge_byte_pkt_count(self, traffic_rate_type, sliding_window):
            """this function is for the first time scale (usually 1 min) feature extraction as only total byte and pkt count are required.
            Sliding window and sampling rate should be the same i.e. 60 second sampling rate => 1 min total byte/pkt count"""
            byte_rate, pkt_rate = self.get_rate_type_data_struct(traffic_rate_type)
            sampling_rate = list(byte_rate.keys())[1] - list(byte_rate.keys())[0]
            assert sampling_rate == sliding_window
            # Check byte rate and pkt rate keys are same i.e. same sampling rate
            assert set(byte_rate.keys()) == set(pkt_rate.keys())
            total_count = {}
            for time_window in byte_rate:
                total_count[time_window] = {}
                total_count[time_window]['byte_count'] = byte_rate[time_window]
                total_count[time_window]['pkt_count'] = pkt_rate[time_window]
            return total_count

        def cluster_device_signature_features(self, w_window, count_type):
            internet_input_vectors = self.create_traffic_volume_features("internet_inputs", w_window=w_window)
            internet_output_vectors = self.create_traffic_volume_features("internet_outputs",w_window=w_window)
            local_input_vectors = self.create_traffic_volume_features("local_inputs",w_window=w_window)
            local_output_vectors = self.create_traffic_volume_features("local_outputs",w_window=w_window)
            fig = plt.figure()
            ax = fig.add_subplot(1, 1, 1)
            internet_input_x, internet_input_y = self.get_mean_and_std(internet_input_vectors, count_type)
            internet_output_x, internet_output_y = self.get_mean_and_std(internet_output_vectors, count_type)
            local_input_x, local_input_y = self.get_mean_and_std(local_input_vectors, count_type)
            local_output_x, local_output_y = self.get_mean_and_std(local_output_vectors, count_type)
            if self.device_name == "Samsung SmartCam":
                print('internet input len',len(internet_input_x), len(internet_input_y))
                print('local input len', len(local_input_x), len(local_input_y))
            ax.scatter(self.convert_to_KB(internet_input_x), self.convert_to_KB(internet_input_y), label='Internet inputs', color='b')
            ax.scatter(self.convert_to_KB(internet_output_x), self.convert_to_KB(internet_output_y), label='Internet outputs', color='r')
            ax.scatter(self.convert_to_KB(local_input_x), self.convert_to_KB(local_input_y), label='Local inputs', color='m')
            ax.scatter(self.convert_to_KB(local_output_x), self.convert_to_KB(local_output_y), label='Local outputs', color='c')
            for item in ([ax.title, ax.xaxis.label, ax.yaxis.label] +
                         ax.get_xticklabels() + ax.get_yticklabels()):
                item.set_fontsize(15)

            name = "Netatmo Cam" if self.device_name == "Netatmo Welcom" else self.device_name
            ax.set_title(self.device_name + " fingerprint")
            ax.set_xlabel("Mean packet count (K)")
            ax.set_ylabel("Packet count standard deviation (K)")
            plt.legend(loc='best', fontsize=13)
            # plt.savefig(self.device_name+'location_direction_signature.png')
            plt.show()

        def get_avg_flow_byte_rate(self):
            flow_types = ['internet_inputs', 'internet_outputs', 'local_inputs', 'local_outputs']
            stats = {flow: {'avg_pkt_size': None, 'avg_byte_rate':[]} for flow in flow_types}

            def compute_avg(flow_vectors, pkt_vector):
                count = sum(list(flow_vectors.values()))
                rate = count / list(flow_vectors.keys())[-1]
                # print(count, rate, list(flow_vectors.keys())[-1])
                pkt_size = count / sum(list(pkt_vector.values()))
                # print(pkt_size, rate)
                return pkt_size, rate

            stats['internet_outputs']['avg_pkt_size'], stats['internet_outputs']['avg_byte_rate'] = compute_avg(self.internet_output_rate, self.internet_output_pkt_rate)
            stats['internet_inputs']['avg_pkt_size'], stats['internet_inputs']['avg_byte_rate'] = compute_avg(self.internet_input_rate, self.internet_input_pkt_rate)
            stats['local_outputs']['avg_pkt_size'], stats['local_outputs']['avg_byte_rate'] = compute_avg(self.local_output_rate, self.local_output_pkt_rate)
            stats['local_inputs']['avg_pkt_size'], stats['local_inputs']['avg_byte_rate'] = compute_avg(self.local_input_rate, self.local_input_pkt_rate)

            return stats

        @staticmethod
        def get_attack_window_data(pkt_rate_time_bin, attack_window):
            vals = []
            keys = []
            pkt_rate_time_bin = pkt_rate_time_bin[0]
            for window in pkt_rate_time_bin:
                if attack_window[0] <= window <= attack_window[1]:
                    vals.append(pkt_rate_time_bin[window])
                    keys.append(window)
            return keys, vals

        def plot_attack_in_flow(self, timestamps, date):
            from tools import get_ax
            from pathlib import Path
            save_path = Path(r"C:\Users\amith\Documents\Uni\Masters\Graphs\CDF_Tests") / self.device_name

            for flow in timestamps:
                ax = get_ax()
                # Get pkt rate dict for flow
                pkt_rate_time_bin = self.get_rate_type_data_struct(flow)[1]
                vals = []
                keys = []
                print(flow)
                for window in pkt_rate_time_bin:
                    for time_stamp in timestamps[flow]:
                        if time_stamp[0] <= window <= time_stamp[1]:
                            vals.append(pkt_rate_time_bin[window])
                            keys.append(window)
                ax.set_ylim(0, max(vals))
                ax.plot(keys, vals, label=flow)
                plt.legend(loc='best')
                plt.savefig(str(save_path / (date+flow+".png")))
                print('attack_time', flow, timestamps[flow])
                plt.show()

        def get_attack_pkt_rate(self, attack_ts, attack_flows):
            in_pkts = self.get_rate_type_data_struct(attack_flows[0])
            input_pkt_rate_bin = self.get_attack_window_data(in_pkts, attack_ts)
            if len(attack_flows) > 1:
                out_pkts = self.get_rate_type_data_struct(attack_flows[1])
                output_pkt_rate_bin = self.get_attack_window_data(out_pkts, attack_ts)
            duration = int(attack_ts[1]) - int(attack_ts[0])
            print("avg input pkt rate", sum(input_pkt_rate_bin[1]) / duration)








        def find_attack_in_coarse_grained_flows(self, DeviceAttacks, date):
            cg_flows = ['local_inputs', 'local_outputs', 'internet_inputs', 'internet_outputs']
            cg_timestamps = {flow: [] for flow in cg_flows}
            for attack_ts in DeviceAttacks.relative_attack_timestamp[date]:
                # print(DeviceAttacks.attack_metadata[attack_ts]['coarse_grained_flows'])
                for flow_type in DeviceAttacks.attack_metadata[attack_ts]['coarse_grained_flows']:
                    cg_timestamps[flow_type].append(attack_ts)
                print(DeviceAttacks.attack_metadata[attack_ts]['attack_type'])
                self.get_attack_pkt_rate(attack_ts, DeviceAttacks.attack_metadata[attack_ts]['coarse_grained_flows'])
            # print(DeviceAttacks.relative_attack_timestamp[date])
            # self.plot_attack_in_flow(cg_timestamps, date)

