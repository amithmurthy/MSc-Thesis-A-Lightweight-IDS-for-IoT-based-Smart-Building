from tools import *
from collections import OrderedDict
from scapy.layers.l2 import Ether
from io import FileIO
from pathlib import Path
from scapy.all import *
import pandas as pd
from datetime import timezone

class Attacks:

    def __init__(self, device_mac_addr):
        self.device_addr = device_mac_addr
        self.device_name = get_iot_device_name(device_mac_addr)
        self.relative_attack_timestamp = {}
        self.attack_metadata = {} # Keys are timestamps
        self.file_device_traffic_duration = {}
        self.rel_attack_time_file_filter = []
        self.attack_flow_tuples = None # Attack will have bidirectional flows; need them to be appended to relative timestamp
        self.attack_flows_identified = False
        self.attack_flow_issue = []
        self.attack_epochs = {}
        self.attack_epoch_attack_desc = {}
        self.attack_annotations()

    def is_attack_flows_identified(self):
        """Function checks whether a relative attack timestamp has the corresponding flow tuple"""

        def match(string):
            del_list = ["Smurf100L2D2L", "Smurf1L2D2L", "Smurf10L2D2L", "Icmpfeatures|Localfeatures|Allfeatures|LocalICMPPortALL"]
            # match = re.search(pattern, string)
            # if match:
            #     print(pattern, string)
            #     return True
            # else:
            #     return False
            # print("passed in attack type at match", string)
            if string in del_list:
                return True
            else:
                return False

        def check_icmp():
            # print(self.attack_flow_issue)
            for attack_timestamp in self.attack_flow_issue:
                attack_type = self.attack_metadata[attack_timestamp]['attack_type']
                # print(match('smurf', attack_type))
                # print(match('icmp', attack_type))
                if match(attack_type):
                    # print('hit')
                    # self.attack_flow_issue.remove(attack_timestamp)
                    del self.attack_metadata[attack_timestamp]
                    del self.attack_flow_tuples[attack_timestamp]
            return True
            # if len(self.attack_flow_issue) > 0:
            #     for attack in self.attack_flow_issue:
            #         # print("deleted attack types", self.attack_metadata[attack]['attack_type'])
            #         del self.attack_flow_tuples[attack]
            #         # del self.attack_metadata[attack]
            #         self.attack_flow_issue.remove(attack)
            #     return True
            # else:
            #     return True


        for attack in self.attack_flow_tuples:
            if len(self.attack_flow_tuples[attack]) > 0:
                continue
            else:
                print("attack flow tuple not identified", self.attack_metadata[attack]['attack_type'], attack)
                self.attack_flow_issue.append(attack)
        if len(self.attack_flow_issue) == 0:
            self.attack_flows_identified = True
        elif check_icmp() is True:
            self.attack_flows_identified = True

    def get_timestamp_object(self, epoch_window):
        return self.timestamp_objects[epoch_window]

    def attack_annotations(self):
        """TODO: Need to refactor the process of adding to attacks dict"""
        device_mac_addr = get_mac_addr(self.device_name).replace(':', '')
        # print('device mac addr', device_mac_addr)
        annotation_path = Path(r"D:\UNSW Dataset\2018\annotations\annotations") / (
                    device_mac_addr + ".csv")
        col_names = ['start_time', 'end_time', 'attack_features', 'attack_type']
        annotations = pd.read_csv(str(annotation_path), names=col_names)
        attacks = {}  # attack time for each date {'2018-06-01':[(start, end)...],...}
        test = ['18-06-01', '18-06-02', '18-06-05', '18-06-06', '18-10-24', '18-10-22', '18-06-03', '18-10-23']
        def nest_metadata(key, timestamp, start_epoch):
            if key in attacks:
                attacks[key][timestamp] = {
                    'attack_features': annotations.loc[annotations['start_time'] == start_epoch, 'attack_features'].iloc[0],
                    'attack_type': annotations.loc[annotations['start_time'] == start_epoch, 'attack_type'].iloc[0]}

            else:
                attacks[key] = {}
                attacks[key][timestamp] = {
                    'attack_features': annotations.loc[annotations['start_time'] == start_epoch, 'attack_features'].iloc[0],
                    'attack_type': annotations.loc[annotations['start_time'] == start_epoch, 'attack_type'].iloc[0]}


        for start_epoch, end_epoch in zip(annotations['start_time'], annotations['end_time']):
            # start_date = time.strftime('%Y-%m-%d', time.localtime(i))
            start_date = datetime.utcfromtimestamp(start_epoch).strftime('%Y-%m-%d')
            end_date = datetime.utcfromtimestamp(end_epoch).strftime(
                '%Y-%m-%d')  # (time.strftime('%Y-%m-%d', time.localtime(j))[2:])
            t = datetime.fromtimestamp(start_epoch).strftime('%Y-%m-%d')
            start_date, end_date = start_date[2:], end_date[2:]

            self.attack_epochs[start_epoch] = end_epoch
            self.attack_epoch_attack_desc[(start_epoch, end_epoch)] = annotations.loc[annotations['start_time']==start_epoch,'attack_type'].iloc[0]
            # if t != start_date:
            #     print("different date, START:", start_date, "   TEST:", t)
            if start_date == end_date:
                nest_metadata(start_date, (datetime.utcfromtimestamp(start_epoch).strftime('%H:%M:%S'),
                                           datetime.utcfromtimestamp(end_epoch).strftime('%H:%M:%S')), start_epoch)

            else:
                print('attack annotations different dates', start_epoch)
                nest_metadata(start_date, (datetime.utcfromtimestamp(start_epoch).strftime('%H:%M:%S'), "23:59:59"),
                              start_epoch)
                nest_metadata(end_date, ("00:00:00", datetime.utcfromtimestamp(end_epoch).strftime('%H:%M:%S')),
                              start_epoch)

        # if self.device_name == "Light Bulbs LiFX Smart Bulb":
        #     self.link_file_device_time()
        # else:
        device_first_pkt = self.get_attack_file_first_pkt_epoch(attacks)
        self.get_relative_attack_timestamps(device_first_pkt, attacks)
        # print(self.relative_attack_timestamp)
        # print("rel_attack_timestamp struct", self.relative_attack_timestamp)
        # Link relative time to metadata
        for date in self.relative_attack_timestamp:
            relative_timestamps = self.relative_attack_timestamp[date]
            date_timestamps = attacks[date].keys()
            for rel_time, date_time in zip(relative_timestamps, date_timestamps):
                self.attack_metadata[rel_time] = attacks[date][date_time]

    def init_attack_flow_tuples(self):
        try:
            assert len(self.attack_metadata) > 0
        except AssertionError as e:
            print(self.device_name, ' does not have attack metadadata struct')
        self.attack_flow_tuples = {key: [] for key in self.attack_metadata}

    def get_relative_attack_timestamps(self, device_first_pkt, attack_times):
        def attack_duration(attack_datetime):
            fmt = '%H:%M:%S'
            return (datetime.strptime(attack_datetime[1], fmt) - datetime.strptime(attack_datetime[0],
                                                                                   fmt)).total_seconds()

        for file in device_first_pkt:
            # print('first pkt time in file', device_first_pkt[file])
            # print('attack timestamps in file', attack_times[file])
            if file in self.rel_attack_time_file_filter:
                continue
            self.relative_attack_timestamp[file] = []
            first_pkt_time = datetime.strptime(device_first_pkt[file], '%H:%M:%S')
            attack_timestamps = list(attack_times[file].keys())
            for attack_timestamp in attack_timestamps:
                rel_attack_start = ((datetime.strptime(attack_timestamp[0], '%H:%M:%S')) - first_pkt_time).total_seconds()
                rel_attack_duration = attack_duration(attack_timestamp)
                rel_attack_end = rel_attack_start + rel_attack_duration
                self.relative_attack_timestamp[file].append((rel_attack_start, rel_attack_end))
                if rel_attack_start < 0:
                    print('negative time', rel_attack_start, rel_attack_end)

                # print('rel_diff', rel_dif, 'file', file)
                # rel_attack_end = (datetime.strptime(attack_timestamp[1], '%H:%M:%S') - first_pkt_time).total_seconds()
        # print(self.relative_attack_timestamp)

    def get_attack_file_first_pkt_epoch(self, attack_times):
        attack_dataset = Path(r"D:\UNSW Dataset\2018\Attack Data")
        first_pkt_time = {attack_file: None for attack_file in list(attack_times.keys())}
        for pcap in attack_dataset.iterdir():
            if pcap.name[:-5] in list(attack_times.keys()):
                first_pkt_epoch = self.read_pcap(FileIO(pcap))
                # print(first_pkt_epoch)
                first_pkt_time[pcap.name[:-5]] = datetime.utcfromtimestamp(first_pkt_epoch).strftime('%H:%M:%S')
                try:
                    pkt_date = datetime.utcfromtimestamp(first_pkt_epoch).strftime("%Y-%m-%d")
                    # print(pkt_date, "20" + pcap.name[:-5])
                    assert pkt_date == ("20" + pcap.name[:-5])
                except AssertionError:
                    self.rel_attack_time_file_filter.append(pcap.name[:-5])
                    print(self.rel_attack_time_file_filter)
                    print("First pkt date is different to file")
                    print("pkt date", pkt_date)
                    print("file", pcap.name)
                # print('test', datetime.utcfromtimestamp(first_pkt_epoch).strftime('%H:%M:%S'))
        return first_pkt_time

    def link_file_device_time(self):
        """This is for lifx and huebulb """
        def get_first_pkt_time(device_obj):
            smallest_time = None
            for direction in device_obj.flows:
                for flow in device_obj.flows[direction]:
                    start_pkt = device_obj.flows[direction][flow][0]['relative_timestamp']
                    if smallest_time is None:
                        smallest_time = start_pkt
                    else:
                        if start_pkt < smallest_time:
                            smallest_time = start_pkt
                        else:
                            continue
            return smallest_time

        def map_ordinal_rel_time(file, attack_ordinals, device_obj):
            ordinal_time_map = {ordinal: None for ordinal in [element for tupl in attack_ordinals for element in tupl]}
            # print(ordinal_time_map)
            for direction in device_obj.flows:
                flow_table = device_obj.flows[direction]  # Easier readibility. direction flow table
                for flow in flow_table:
                    for pkt in flow_table[flow]:
                        if pkt['ordinal'] in ordinal_time_map:
                            ordinal_time_map[pkt['ordinal']] = pkt['relative_timestamp']
            return ordinal_time_map

        # processed_attack_traffic = r"D:\New back up\Takeout\Drive\UNSW device traffic\Attack"
        processed_attack_traffic = r"C:\Users\amith\Documents\Uni\Masters\JNCA\traffic\processed-traffic\Attack"
        # Get relative ordinals of attack start, end for attack in file
        attack_file_ordinals = attack_ordinals(self.device_name)
        f = [str("_" + file) for file in attack_file_ordinals]
        print("attack ordinal file names", attack_file_ordinals.keys())
        # Get device traffic from these files
        network_instance = unpickle_network_trace_and_device_obj(processed_attack_traffic, devices=self.device_name,
                                                                 files=f)

        for network_obj in network_instance:
            file_rel_pkt_time = None
            for device_obj in network_instance[network_obj]:
                file_rel_pkt_time = get_first_pkt_time(device_obj)
                # Find and set rel_attack time
                attack_file_name = network_obj.file_name[:-5]
                print("attack file", attack_file_name)
                self.relative_attack_timestamp[attack_file_name] = []
                ordinal_time = map_ordinal_rel_time(attack_file_name, attack_file_ordinals[attack_file_name], device_obj)
                for attack_ordinal in attack_file_ordinals[attack_file_name]:
                    if ordinal_time[attack_ordinal[0]] is not None or ordinal_time[attack_ordinal[1]] is not None:
                        start = ordinal_time[attack_ordinal[0]]
                        end = ordinal_time[attack_ordinal[1]]
                        rel_start = start - file_rel_pkt_time
                        rel_end = end - file_rel_pkt_time
                        print('ordinal timestamp', attack_ordinal, (rel_start, rel_end))
                        self.relative_attack_timestamp[attack_file_name].append((rel_start, rel_end))
                    else:
                        print('No timestamp ordianls', attack_ordinal)
        print(self.relative_attack_timestamp)

    def read_pcap(self, pcap_file):
        device_filter = get_mac_addr(self.device_name)
        if self.device_name == "iHome" and "18-10-22.pcap" in str(pcap_file.name):
            print('getting epoch from tools.py')
            return ihome_first_pkt_ordinal("18-10-22.pcap")
        else:
            count = 0
            print('reading', pcap_file)
            for pkt_data, pkt_metadata in RawPcapReader(pcap_file):
                count += 1
                ether_pkt = Ether(pkt_data)
                if ether_pkt.src == device_filter or ether_pkt.dst == device_filter:
                    # print('pkt ordinal', count)
                    return ((pkt_metadata.tshigh << 32) | pkt_metadata.tslow) / pkt_metadata.tsresol
                else:
                    continue

    def get_attack_rate(self, attack_type):
        # print(attack_type)
        x = re.findall('[0-9]+', attack_type)
        if x[0] == '10':
            return '10pps'
        elif x[0] == '100':
            return '100pps'
        else:
            return '1pps'

    def get_flow_attack_rate(self, flow):
        """Return the attack rate of flow passed in"""
        for timestamp in self.attack_flow_tuples:
            if flow in self.attack_flow_tuples[timestamp]:
                # Get attack type from metadata
                print(self.attack_metadata[timestamp]['attack_type'])
                return self.get_attack_rate(self.attack_metadata[timestamp]['attack_type'])


    def get_attack_flows(self, date):
        """Need to get attack flows corresponding to the correct date"""
        relevant_flows = {}
        date_attacks = self.relative_attack_timestamp[date]
        # Need to ensure returned list values are in attack_flow_tuples
        for timestamp in date_attacks:
            if timestamp not in self.attack_flow_tuples:
                continue
            else:
                # print("relevant flows", self.attack_metadata[timestamp])
                for flow in self.attack_flow_tuples[timestamp]:
                    relevant_flows[flow] = self.attack_metadata[timestamp]['attack_type']
        # list(chain(*relevant_flows))
        return relevant_flows

    def identify_attack_flow_type(self, date):
        """Loops through attack_metadata dict and identifies the coarse-grained flows in the attacks."""
        print('identifying attack flow types...')
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
            # attack_rate = self.get_attack_rate(attack_type)
            attack_direction = get_attack_direction(attack_type, attack_protocol)

            def compute_slice():
                pos = None
                if attack_direction == 'bidirectional':
                    pos = -5
                elif attack_direction == 'incoming':
                    pos = -3
                return pos

            def get_location(input_string):
                """Handles attack annotations acronym format to return location"""
                if "W" in input_string:
                    return "internet"
                elif "L" in input_string:
                    return "local"

            str_slice = compute_slice()
            # Turn into key format and return key(s)
            if attack_direction == 'bidirectional':
                incoming_location = get_location(attack_type[str_slice:-2]) + "_inputs"
                outgoing_location = get_location(attack_type[-2:]) + "_outputs"
                # print([incoming_location, outgoing_location])
                return [incoming_location, outgoing_location]
            else:
                incoming_location = get_location(attack_type[str_slice:]) + "_inputs"
                # print([incoming_location])
                return [incoming_location]

        for attack_window in self.relative_attack_timestamp[date]:
            """ Check if flow matches attack traffic protocol before checking whether its in attack_window"""
            # print("date", date, "attack window:", attack_window)
            try:
                attack_type = self.attack_metadata[attack_window]['attack_type'].upper()
            except KeyError as e:
                print(e)
                print(self.relative_attack_timestamp.keys())
                print(self.attack_metadata)
                break
            attack_protocol = get_attack_protocol(attack_type)
            self.attack_metadata[attack_window]['coarse_grained_flows'] = get_attack_location_direction(attack_type, attack_protocol)
        print("DONE...coarse grained flow types appended to metadata dictionary")

