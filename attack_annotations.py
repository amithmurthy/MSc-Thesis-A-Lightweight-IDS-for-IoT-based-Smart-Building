from tools import *
from collections import OrderedDict
from scapy.layers.l2 import Ether
from io import FileIO
from pathlib import Path
from scapy.all import *
import pandas as pd

class Attacks():

    def __init__(self, device_mac_addr):
        self.device_name = get_iot_device_name(device_mac_addr)
        self.relative_attack_timestamp = {}
        self.attack_metadata = {}
        self.file_device_traffic_duration = {}
        self.rel_attack_time_file_filter = []
        self.attack_flow_tuples = None # Attack will have bidirectional flows; need them to be appended to relative timestamp
        self.attack_flows_identified = False
        self.attack_flow_issue = []
        self.attack_annotations()
        # print(self.attack_metadata)
        # print(self.relative_attack_timestamp)




    def is_attack_flows_identified(self):
        """Function checks whether a relative attack timestamp has the corresponding flow tuple"""

        def match(pattern, string):
            match = re.search(pattern, string)

            if match:
                return True
            else:
                return False


        def check_icmp():
            for attack_timestamp in self.attack_flow_issue:
                attack_type = self.attack_metadata[attack_timestamp]['attack_type'].lower()
                # print(match('smurf', attack_type))
                # print(match('icmp', attack_type))
                if match('smurf', attack_type) is True or match('icmp', attack_type) is True:
                    # print('hit')
                    self.attack_flow_issue.remove(attack_timestamp)
            if len(self.attack_flow_issue) > 0:
                for attack in self.attack_flow_issue:
                    del self.attack_flow_tuples[attack]
                    self.attack_flow_issue.remove(attack)
                return True
            else:
                return True

        for attack in self.attack_flow_tuples:
            if len(self.attack_flow_tuples[attack]) > 0:
                continue
            else:
                print("attack flow tuple not identified", self.attack_metadata[attack]['attack_type'])
                self.attack_flow_issue.append(attack)
        if len(self.attack_flow_issue) == 0:
            self.attack_flows_identified = True
        elif check_icmp() is True:
            self.attack_flows_identified = True

    def attack_annotations(self):
        """TODO: Need to refactor the process of adding to attacks dict"""
        device_mac_addr = get_mac_addr(self.device_name).replace(':', '')
        # print('device mac addr', device_mac_addr)
        annotation_path = Path(r"C:\Users\amith\Documents\Uni\Masters\Datasets\UNSW\2018\annotations\annotations") / (
                    device_mac_addr + ".csv")
        col_names = ['start_time', 'end_time', 'attack_features', 'attack_type']
        annotations = pd.read_csv(str(annotation_path), names=col_names)
        attacks = {}  # attack time for each date {'2018-06-01':[(start, end)...],...}

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
            start_date, end_date = start_date[2:], end_date[2:]
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
        assert len(self.attack_metadata) > 0
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
        attack_dataset = Path(r"C:\Users\amith\Documents\Uni\Masters\Datasets\UNSW\2018\Attack Data")
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
