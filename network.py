from collections import OrderedDict
import matplotlib.pyplot as plt
import matplotlib.cm as cm
import numpy as np
from datetime import datetime, date
import logging
from pathlib import Path


class NetworkTrace:
    def __init__(self, trace_file, devices = None,*mac_to_ip, **kwargs):
        if len(str(trace_file)) > 20:
            self.file_name = str(trace_file)[-13:-5]
        else:
            self.file_name = trace_file

        if mac_to_ip:
            self.mac_to_ip = mac_to_ip[0]
        else:
            self.mac_to_ip = {}  #Aim is to map device to its IP addresses. A device may have multiple IPs but only one MAC

        if devices is not None:
            self.iot_devices = devices
        else:
            ## Reference: UNSW IoT traffic profile dataset, the information for mac address found at: https://iotanalytics.unsw.edu.au/resources/List_Of_Devices.txt
            self.iot_devices = {"Smart Things": "d0:52:a8:00:67:5e",
                       "Amazon Echo": "44:65:0d:56:cc:d3",
                       "Netatmo Welcom": "70:ee:50:18:34:43",
                       "TP-Link Day Night Cloud camera": "f4:f2:6d:93:51:f1",
                       "Samsung SmartCam": "00:16:6c:ab:6b:88",
                       "Dropcam": "30:8c:fb:2f:e4:b2",
                       "Insteon Camera": "00:62:6e:51:27:2e",
                       "Withings Smart Baby Monitor": "00:24:e4:11:18:a8",
                       "Belkin Wemo switch":"ec:1a:59:79:f4:89",
                       "TP-Link Smart plug": "50:c7:bf:00:56:39",
                       "iHome":"74:c6:3b:29:d7:1d",
                       "Belkin wemo motion sensor": "ec:1a:59:83:28:11",
                       "NEST Protect smoke alarm":"18:b4:30:25:be:e4",
                       "Netatmo weather station":"70:ee:50:03:b8:ac",
                       "Withings Smart scale":"00:24:e4:1b:6f:96",
                       "Blipcare Blood Pressure meter":"74:6a:89:00:2e:25",
                       "Withings Aura smart sleep sensor":"00:24:e4:20:28:c6",
                       "Light Bulbs LiFX Smart Bulb":"d0:73:d5:01:83:08",
                       "Triby Speaker":"18:b7:9e:02:20:44",
                       "PIX-STAR Photo-frame":"e0:76:d0:33:bb:85",
                       "HP Printer":"70:5a:0f:e4:9b:c0",
                       "Samsung Galaxy Tab":"08:21:ef:3b:fc:e3",
                       "Huebulb": "00:17:88:2b:9a:25",
                       "Chromecast": "f4:f5:d8:8f:0a:3c",
                       "Nest Dropcam":"30:8c:fb:b6:ea:45",
                       }
        self.iot_mac_addr = self.iot_devices.values()
        self.non_iot = {
            "Android Phone": "40:f3:08:ff:1e:da",
            "Laptop": "74:2f:68:81:69:42",
            "MacBook": "ac:bc:32:d4:6f:2f",
            "Android Phone": "b4:ce:f6:a7:a3:c2",
            "IPhone": "d0:a6:37:df:a1:e1",
            "MacBook/Iphone": "f4:5c:89:93:cc:85",
            "TPLink Router Bridge LAN (Gateway)": "14:cc:20:51:33:ea"
        }
        self.keys_list = []
        for i in self.iot_devices:
            self.keys_list.append(self.iot_devices[i])
        self.non_iot_addr = []
        for key in self.non_iot:
            self.non_iot_addr.append(self.non_iot[key])
        self.device_traffic = {addr: [] for addr in self.keys_list}  # Key is the device mac address and values are list of packets (dictionaries)
        self.local_device_traffic = {i: [] for i in self.non_iot_addr}
        self.internet_traffic = {}
        # self.flow_table = {}
        self.save_folder = r"C:\Users\amith\Documents\Uni\Masters\Graphs\device_signature"
        self.device_flows = {addr: {'incoming': OrderedDict(), 'outgoing': OrderedDict()} for addr in self.keys_list}
        self.device_flow_stats = {addr: {'incoming': {}, 'outgoing': {}} for addr in self.keys_list}
        self.ordinal_timestamp = kwargs['ordinal_timestamp'] if 'ordinal_timestamp' in kwargs.keys() else None
        # logging.basicConfig(filename=self.file_name[0:-5]+"log", level=logging.DEBUG)

    def flow_stats(self, device):
        """
        Function calculates flow-level statistics for links in all devices or for a specified device
        """
        for flow_direction in self.device_flows[device]:   # flow = flow_tuple i.e. (ip_src, ip_dst, )
            for flow in self.device_flows[device][flow_direction]:
                flow_size = 0
                self.device_flow_stats[device][flow_direction][flow] = []
                self.device_flow_stats[device][flow_direction][flow].append(self.device_flows[device][flow_direction][flow][0]["direction"])
                flow_duration = None
                if len(self.device_flows[device][flow_direction][flow]) > 1:
                    first_pkt_ts = self.device_flows[device][flow_direction][flow][0]['relative_timestamp']
                    last_pkt_ts = self.device_flows[device][flow_direction][flow][-1]['relative_timestamp']
                    flow_duration = abs(last_pkt_ts.total_seconds() - first_pkt_ts.total_seconds())
                else:
                    flow_duration = abs(self.device_flows[device][flow_direction][flow][0]['relative_timestamp'].total_seconds())
                self.device_flow_stats[device][flow_direction][flow].append(flow_duration)
                # pkt_count = 0
                # print(flow, "duration:", flow_duration)
                for packet in self.device_flows[device][flow_direction][flow]:
                    if packet["protocol"] == "TCP":
                        flow_size += packet["tcp_data"]["payload_len"]
                    elif packet["protocol"] == "UDP":
                        flow_size += packet["udp_data"]["payload_len"]
                    elif packet["protocol"] == "ICMP":
                        flow_size += packet["icmp_data"]["payload_len"]
                    else:
                        flow_size += packet['payload_len']
                    # pkt_count += 1
                self.device_flow_stats[device][flow_direction][flow].append(flow_size)
                # self.device_flow_stats[device][flow_direction][flow].append(pkt_count)

    def plot_device_flow(self, device):
        from trace_filtering import PktDirection
        to_internet_x = []
        to_internet_y = []
        from_internet_x = []
        from_internet_y = []
        to_iot_x = []
        to_iot_y = []
        from_iot_x = []
        from_iot_y = []
        to_local_x = []
        to_local_y = []
        from_local_x = []
        from_local_y = []

        """
        Needs to handle incoming vs outgoing. 
        """
        for flow_direction in self.device_flow_stats[device]:
            # print("Flow direction data:",self.device_flow_stats[device][flow_direction])
            for flow in self.device_flow_stats[device][flow_direction]:
                if self.device_flow_stats[device][flow_direction][flow][0].name == PktDirection.iot_to_internet.name:
                    to_internet_x.append(self.device_flow_stats[device][flow_direction][flow][-1])
                    to_internet_y.append(self.device_flow_stats[device][flow_direction][flow][1])
                elif self.device_flow_stats[device][flow_direction][flow][0].name == PktDirection.iot_to_iot.name:
                    to_iot_x.append(self.device_flow_stats[device][flow_direction][flow][-1])
                    to_iot_y.append(self.device_flow_stats[device][flow_direction][flow][1])
                elif self.device_flow_stats[device][flow_direction][flow][0].name == PktDirection.iot_to_local_network.name:
                    to_local_x.append(self.device_flow_stats[device][flow_direction][flow][-1])
                    to_local_y.append(self.device_flow_stats[device][flow_direction][flow][1])
                elif self.device_flow_stats[device][flow_direction][flow][0].name == PktDirection.internet_to_iot.name:
                    from_internet_x.append(self.device_flow_stats[device][flow_direction][flow][-1])
                    from_internet_y.append(self.device_flow_stats[device][flow_direction][flow][1])
                elif self.device_flow_stats[device][flow_direction][flow][0].name == PktDirection.local_network_to_iot.name:
                    from_local_x.append(self.device_flow_stats[device][flow_direction][flow][-1])
                    from_local_y.append(self.device_flow_stats[device][flow_direction][flow][1])

        fig = plt.figure()
        ax = fig.add_subplot(1,1,1)
        ax.scatter(to_internet_x,to_internet_y,color='r', label="IoT -> Internet")
        ax.scatter(to_iot_x, to_iot_y, color='b', label="IoT -> IoT")
        ax.scatter(to_local_x, to_local_y, color='g', label="IoT -> Phone/Laptop")
        ax.scatter(from_internet_x, from_internet_y, color = 'm',label = "Internet -> IoT")
        ax.scatter(from_local_x, from_local_y, color='k',label="Phone -> IoT")
        # plt.xlabel("Flow Duration(seconds)")
        # plt.ylabel("Flow Size (Bytes)")
        # ax.set_xlim(0, max(to_internet_x))
        # ax.set_ylim(0, max(to_internet_y))
        ax.set_ylabel("Flow Duration (ms)")
        ax.set_xlabel("Flow Size (Bytes)")
        plt.legend(loc='best')
        plt.savefig("tpplug.png")
        plt.show()

    def sort_flow(self, flow_tuple, packet_data, flow_direction, protocol):
        """
            1. Function only sorts IoT device traffic flows
            2. First check is for output traffic flow => if device is src
            3. Second check is for input traffic flow => if device is dst
        """
        # print(self.device_flows)
        try:
            # print("src ip in src mac key", flow_tuple[0] in self.mac_to_ip[packet_data['eth_src']])
            # print("dst ip in dst mac key", flow_tuple[1] in self.mac_to_ip[packet_data['eth_dst']])
            assert flow_tuple[0] in self.mac_to_ip[packet_data['eth_src']]
            assert flow_tuple[1] in self.mac_to_ip[packet_data['eth_dst']]
        except AssertionError as e:
            # logging.info("src or dst ip not in mac_to_ip dictionary")
            print("Assertion Error", packet_data['ordinal'])

        if flow_direction == "outgoing":
            # print(flow_tuple)
            # print(packet_data)
            if flow_tuple[0] == packet_data['ip_src'] and flow_tuple[2] == packet_data[protocol]['src_port']:
                if flow_tuple in self.device_flows[packet_data['eth_src']]['outgoing']:
                    self.device_flows[packet_data['eth_src']]['outgoing'][flow_tuple].append(packet_data)
                else:
                    self.device_flows[packet_data['eth_src']]['outgoing'][flow_tuple] = []
                    self.device_flows[packet_data['eth_src']]['outgoing'][flow_tuple].append(packet_data)
        elif flow_direction == "incoming":
            if flow_tuple[1] == packet_data['ip_dst'] and flow_tuple[3] == packet_data[protocol]['dst_port']:
                if flow_tuple in self.device_flows[packet_data['eth_dst']]['incoming']:
                    self.device_flows[packet_data['eth_dst']]['incoming'][flow_tuple].append(packet_data)
                else:
                    self.device_flows[packet_data['eth_dst']]['incoming'][flow_tuple] = []
                    self.device_flows[packet_data['eth_dst']]['incoming'][flow_tuple].append(packet_data)

    def sort_arp_traffic(self, packet_data):
        src = packet_data['eth_src']
        dst = packet_data['eth_dst']
        flow_tuple = (src, dst, packet_data['protocol'])
        """if src is non iot device in lcoal network we don't append to device flows - only interested in iot traffic"""
        if src in self.keys_list:
            if flow_tuple in self.device_flows[src]['outgoing']:
                self.device_flows[src]['outgoing'][flow_tuple].append(packet_data)
            else:
                self.device_flows[src]['outgoing'][flow_tuple] = []
                self.device_flows[src]['outgoing'][flow_tuple].append(packet_data)
        if dst in self.keys_list:
            if flow_tuple in self.device_flows[dst]['incoming']:
                self.device_flows[dst]['incoming'][flow_tuple].append(packet_data)
            else:
                self.device_flows[dst]['incoming'][flow_tuple] = []
                self.device_flows[dst]['incoming'][flow_tuple].append(packet_data)

    def save_legend(self,handles, labels, name):
        fig = plt.figure()
        ax1 = fig.add_subplot(1, 1, 1)
        ax1.legend(handles, labels)
        ax1.xaxis.set_visible(False)
        ax1.yaxis.set_visible(False)
        for v in ax1.spines.values():
            v.set_visible(False)
        plt.savefig(self.file_name+ name)

    def device_signature_plots(self,device_objs):
        import tools
        ax = tools.get_ax()
        ax.set_xlabel("Mean traffic volume (bytes)")
        ax.set_ylabel("Standard deviation traffic volume (bytes)")
        used_colors = []
        def get_unique_colour():
            c = np.random.rand(3,)
            if np.any(used_colors == c):
                c = get_unique_colour()
            else:
                used_colors.append(c)
                return c

        for device_obj in device_objs:
            # if device_obj.device_name == "Dropcam":
            if "Router" in device_obj.device_name:
                continue
            window_vectors = device_obj.create_traffic_volume_features("bidirectional")
            x = []
            y = []
            for k in window_vectors:
                x.append(window_vectors[k]['mean'])
                y.append(window_vectors[k]['std'])
            if len(x) > 1 and len(y) > 1:
                col = get_unique_colour()
                ax.scatter(x, y, label=device_obj.device_name, color=col)
        # plt.legend(loc='best')
        save_path = Path(self.save_folder) / str(self.file_name+'device_signature.png')
        plt.savefig(str(save_path))
        handles, labels = ax.get_legend_handles_labels()
        self.save_legend(handles, labels, "device_signature.png")
        # ax1.figure.savefig('device_signature_legend.jpeg ')
        plt.show()

    def change_device_timestamp(self, device_objs):
        print("changing timestamp")
        count = 0
        for device in device_objs:
            print(device.device_name)
            for direction in device.flows:
                for flow in device.flows[direction]:
                    for pkt in device.flows[direction][flow]:
                        count += 1
                        # print("changed timestamp from {0} to {1}".format(pkt['relative_timestamp'], self.ordinal_timestamp[pkt['ordinal']]))
                        pkt['relative_timestamp'] = self.ordinal_timestamp[pkt['ordinal']]
        print('---------------')
        print("processed file {0}, number of packets {1}".format(self.file_name, count))
        print('---------------')


    def device_flow_direction_signature(self, device_objs):
        import tools
        ax = tools.get_ax()
        plot_name = 'flow_direction_signature.png'
        ax.set_xlabel("Mean traffic volume (bytes)")
        ax.set_ylabel("Standard deviation traffic volume (bytes)")
        ax.set_title("Device flow direction rate signature")
        filter_out = ["PIX-STAR Photo-frame", "iHome"]
        color = iter(cm.rainbow(np.linspace(0, 1, len(device_objs) * 2)))
        used_colors = []

        def get_unique_colour():
            c = np.random.rand(3,)
            if np.any(used_colors == c):
                c = get_unique_colour()
            else:
                used_colors.append(c)
                return c

        for device_obj in device_objs:
            input_vectors = device_obj.create_traffic_volume_features("input")
            output_vectors = device_obj.create_traffic_volume_features("output")
            input_x, input_y = [],[]
            output_x, output_y = [],[]
            for t in input_vectors:
                input_x.append(input_vectors[t]['mean'])
                input_y.append(input_vectors[t]['std'])
            for time in output_vectors:
                output_x.append(output_vectors[time]['mean'])
                output_y.append(output_vectors[time]['std'])
            if len(input_x) > 0 and len(input_y) > 0:
                col = get_unique_colour()
                ax.scatter(input_x, input_y, label=device_obj.device_name + ' inputs', color=col)
            if len(output_x) > 0 and len(output_y) > 0:
                col = get_unique_colour()
                ax.scatter(output_x, output_y, label=device_obj.device_name + ' ouputs', color=col)

        save_path = Path(self.save_folder) / str(self.file_name + plot_name)
        plt.savefig(str(save_path))
        handles, labels = ax.get_legend_handles_labels()
        self.save_legend(handles, labels, plot_name)
        plt.show()