import collections
import matplotlib.pyplot as plt
import numpy as np
from datetime import datetime, date
import logging



class NetworkTrace:
    def __init__(self, trace_file):
        self.trace_file = trace_file
        self.mac_to_ip = {}  #Aim is to map device to its IP addresses. A device may have multiple IPs but only one MAC

        ## Reference is UNSW IoT traffic profile dataset, the information for mac address found at: https://iotanalytics.unsw.edu.au/resources/List_Of_Devices.txt
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
                       "Nest Dropcam":"30:8c:fb:b6:ea:45",
                       "TPLink Router Bridge LAN (Gateway)":"14:cc:20:51:33:ea"
                       }
        self.iot_mac_addr = self.iot_devices.values()
        self.non_iot = {
            "Android Phone": "40:f3:08:ff:1e:da",
            "Laptop": "74:2f:68:81:69:42",
            "MacBook": "ac:bc:32:d4:6f:2f",
            "Android Phone": "b4:ce:f6:a7:a3:c2",
            "IPhone": "d0:a6:37:df:a1:e1",
            "MacBook/Iphone": "f4:5c:89:93:cc:85",
        }
        self.keys_list = []
        for i in self.iot_devices:
            self.keys_list.append(self.iot_devices[i])
        self.non_iot_addr = []
        for key in self.non_iot:
            self.non_iot_addr.append(self.non_iot[key])
        # self.small_keys.append("14:cc:20:51:33:ea")
        # self.small_keys.append("18:b7:9e:02:20:44")
        self.device_traffic = {addr: [] for addr in self.keys_list}  # Key is the device mac address and values are list of packets (dictionaries)
        # self.device_traffic = {"14:cc:20:51:33:ea":[], "18:b7:9e:02:20:44":[]}
        self.local_device_traffic = {i: [] for i in self.non_iot_addr}
        self.internet_traffic = {}
        self.flow_table = {}
        logging.basicConfig(filename=trace_file[0:-4]+"log", level=logging.DEBUG)

    def device_flow(self, device):
        #include pkt direction in this
        self.device_flow_stats = {}
        for flow in self.flow_table:
            try:
                assert device in self.mac_to_ip
            except AssertionError as e:
                logging.info("Device traffic not in capture, produced key error:", e)
                print("Device traffic not in capture, produced key error")
            if flow[0] in self.mac_to_ip[device]:
                flow_size = 0
                self.device_flow_stats[flow] = []
                self.device_flow_stats[flow].append(self.flow_table[flow][0]["direction"])
                # print(self.flow_table[flow])
                flow_duration = None
                if len(self.flow_table[flow]) > 1:
                    first_pkt_ts = self.flow_table[flow][0]['relative_timestamp']
                    last_pkt_ts = self.flow_table[flow][-1]['relative_timestamp']
                    flow_duration = abs(last_pkt_ts.total_seconds() - first_pkt_ts.total_seconds())
                else:
                    flow_duration = abs(self.flow_table[flow][0]['relative_timestamp'].total_seconds())
                self.device_flow_stats[flow].append(flow_duration)
                for packet in self.flow_table[flow]:
                    if packet["protocol"] == "TCP":
                        flow_size += packet["tcp_data"]["payload_len"]
                    elif packet["protocol"] == "UDP":
                        flow_size += packet["udp_data"]["payload_len"]
                    elif packet["protocol"] == "ICMP":
                        flow_size += packet["icmp_data"]["payload_len"]
                    else:
                        flow_size += packet['payload_len']
                self.device_flow_stats[flow].append(flow_size)
        return self.device_flow_stats

    def plot_device_flow(self, flow_stats):
        from TraceFiltering import PktDirection
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
        for flow in flow_stats:
            # print("Flow:",flow_stats[flow])
            # print("Direction",flow_stats[flow][0])
            # print("bool:", flow_stats[flow][0] == PktDirection.iot_to_internet)
            if flow_stats[flow][0] == "PktDirection.iot_to_internet":
                to_internet_x.append(flow_stats[flow][-1])
                to_internet_y.append(flow_stats[flow][1])
            elif flow_stats[flow][0] == "PktDirection.iot_to_iot":
                to_iot_x.append(flow_stats[flow][-1])
                to_iot_y.append(flow_stats[flow][1])
            elif flow_stats[flow][0] == "PktDirection.iot_to_local_network":
                to_local_x.append(flow_stats[flow][-1])
                to_local_y.append(flow_stats[flow][1])
            elif str(flow_stats[flow][0]) == "PktDirection.internet_to_iot":
                from_internet_x.append(flow_stats[flow][-1])
                from_internet_y.append(flow_stats[flow][1])
            elif flow_stats[flow][0] == "PktDirection.local_network_to_iot":
                from_local_x.append(flow_stats[flow][-1])
                from_local_y.append(flow_stats[flow][1])

        print(len(to_local_x))
        print(len(from_internet_x))
        fig = plt.figure()
        ax = fig.add_subplot(1,1,1)
        ax.scatter(to_internet_x,to_internet_y,color='r', label="IoT -> Internet")
        ax.scatter(to_iot_x, to_iot_y, color='b', label="IoT -> IoT")
        ax.scatter(to_local_x, to_local_y, color='g', label="IoT -> Phone/Laptop")
        ax.scatter(from_internet_x, from_internet_y, color = 'm',label = "Internet -> IoT")
        ax.scatter(from_local_x, from_local_y, color='k',label="Phone -> IoT")
        # plt.xlabel("Flow Duration(seconds)")
        # plt.ylabel("Flow Size (Bytes)")
        ax.set_xlim(0, max(to_internet_x))
        ax.set_xlim(0, max(to_internet_y))
        ax.set_ylabel("Flow Duration (ms)")
        ax.set_xlabel("Flow Size (Bytes)")
        plt.legend(loc='best')
        plt.savefig("tpplug.png")
        plt.show()