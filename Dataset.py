import collections

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
        # self.small_keys.append("14:cc:20:51:33:ea")
        # self.small_keys.append("18:b7:9e:02:20:44")
        self.device_traffic = {addr: [] for addr in self.keys_list}  # Key is the device mac address and values are list of packets (dictionaries)
        # self.device_traffic = {"14:cc:20:51:33:ea":[], "18:b7:9e:02:20:44":[]}
        self.local_deivice_traffic = {addr: [] for addr in self.non_iot.values()}
        self.internet_traffic = {}


