from pathlib import Path
import trace_filtering
import klepto as kl
from device import DeviceProfile
import math
import time
import matplotlib.pyplot as plt


def halve_dict(large_dict):
    large_dict = large_dict
    dict1 = dict(list(large_dict.items())[len(large_dict) // 2:])
    dict2 = dict(list(large_dict.items())[:len(large_dict) // 2])
    return dict1, dict2

def save_traffic(NetworkTraffic, file_path,devices):
    path = file_path+str('\_')+NetworkTraffic.file_name
    folder = Path(path)
    if folder.is_dir():
        pass
    else:
        folder.mkdir(parents=True)

    trace_filtering.shelve_network_info(NetworkTraffic, path+'\_network_info')
    for device in devices:
        trace_filtering.shelve_device_traffic(device, path+'\_' +device.device_name + "-db")


def unpickle_objects(file_path, device_filter):
    path = file_path
    database = Path(path)
    import re
    device_objects = []
    count = 0
    limit = 2 #This is for logic testing purposes  math.inf
    files = []
    for network_trace in database.iterdir():
        count += 1
        if count > limit:
            break
        for device_folder in network_trace.iterdir():
            # print(device_folder)
            file_name = re.search('_(.+?)-db', device_folder.name)
            if file_name:
                device_name = file_name.group(1)
                if device_name == device_filter:
                    files.append("20" + str(network_trace)[-8:])
                    device_obj = open_archive(path+'\_'+str(network_trace)[-8:]+'\_'+device_name+'-db')
                    device_objects.append(device_obj)
    return device_objects, files

def open_archive(directory):
    # print(directory)
    d = kl.archives.dir_archive(name=directory, serialized = True)
    # print(d.archive._keydict())
    d.load('ip_addrs')
    # print(d['ip_addrs'])
    d.load('device_traffic')
    d.load('mac_addr')
    d.load('device_name')
    return DeviceProfile(d['device_name'], d['mac_addr'], d['ip_addrs'], d['device_traffic'])

def create_device_plots(devices, malicious_pkts, benign_pkts):

    for device in devices:
        device.update_profile(malicious_pkts, benign_pkts)

def get_malicious_flows(folder_path):
    folder = Path(folder_path)

    malicious_flows = {}
    for file in folder.iterdir():
        if "packet" in file.name:
            with open(file, 'r') as txtfile:
                # mylist = [line.rstrip('\n') for line in txtfile]
                # line = txtfile.readline()
                # print(file.name)
                for line in txtfile:
                    elements = line.split(',')
                    proto = None
                    if elements[6] == '6':
                        proto = "TCP"
                    elif elements[6] == '17':
                        proto = "UDP"
                    date = time.strftime('%Y-%m-%d', time.localtime(int(elements[0])/1000))
                    if date in malicious_flows:
                        malicious_flows[date].append((elements[4], elements[5], int(elements[7]), int(elements[8]), proto))
                    else:
                        malicious_flows[date] = []
                        malicious_flows[date].append((elements[4], elements[5], int(elements[7]), int(elements[8]), proto))
    return malicious_flows

def get_ax():
    fig = plt.figure()
    ax = fig.add_subplot(1, 1, 1)
    return ax

def get_iot_devices(country):
    """Returns a dictionary of IoT devices and their MAC address accroding to the folder in the Northeastern IMC 2019 Dataset.
    The addresses were obtained from manual wireshark inspection """
    uk_wired = ["bosiwo-camera-wired", "wansview-cam-wired"]
    uk_iot_devices = {
        "tplink-plug": "50:c7:bf:b1:d2:78",
        "bosiwo-camera-wired":"ae:ca:06:0e:ec:89",
        "blink-camera":"f4:b8:5e:68:8f:35",
        "charger-camera":"fc:ee:e6:2e:23:a3",
        "honeywell-thermostat": "b8:2c:a0:28:3e:6b",
        "magichome-strip": "dc:4f:22:89:fc:e7",
        "nest-tstat": "64:16:66:2a:98:62",
        "ring-doorbell": "f0:45:da:36:e6:23",
        "sengled-hub": "b0:ce:18:20:43:bf",
        "tplink-bulb":"50:c7:bf:ca:3f:9d",
        "t-wemo-plug":"58:ef:68:99:7d:ed",
        "wansview-cam-wired":"78:a5:dd:28:a1:b7",
        "yi-camera": "0c:8c:24:0b:be:fb"
    }
    us_iot_devices = {
        "phillips-bulb": "34:ce:00:99:9b:83",
        "tplink-plug":"50:c7:bf:5a:2e:a0",
        "tplink-bulb": "50:c7:bf:a0:f3:76",
        "t-phillips-hub": "00:17:88:68:5f:61",
        "zmodo-doorbell":"7c:c7:09:56:6e:48",
    }
    if country == "uk":
        return uk_iot_devices
    elif country == "us":
        return us_iot_devices