from pathlib import Path
import trace_filtering
import klepto as kl
from device import DeviceProfile

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
    # device_objects = []
    for file in database.rglob(""):
        print(file)
        file_name = re.search('_(.+?)-db', file.name)
        if file_name:
            device_name = file_name.group(1)
            if device_name == device_filter:
                print(device_name)
                device_obj = open_archive(path+'\_'+device_name+'-db')
                # device_objects.append(device_obj)
    return device_obj

def open_archive(directory):
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