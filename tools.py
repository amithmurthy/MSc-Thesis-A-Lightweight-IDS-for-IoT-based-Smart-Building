from pathlib import Path
import trace_filtering
from device import DeviceProfile

def halve_dict(large_dict):
    large_dict = large_dict
    dict1 = dict(list(large_dict.items())[len(large_dict) // 2:])
    dict2 = dict(list(large_dict.items())[:len(large_dict) // 2])
    return dict1, dict2

def save_traffic(NetworkTraffic, file_path,devices):
    path = file_path+str('\_')+NetworkTraffic.file_name[0:-5]
    folder = Path(path)
    if folder.is_dir():
        pass
    else:
        folder.mkdir(parents=True)

    trace_filtering.shelve_network_info(NetworkTraffic, path+'\_network_info')
    for device in devices:
        trace_filtering.shelve_device_traffic(device, path+'\_' +device.device_name + "-db")

def create_device_plots(devices, malicious_pkts, benign_pkts):
    for device in devices:
        device.update_profile(malicious_pkts, benign_pkts)