
from packet_level_signature import *
from trace_filtering import *
from network import NetworkTrace
import threading
from pathlib import Path
"""
This file controls the filtering and analysis process 

1. Control both network analysis and device analysis
2. Control the graphs plotted
Parse packets and then pickle network object
"""

def get_pcaps():
    dir_path = Path(r"C:\Users\amith\Documents\Uni\Masters\Datasets\UNSW\IoT Traces\Extracted")
    traces = dir_path.glob('*.pcap')
    file_list = []
    for path in dir_path.rglob('*.pcap'):
        yield path
        # print(path.name)
        # file_list.append(path)
    # print(file_count)
    # return file_list

def analyse_dataset():
    for file in get_pcaps():
        traffic = NetworkTrace(file)


def main():
    # parse_dataset()
    attack_file = "18-10-20.pcap"
    # benign_file = "18-10-29.pcap"
    test_file = "16-09-23.pcap"
    # for file in get_pcaps():
    #     print(file)
        # traffic = NetworkTrace(file)
        # analyse_pcap(traffic)
    pcap_file = NetworkTrace(test_file)
    # analyse_pcap(pcap_file, "16-09-23.pcap")
    thread = threading.Thread(target=analyse_pcap(pcap_file, test_file))
    thread.start()
    thread.join()
    malicious_pkts = []
    benign_pkts = []
    pkt_rmse = []
    with open('results.pickle', 'rb') as pickle_fd:
        phi = pickle.load(pickle_fd)
        malicious_pkts = pickle.load(pickle_fd)
        benign_pkts = pickle.load(pickle_fd)
        pkt_rmse = pickle.load(pickle_fd)

    # dropcam = DeviceProfile("Dropcam", "30:8c:fb:2f:e4:b2", pcap_file.mac_to_ip["30:8c:fb:2f:e4:b2"])
    # dropcam.update_profile(pcap_file.device_flows["30:8c:fb:2f:e4:b2"])
    # print("test")
    devices = get_device_objects(pcap_file, malicious_pkts, benign_pkts)
    file_path = r"C:\Users\amith\Documents\Uni\Masters\processed-traffic"
    # thread1 = threading.Thread(target= save_traffic(pcap_file, file_path, devices))
    # thread2 = threading.Thread(target=create_device_plots(devices,malicious_pkts, benign_pkts))
    # thread1.start()
    # thread2.start()
    # thread1.join()
    save_traffic(pcap_file, file_path, devices)
    # create_device_plots(devices,malicious_pkts, benign_pkts)

if __name__ == "__main__":
    main()