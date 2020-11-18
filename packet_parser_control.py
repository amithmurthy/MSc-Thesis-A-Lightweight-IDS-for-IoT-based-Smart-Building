from device import DeviceProfile
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

def parse_dataset():
    dir_path = Path(r"C:\Users\amith\Documents\Uni\Masters\Datasets\UNSW\IoT Traces\Extracted")
    traces = dir_path.glob('*.pcap')
    file_count = 0
    for path in dir_path.rglob('*.pcap'):
        file_count += 1
        # print(path.name)
    print(file_count)

def main():
    # parse_dataset()
    pcap_file = NetworkTrace("16-09-23.pcap")
    # analyse_pcap(pcap_file, "16-09-23.pcap")
    thread = threading.Thread(target=analyse_pcap(pcap_file, "16-09-23.pcap"))
    thread.start()
    thread.join()
    # dropcam = DeviceProfile("Dropcam", "30:8c:fb:2f:e4:b2", pcap_file.mac_to_ip["30:8c:fb:2f:e4:b2"])
    # dropcam.update_profile(pcap_file.device_flows["30:8c:fb:2f:e4:b2"])
    create_device_plots(pcap_file)
    # print("waited for filtering")
    # shelve_network_trace(pcap_file, pcap_file.file_name[0:-5]+"-db")



if __name__ == "__main__":
    main()