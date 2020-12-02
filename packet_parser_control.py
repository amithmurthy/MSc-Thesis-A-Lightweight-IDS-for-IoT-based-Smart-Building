from io import FileIO
from packet_level_signature import *
from trace_filtering import *
from network import NetworkTrace
import threading
from pathlib import Path
from flow_stats import *
"""
This file controls the filtering and analysis process 

1. Control both network analysis and device analysis
2. Control the graphs plotted
Parse packets and then pickle network object
"""

def get_pcaps(dataset):

    dir_path = Path(dataset)
    traces = dir_path.glob('*.pcap')
    for path in dir_path.rglob('*.pcap'):
        yield path
        # print(path.name)
        # file_list.append(path)
    # paths = []
    # for path in dir_path.rglob('*.pcap'):
    #     paths.append(path)
    # return paths
    # print(file_count)
    # return file_list

def analyse_dataset(dataset, save_path,malicious_pkts,benign_pkts):
    large_attack_files = ["18-06-01", "18-06-02", "18-06-03", "18-06-04", "18-06-05"]
    processed_files = ["16-09-23", "16-09-24", "16-09-25", "16-09-26", "16-09-27", "16-09-28"]

    for file in get_pcaps(dataset):
        print(file)
        if str(file)[-13:-5] in large_attack_files:
            continue
        traffic_file = NetworkTrace(file)
        analyse_pcap(traffic_file, FileIO(file))
        print("creating device objects")
        devices = get_device_objects(traffic_file, malicious_pkts, benign_pkts)
        print("saving traffic")
        save_traffic(traffic_file, save_path, devices)
        processed_files.append(str(file)[-13:-5])

def main():
    # parse_dataset()
    dataset1 = r"C:\Users\amith\Documents\Uni\Masters\Datasets\UNSW\IoT Traces\Extracted"
    attack_dataset = r"C:\Users\amith\Documents\Uni\Masters\Datasets\UNSW\2018\Attack Data"
    benign_dataset = r"C:\Users\amith\Documents\Uni\Masters\Datasets\UNSW\2018\Benign Data"
    # attack_file = "18-10-20.pcap"
    # benign_file = "18-10-29.pcap"
    # test_file = "16-09-23.pcap"
    malicious_pkts = []
    benign_pkts = []
    pkt_rmse = []
    with open('results.pickle', 'rb') as pickle_fd:
        phi = pickle.load(pickle_fd)
        malicious_pkts = pickle.load(pickle_fd)
        benign_pkts = pickle.load(pickle_fd)
        pkt_rmse = pickle.load(pickle_fd)

    attack_file_path = r"C:\Users\amith\Documents\Uni\Masters\processed-traffic\Attack"
    benign_file_path = r"C:\Users\amith\Documents\Uni\Masters\processed-traffic\Benign"
    dataset1_file_path = r"C:\Users\amith\Documents\Uni\Masters\processed-traffic\2016"

    # analyse_dataset(attack_dataset, attack_file_path, malicious_pkts, benign_pkts)
    dropcam = unpickle_objects(dataset1_file_path, "Dropcam")
    model_device_behaviour(dropcam)

    # pcap_file = NetworkTrace(test_file)
    # analyse_pcap(pcap_file, "16-09-23.pcap")
    # thread = threading.Thread(target=analyse_pcap(pcap_file, test_file))
    # thread.start()
    # thread.join()


if __name__ == "__main__":
    iot = ["Smart Things", "Amazon Echo", "Netatmo Welcom", "TP-Link Day Night Cloud camera", "Samsung SmartCam", "Dropcam",
            "Insteon Camera", "Withings Smart Baby Monitor",
            "Belkin Wemo switch", "TP-Link Smart plug", "iHome", "Belkin wemo motion sensor", "NEST Protect smoke alarm",
            "Netatmo weather station", "Withings Smart scale",
            "Blipcare Blood Pressure meter", "Withings Aura smart sleep sensor", "Light Bulbs LiFX Smart Bulb",
            "Triby Speaker", "PIX-STAR Photo-frame",
            "HP Printer", "Samsung Galaxy Tab", "Nest Dropcam", "TPLink Router Bridge LAN (Gateway)"]
    # for device in iot:
    #     path = r"C:\Users\amith\Documents\Uni\Masters\Implementation\plots"
    #     path = path +"\_" + device
    #     folder = Path(path)
    #     folder.mkdir()
    main()

    # thread1 = threading.Thread(target= save_traffic(pcap_file, file_path, devices))
    # thread2 = threading.Thread(target=create_device_plots(devices,malicious_pkts, benign_pkts))
    # thread1.start()
    # thread2.start()
    # thread1.join()

    # create_device_plots(devices,malicious_pkts, benign_pkts)

    # devices_objs = unpickle_objects(file_path, "16-09-23")
    # print(devices_objs)

