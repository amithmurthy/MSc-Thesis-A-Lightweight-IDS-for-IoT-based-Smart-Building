from io import FileIO
from packet_level_signature import *
from trace_filtering import *
from network import NetworkTrace
import threading
from pathlib import Path
from flow_stats import *
import os
"""
This file controls the filtering and analysis process 

1. Control both network analysis and device analysis
2. Control the graphs plotted
Parse packets and then pickle network object
"""
iot = ["Smart Things", "Amazon Echo", "Netatmo Welcom", "TP-Link Day Night Cloud camera", "Samsung SmartCam", "Dropcam",
            "Insteon Camera", "Withings Smart Baby Monitor",
            "Belkin Wemo switch", "TP-Link Smart plug", "iHome", "Belkin wemo motion sensor", "NEST Protect smoke alarm",
            "Netatmo weather station", "Withings Smart scale",
            "Blipcare Blood Pressure meter", "Withings Aura smart sleep sensor", "Light Bulbs LiFX Smart Bulb",
            "Triby Speaker", "PIX-STAR Photo-frame",
            "HP Printer", "Samsung Galaxy Tab", "Nest Dropcam", "TPLink Router Bridge LAN (Gateway)"]

infected_devices = ["Belkin wemo motion sensor", "Belkin Wemo switch", "Samsung SmartCam", "Light Bulbs LiFX Smart Bulb","TP-Link Smart plug", "Netatmo Welcom",
                    "Amazon Echo", "iHome"]

device_events = {
    "tplink-plug": {
        'alexa_off': "2019-05-04_15_27_41.24s",
        "alexa_on": "2019-04-28_15_52_32.23s",
        "power": "2019-04-26_12_41_34.198s"},
    "ring-doorbell": {
        'alexa_stop': "2019-04-26_17_30_24.22s",
        'alexa_watch': "2019-04-26_18_46_31.22s",
        'local_move': "2019-04-26_15_52_31.101s",
        'android_wan_watch': "2019-04-29_10_54_20.47s",
        "android_lan_watch": "2019-04-28_15_44_57.47s",
        'power': "2019-04-26_12_23_33.215s"}
}

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

def analyse_device_events(file_path, device):
    # this is where the pcaps are stored
    dir_path = Path(file_path) / device
    command_folders = Path(dir_path)
    country = str(file_path)[-2:] # either the us or uk depends on the file path
    iot_devices = get_iot_devices(country)
    # for obj in iot_devices:
    #     path = r"C:\Users\amith\Documents\Uni\Masters\Implementation\commands"
    #     path = Path(path) / country / obj
    #     folder = Path(path)
    #     if folder.is_dir():
    #         pass
    #     else:
    #         folder.mkdir()
    iot_objects = {}
    non_iot_objects = {}
    for command in command_folders.iterdir():
        # if file.name in device_events[device]:
            # print(file.name)
        iot_objects[command.name] = []
        non_iot_objects[command.name] = []
        for pcap in command.iterdir():
            # print(pcap.name)
            # if pcap.name[0:-5] in device_events[device][file.name]:
            print("analysing pcap", pcap.name)
            traffic_file = NetworkTrace(pcap, devices=iot_devices)
            analyse_pcap(traffic_file, FileIO(pcap))
            print("creating device objs from pcap")
            device_list = get_device_objects(traffic_file, [], [])
            for device_obj in device_list:
                if device_obj.mac_address == iot_devices[device]:
                    iot_objects[command.name].append(device_obj)
                else:
                    non_iot_objects[command.name].append(device_obj)
    # print("iot_objects:",iot_objects)
    # model_command_traffic(iot_objects, country, device)
    for device_obj in iot_objects["alexa_on"]:
        device_obj.extract_command_traffic_signatures()
    # for command_name in iot_objects:
    #     # Saving graphs in appropriate folders i.e. accroding to the command
    #     save_graph_path = Path(plots_folder) / country / device / command_name
    #     save_folder = Path(save_graph_path)
    #     if save_folder.is_dir():
    #         pass
    #     else:
    #         save_folder.mkdir()
    #     plot_command_traffic = model_device_behaviour(device_trafic_objects=iot_objects[command_name], dates=None, mal_flows={}, save_folder=save_folder, behaviour_type="benign")
    #     if plot_command_traffic:
    #         print(plot_command_traffic)
    #         continue


def main():
    process_moniotr_file_path = r"C:\Users\amith\Documents\Uni\Masters\processed-traffic\moniotr"
    northeastern_dataset_uk = r"D:\Mon(IoT)r\iot-data\uk"
    analyse_device_events(northeastern_dataset_uk, "tplink-plug")
    # devices = get_iot_devices("uk")
    # for device in devices:
    #     if device != "yi-camera" or device != "tplink-plug":
    #         analyse_device_events(northeastern_dataset_uk, device)

    # analyse_device_events(dataset_file_paths['tplink-plug'], "tplink-plug")
    # analyse_device_events(dataset_file_paths['ring-doorbell'], "ring-doorbell")
    # parse_dataset()
    dataset1 = r"C:\Users\amith\Documents\Uni\Masters\Datasets\UNSW\IoT Traces\Extracted"
    attack_dataset = r"C:\Users\amith\Documents\Uni\Masters\Datasets\UNSW\2018\Attack Data"
    benign_dataset = r"C:\Users\amith\Documents\Uni\Masters\Datasets\UNSW\2018\Benign Data"
    # attack_file = "18-10-20.pcap"
    # benign_file = "18-10-29.pcap"
    # test_file = "16-09-23.pcap"
    # pcap_file = NetworkTrace(test_file)
    # analyse_pcap(pcap_file, "16-09-23.pcap")
    malicious_pkts = []
    benign_pkts = []
    pkt_rmse = []
    # with open('results.pickle', 'rb') as pickle_fd:
    #     phi = pickle.load(pickle_fd)
    #     malicious_pkts = pickle.load(pickle_fd)
    #     benign_pkts = pickle.load(pickle_fd)
    #     pkt_rmse = pickle.load(pickle_fd)

    save_attack_file_path = r"C:\Users\amith\Documents\Uni\Masters\processed-traffic\Attack"
    save_benign_file_path = r"C:\Users\amith\Documents\Uni\Masters\processed-traffic\Benign"
    save_dataset1_file_path = r"C:\Users\amith\Documents\Uni\Masters\processed-traffic\2016"

    # analyse_dataset(attack_dataset, attack_file_path, malicious_pkts, benign_pkts)
    processed = ["Dropcam", "Amazon Echo", "Netatmo Welcom", "TP-Link Day Night Cloud camera", "Samsung SmartCam"]


    malicious_flows = get_malicious_flows(r"C:\Users\amith\Documents\Uni\Masters\Datasets\UNSW\2018\annotations\annotations")


    dates = ["2018-06-01","2018-06-02", "2018-06-03", "2018-06-04","2018-06-06", "2018-06-07","2018-06-08"]
    mal_keys = list(malicious_flows.keys())
    # for device in infected_devices:
    #     traffic_objects, dates = unpickle_objects(attack_file_path, device)
    #     for date in dates:
    #         # if date in mal_keys:
    #         make_graphs = model_device_behaviour(traffic_objects, date, malicious_flows)
    #         if make_graphs:
    #             print(make_graphs)
    #             break
    # traffic_objts, dates = unpickle_objects(dataset1_file_path, "Dropcam")
    # for date in dates:
    #     if date in mal_keys:
    # print(len(traffic_objts))
    # get_graphs = model_device_behaviour(traffic_objts, dates, malicious_flows)

        # print(traffic_objects)
        # print(dates)
        # print(len(traffic_objects))
        # print(len(dates))

    # thread = threading.Thread(target=analyse_pcap(pcap_file, test_file))
    # thread.start()
    # thread.join()
    # for device in iot:
    #     if device == "iHome":
    #         print(device)
    #         x, dates = unpickle_objects(dataset1_file_path, device)
    #         print(x)
    #         make_graphs = model_device_behaviour(x,dates , mal_flows={})
    #         if make_graphs:
    #             print(make_graphs)
    #     else:
    #         continue

if __name__ == "__main__":
    main()
    # for device in infected_devices:
    #     path = r"C:\Users\amith\Documents\Uni\Masters\Implementation\attack"
    #     path = path +"\_" + device
    #     folder = Path(path)
    #     folder.mkdir()


    # thread1 = threading.Thread(target= save_traffic(pcap_file, file_path, devices))
    # thread2 = threading.Thread(target=create_device_plots(devices,malicious_pkts, benign_pkts))
    # thread1.start()
    # thread2.start()
    # thread1.join()

    # create_device_plots(devices,malicious_pkts, benign_pkts)

    # devices_objs = unpickle_objects(file_path, "16-09-23")
    # print(devices_objs)
