from io import FileIO
from packet_level_signature import *
from trace_filtering import *
from network import NetworkTrace
import threading
from pathlib import Path
from flow_stats import *
import klepto as kl
import os
from preprocess import save_device_attributes

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
                    "Amazon Echo", "TP-Link Smart plug"]

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
    # paths = []
    # for path in dir_path.rglob('*.pcap'):
    #     paths.append(path)
    # return paths
    # print(file_count)
    # return file_list

def get_file_list(dataset):
    dir_path = Path(dataset)
    file_list = []
    for path in dir_path.iterdir():
        if "pcap" in path.name:
            continue
        else:
            file_list.append(path.name)
    return file_list

def analyse_dataset(dataset, save_path,malicious_pkts,benign_pkts):
    large_attack_files = ["18-06-01", "18-06-02", "18-06-03", "18-06-04", "18-06-05"]
    processed_files = ["18-06-11", "18-06-12", "18-06-13", "18-06-14", "18-06-15", "18-06-16"]

    for file in get_pcaps(dataset):
        print(file)
        if str(file)[-13:-5] in processed_files:
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
    path = r"C:\Users\amith\Documents\Uni\Masters\Implementation\commands"
    def create_folders():
        for obj in iot_devices:
            path = Path(path) / country / obj
            folder = Path(path)
            if folder.is_dir():
                pass
            else:
                folder.mkdir()
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
            analyse_pcap(traffic_file, FileIO(pcap), ttl = "ttl")
            print("creating device objs from pcap")
            device_list = get_device_objects(traffic_file, [], [])
            for device_obj in device_list:
                if device_obj.mac_address == iot_devices[device]:
                    iot_objects[command.name].append(device_obj)
                else:
                    non_iot_objects[command.name].append(device_obj)
    # print("iot_objects:",iot_objects)

    event_traffic = get_reorganised_command_traffic_dict(iot_objects)
    device_command_signature = PacketLevelSignature(event_traffic)
    device_command_signature.cluster_event_traffic("on")
    def make_command_plot_folders():
        for command_name in event_traffic:
            # Saving graphs in appropriate folders i.e. accroding to the command
            if len(event_traffic[command_name]['lan']) > 0 or len(event_traffic[command_name]['wan']) > 0:
                save_graph_path = Path(path) / country / device / command_name
                save_folder = Path(save_graph_path)
                if save_folder.is_dir():
                    pass
                else:
                    save_folder.mkdir()
                # plot_command_traffic = model_device_behaviour(device_trafic_objects=iot_objects[command_name], dates=None, mal_flows={}, save_folder=save_folder, behaviour_type="benign")
                # if plot_command_traffic:
                #     print(plot_command_traffic)
                #     continue
    # make_command_plot_folders()
    # model_command_traffic(iot_objects, country, device, path)

def preprocess_device_traffic():
    network_instances = unpickle_network_trace_and_device_obj(processed_benign_traffic, limit=1, devices=infected_devices)
    for network_obj in network_instances:
        for device_obj in network_instances[network_obj]:
            if device_obj.device_name not in infected_devices:
                continue
            device_obj.update_profile([],[], compute_attributes=False)
            device_obj.sort_flow_location(network_obj)
            device_obj.set_location_direction_rates()
            save_device_attributes(device_obj)


def cluster_device_signature(processed_traffic_path):
    """Clusters multiple network traces instead of just one to get a better singature of benign device behaviour"""
    network_instances = unpickle_network_trace_and_device_obj(processed_traffic_path, limit=1, devices=infected_devices)
    for network_obj in network_instances:
        for device_obj in network_instances[network_obj]:
            if device_obj.device_name not in infected_devices:
                continue
            device_obj.update_profile([],[], False)
            device_obj.set_device_activity()
            device_obj.sort_flow_location(network_obj)
            device_obj.set_location_direction_rates()
            device_obj.cluster_device_signature_features()
        # network_obj.device_signature_plots(network_instances[network_obj])
        # network_obj.device_flow_direction_signature(network_instances[network_obj])

def extract_packet_level_signature(device_objs):
    """Takes in all device_objs of a device and calls PacketLevelFeatures"""
    for device_obj in device_objs:
        PacketLevelSignature({},'device', device_obj)

def extract_timestamps(dataset, save_path):
    count = 0
    limit = math.inf
    processed = ['16-09-23']
    for file in get_pcaps(dataset):
        print(file)

        count += 1
        if count > limit:
            break
        if str(file)[-13:-5] in processed:
            continue
        pcap = NetworkTrace(file)
        # Pass in epoch filter and get the ordinal_timestamp dict
        analyse_pcap(pcap, FileIO(file), epoch_filter=True)
        # Save dictionary so it can be unpacked later to modify incorrect timestamp
        save_dir = save_path + '\_' + pcap.file_name + '\_network_info'
        ar = kl.archives.dir_archive(name=save_dir, serialized=True, cached=True, protocol=4)
        try:
            print("saving ordinal_timestamp")
            ar['ordinal_timestamp'] = pcap.ordinal_timestamp
            ar.dump()
            ar.clear()
        except MemoryError:
            print("memory error for ordinal_timestamp dict")
            pass

def modify_timestamp(processed_traffic_path, *files):
    # Cannot unpack all 60 files - not enough memory.
    if files:
        files = files[0]
    else:
        files = get_file_list(processed_traffic_path)

    print('files', len(files))
    # test_file = ['_16-09-23','_16-09-24']

    for file in files:
        print("unpickling", file)
        network_instances = unpickle_network_trace_and_device_obj(processed_traffic_path,extract_timestamp=True, files=file)
        for network_trace in network_instances:
            # print('path', processed_traffic_path + "\_" + network_trace.file_name[-14:-5])
            network_trace.change_device_timestamp(network_instances[network_trace])
            for device in network_instances[network_trace]:
                print('saving devices')
                path = processed_traffic_path + "\_" + network_trace.file_name[-14:-5] + '\_' +device.device_name + "-db"
                shelve_device_traffic(device, path, 'timestamp')

    print("COMPLETED MODIFYING TIMESTAMP BUG")

def compare_attack_and_benign(device_addr,device_name):
    """Plot throughput of attack flows to compare against benign flow types - only for one device """
    malicious_flows = get_malicious_flows(r"C:\Users\amith\Documents\Uni\Masters\Datasets\UNSW\2018\annotations\annotations")
    count = 0
    limit = 1
    for trace_date in malicious_flows[device_addr]:
        count +=1
        if count > limit:
            break
        attack_flows = malicious_flows[device_addr][trace_date]
        print(len(attack_flows))
        ## Unpickle that trace_file date device traffic###
        trace_date_traffic = unpickle_network_trace_and_device_obj(processed_attack_traffic, files=str('_'+ trace_date[2:]), devices=device_name)
        device_obj = list(trace_date_traffic.items())[0][1][0]
        network_obj = list(trace_date_traffic.items())[0][0]
        device_obj.update_profile([],[],True, attack_flows)
        device_obj.sort_flow_location(network_obj)
        device_obj.set_location_direction_rates()
        # device_obj.plot_location_direction_rate()
        # device_obj.plot_flow_type(network_obj.file_name)


def main():
    process_moniotr_file_path = r"C:\Users\amith\Documents\Uni\Masters\processed-traffic\moniotr"
    northeastern_dataset_uk = r"D:\Mon(IoT)r\iot-data\uk"


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
    test_file = "16-09-23.pcap"

    # analyse_pcap(pcap_file, "16-09-23.pcap")
    malicious_pkts = []
    benign_pkts = []
    pkt_rmse = []
    # with open('results.pickle', 'rb') as pickle_fd:
    #     phi = pickle.load(pickle_fd)
    #     malicious_pkts = pickle.load(pickle_fd)
    #     benign_pkts = pickle.load(pickle_fd)
    #     pkt_rmse = pickle.load(pickle_fd)

    global processed_attack_traffic
    global processed_benign_traffic
    processed_attack_traffic = r"C:\Users\amith\Documents\Uni\Masters\processed-traffic\Attack"
    processed_benign_traffic = r"C:\Users\amith\Documents\Uni\Masters\processed-traffic\Benign"
    processed_benign_2016 = r"C:\Users\amith\Documents\Uni\Masters\processed-traffic\2016"
    preprocess_device_traffic()
    # extract_timestamps(dataset1, processed_benign_2016)
    # modify_timestamp(processed_benign_2016)
    # analyse_dataset(dataset1, processed_benign_2016, malicious_pkts, benign_pkts)
    # processed = ["Dropcam", "Amazon Echo", "Netatmo Welcom", "TP-Link Day Night Cloud camera", "Samsung SmartCam"]

    # cluster_device_signature(processed_benign_traffic)
    # compare_attack_and_benign("70:ee:50:18:34:43", "Netatmo Welcom")


    dates = ["2018-06-01","2018-06-02", "2018-06-03", "2018-06-04","2018-06-06", "2018-06-07","2018-06-08"]
    # mal_keys = list(malicious_flows.keys())

    # def process_attack_traffic():
    #     for device in infected_devices:
    #         traffic_objects, dates = unpickle_device_objects(processed_attack_trafffic, device)
    #         for date in dates:
    #             # if date in mal_keys:
    #             make_graphs = model_device_behaviour(traffic_objects, date, malicious_flows)
    #             if make_graphs:
    #                 print(make_graphs)
    #                 break

    def process_benign_traffic():
        for device in iot:
            print(device)
            device_objs, network_objs,dates = unpickle_device_objects(processed_benign_traffic, device, "mal")
            # print(x)
            # make_graphs = model_device_behaviour(device_objs,dates , mal_flows={}, save_folder=r"D:", behaviour_type='benign')
            extract_packet_level_signature(device_objs)

    # process_benign_traffic()

    # tp_link_traffic, network_trace = unpickle_device_objects(processed_benign_traffic, "TP-Link Smart plug", "benign")
    # if len(tp_link_traffic) == len(network_trace):
    #     for i in range(0, len(tp_link_traffic)):
    #         tp_link_traffic[i].update_profile([],[])
    #         # tp_link_traffic[i].sort_flow_location(network_trace[i])
    #         tp_link_traffic[i].compare_flow_location_traffic()
    #
    # pcap = NetworkTrace(test_file)
    # thread = threading.Thread(target=analyse_pcap(pcap, test_file, count_limit=100000))
    # thread.start()
    # thread.join()
    # device_objs = get_device_objects(pcap, [], [])
    # for device in device_objs:
    #     device.update_profile([],[])
        # device.sort_flow_location(pcap)
        # device.compare_flow_location_traffic()
    # device_signature_plots(device_objs)

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
    # devices_objs = unpickle_device_objects(file_path, "16-09-23")
    # print(devices_objs)
