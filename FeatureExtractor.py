from pathlib import Path
import math
import pandas as pd
from tools import get_attack_window_timestamps, unpickle_network_trace_and_device_obj, get_ax
import numpy as np
import matplotlib.pyplot as plt
import json

class FeatureExtractor:

    def __init__(self, device_name):
        self.device_name = device_name
        self.processed_attack_traffic = r"D:\New back up\Takeout\Drive\UNSW device traffic\Attack"
        self.processed_benign_traffic = r"C:\Users\amith\Documents\Uni\Masters\processed-traffic\Benign"
        self.attack_windows = get_attack_window_timestamps(self.device_name) # manually configured time windows for each coarse-grained flow
        self.identified_attack_hashkeys = {}  # For storing and comparing whether hash keys are accurate {'attack_timestamp (start, end)':'hashkeys (start, end)',...}
        self.benign_device_model = None
        self.attack_device_model = None
        self.features = {key: [] for key in self.get_feature_list()}
        self.cg_flows = ['local_inputs', 'local_outputs', 'internet_inputs', 'internet_outputs']
        self.save_path = Path(r"D:\thesis_journal_version\cdf_experiments\v1") / self.device_name
        self.device_model = None
        self.features_types = ['mean', 'std']
        self.time_scale = 120
        self.flow_attack_features = None

    def get_feature_list(self):
        traffic_rate_types = ['byte', 'pkt']
        features = ['mean', 'pkt', 'count']
        time_scales = ['one_min', "two_min"]
        flow_features = ['local_inputs_one_min_byte_count','local_inputs_one_min_pkt_count', 'local_inputs_two_min_byte_count','local_inputs_two_min_pkt_count','local_inputs_two_min_byte_mean','local_inputs_two_min_pkt_mean', 'local_inputs_two_min_byte_std','local_inputs_two_min_pkt_std',
                         'local_outputs_one_min_byte_count', 'local_outputs_one_min_pkt_count',
                         'local_outputs_two_min_byte_count', 'local_outputs_two_min_pkt_count',
                         'local_outputs_two_min_byte_mean', 'local_outputs_two_min_pkt_mean',
                         'local_outputs_two_min_byte_std', 'local_outputs_two_min_pkt_std',
                         'internet_inputs_one_min_byte_count', 'internet_inputs_one_min_pkt_count',
                         'internet_inputs_two_min_byte_count', 'internet_inputs_two_min_pkt_count',
                         'internet_inputs_two_min_byte_mean', 'internet_inputs_two_min_pkt_mean',
                         'internet_inputs_two_min_byte_std', 'internet_inputs_two_min_pkt_std',
                         'internet_outputs_one_min_byte_count', 'internet_outputs_one_min_pkt_count',
                         'internet_outputs_two_min_byte_count', 'internet_outputs_two_min_pkt_count',
                         'internet_outputs_two_min_byte_mean', 'internet_outputs_two_min_pkt_mean',
                         'internet_outputs_two_min_byte_std', 'internet_outputs_two_min_pkt_std',
                         ]
        return flow_features


    def plot_cdf(self):

        benign_features = self.load_benign_features()
        attack_features = self.load_attack_features()

        def get_key_name(is_attack, flow, rate_type,metric):
            if is_attack:
                return flow + '_two_min_' + rate_type+'_' + metric

        def get_extract_cdf_values(features_dataframe,key):
            feature_data = features_dataframe[key]
            feature_values = sorted(feature_data)
            feature_value_probability = np.arange(1, len(feature_data) + 1) / len(feature_data)
            return feature_values, feature_value_probability

        def plot_graph():
            attack_key_name = get_key_name(True,'local_inputs', 'pkt', 'mean')
            # benign_key = get_key_name(is_attack=False, 'localinputs')
            attack_x, attack_y = get_extract_cdf_values(attack_features, attack_key_name)
            ax = get_ax()
            ax.set_ylabel("CDF")
            ax.set_xlabel(attack_key_name)
            ax.plot(attack_x, attack_y, label=attack_key_name)
            plt.legend(loc='best')
            plt.show()

        plot_graph()


    def set_device_model(self, model_in):
        self.device_model = model_in

    def set_flow_attack_features(self, attack_timestamps):
        self.flow_attack_features = {flow: {timestamp: {feature: [] for feature in self.features} for timestamp in attack_timestamps[flow]} for flow in self.cg_flows}

    def load_device_traffic(self, traffic_database_path, *date):

        if date:
            file_filter = date[0]
        file_filter = '_' + file_filter[0]
        print(file_filter)
        network_instances = unpickle_network_trace_and_device_obj(traffic_database_path, devices=self.device_name, files=[file_filter])
        # attack_network_instances = unpickle_network_trace_and_device_obj(processed_attack_traffic, devices=device_filter)
        device_traffic = []
        for network_obj in network_instances:
            for device_obj in network_instances[network_obj]:
                # if device_obj.device_name not in device_filter:
                #     continue
                device_traffic.append(device_obj)
                device_obj.update_profile([], [], compute_attributes=False)
                device_obj.sort_flow_location(network_obj)
                # device_obj.set_location_direction_rates()

        print('Number of device instances in dataset', len(device_traffic))
        if len(device_traffic) == 1:
            return device_traffic[0]
        else:
            return device_traffic

    def compute_benign_traffic_features(self):
        from preprocess import ModelDevice
        """1. Loads traffic
           2. Extracts features
           3.Saves extracted features as pickled"""

        device_traffic = self.load_device_traffic(self.processed_benign_traffic)
        device_model = ModelDevice(model_function="preprocess", device_name=self.device_name, device_traffic=device_traffic,
                    time_scales=[60, 120, 240], data_type='benign', feature_set="FS3", window='120', sampling_window='30')
        self.set_device_model(device_model)
        self.run_cdf_experiment(device_model)




    def run_cdf_experiment(self, device_model):
        """This is for the cdf graph plots"""

        all_features = pd.DataFrame()
        local_model_df = device_model.convert_to_df(device_model.local_model)
        internet_model_df = device_model.convert_to_df(device_model.internet_model)
        def append_data_to_all_features_df(location_df, location):
            for col in location_df:
                n_col = location + col
                all_features[n_col] = pd.Series(location_df[col].values)

        append_data_to_all_features_df(local_model_df, 'local')
        append_data_to_all_features_df(internet_model_df, 'internet')
        all_features.to_csv(str(self.save_path/"benign_features.csv"))

    def compute_attack_features(self):
        """takes in attack_windows that have been manually configured
        (by manual inspection/calculation via visualisation of graphs/data_structures)
        and computes traffic features within the window"""
        print('computing attack features')
        attack_date = list(self.attack_windows.keys())
        print('ATTACK DATE NEEDS TO LOOPED THROUGH: IMPLEMENT FOR LOOP HERE')
        device_traffic = self.load_device_traffic(self.processed_attack_traffic, attack_date)
        device_traffic.set_sampling_rate(30)
        device_traffic.set_device_activity()
        device_traffic.set_location_direction_rates()
        flow_features = {}.fromkeys(self.cg_flows)
        for flow in self.cg_flows:
            flow_features[flow] = device_traffic.create_traffic_volume_features(flow, w_window=self.time_scale)

        self.get_attack_window_features(flow_features, self.attack_windows[attack_date[0]])

    def get_attack_window_features(self, flow_features, attack_windows):

        self.set_flow_attack_features(attack_windows)
        all_attack_features = pd.DataFrame()

        def get_attack_interval_keys(attack_timestamp):
            """Hash_key refers to the value of the window interval key in the dictionary..refer to ur notes on index structure of hashmap"""
            start_hash_key = math.floor((attack_timestamp[0] / self.time_scale)) * self.time_scale
            end_hash_key = math.floor((attack_timestamp[1] / self.time_scale)) * self.time_scale
            self.identified_attack_hashkeys[attack_timestamp] = (start_hash_key, end_hash_key)
            return start_hash_key, end_hash_key

        def set_attack_interval_features(hash_keys, feature_vectors, flow):
            start = hash_keys[0]
            end = hash_keys[1]
            byte_mean_name = flow+'_two_min_byte_mean'
            byte_std_name = flow+'_two_min_byte_std'
            pkt_mean_name = flow+'_two_min_pkt_mean'
            pkt_std_name = flow+'_two_min_pkt_std'
            for interval in range(start, end + self.time_scale, self.time_scale):
                print(features_vectors[interval])
                self.features[byte_mean_name].append(features_vectors[interval]['byte_count']['mean'])
                self.features[byte_std_name].append(features_vectors[interval]['byte_count']['std'])
                self.features[pkt_mean_name].append(features_vectors[interval]['pkt_count']['mean'])
                self.features[pkt_std_name].append(features_vectors[interval]['pkt_count']['std'])


        for flow in flow_features:
            attack_timestamps = attack_windows[flow]
            features_vectors = flow_features[flow]
            for timestamp in attack_timestamps:
                hash_keys = get_attack_interval_keys(timestamp)
                set_attack_interval_features(hash_keys, features_vectors, flow)



        for col in self.features:
            all_attack_features[col] = pd.Series(self.features[col])

        all_attack_features.to_csv(str(self.save_path/"attack_features.csv"))

        # self.run_attack_hashkey_validation()
        # self.save_device_features()

    def run_attack_hashkey_validation(self):
        """TEST METHOD: validates hashkeys are accurate..setting up test cases"""
        # Save data as json
        # with open(str(self.save_path / 'code_validation_tests' / 'configured_values.json')) as fp:
        #     json.dump(self.attack_windows, fp)
        # with open(str(self.save_path / 'code_validation_tests' / 'hashkey_values.json')) as fp:
        #     json.dump(self.identified_attack_hashkeys, fp)
        # print values
        print('HASHKEY VALIDATION')
        for key in self.identified_attack_hashkeys:
            print(key, self.identified_attack_hashkeys[key])

    def load_attack_features(self):
        return pd.read_csv(str(self.save_path/"attack_features.csv"))

    def load_benign_features(self):
        return pd.read_csv(str(self.save_path / "benign_features.csv"))

