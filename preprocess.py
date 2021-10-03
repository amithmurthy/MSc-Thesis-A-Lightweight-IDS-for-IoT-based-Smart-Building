from sklearn.decomposition import PCA
import matplotlib.pyplot as plt
from sklearn.preprocessing import StandardScaler, MinMaxScaler
from sklearn.pipeline import Pipeline
from sklearn.cluster import KMeans
import scipy.spatial.distance as sdist
from collections import OrderedDict
from scapy.all import *
from scapy.layers.l2 import Ether
from statistics import mean, stdev
from sklearn.metrics import silhouette_score
import klepto as kl
from multiprocessing import Pool
from copy import deepcopy
# import tensorflow as tf
from pathlib import Path
import pandas as pd
import numpy as np
from tools import *
import time
from datetime import datetime
from io import FileIO
import timeit
import pickle
""" Functions for normalising data """

class ModelDevice:
    def __init__(self, model_function, device_name, **kwargs):
        self.features = ['local_inputs_mean_bytes', 'local_inputs_std_bytes', 'local_outputs_mean_bytes', 'local_outputs_std_bytes',
                         'internet_inputs_mean_bytes', 'internet_inputs_std_bytes', 'internet_outputs_mean_bytes', 'internet_outputs_std_bytes',
                         'local_inputs_mean_pkts', 'local_inputs_std_pkts', 'local_outputs_mean_pkts', 'local_outputs_std_pkts', 'internet_inputs_mean_pkts',
                         'internet_inputs_std_pkts', 'internet_outputs_mean_pkts', 'internet_outputs_std_pkts']
        self.first_time_scale_attributes = ['local_inputs_bytes_total', 'local_outputs_bytes_total', 'internet_inputs_bytes_total', 'internet_outputs_bytes_total',
                                            'local_inputs_pkts_total', 'local_outputs_pkts_total', 'internet_inputs_pkts_total','internet_outputs_pkts_total']
        self.model_features = ['one_min_byte_count', 'one_min_pkt_count', 'two_min_byte_mean_10s', 'two_min_byte_mean_60s', 'two_min_std_10s', 'two_min_std_60s', 'four_min_mean_10s','four_min_std_10s',
                               'four_min_mean_60s', 'four_min_std_60s']
        self.sampling_rates = kwargs['sampling_rate'] if 'sampling_rate' in kwargs else get_sampling_rate()
        self.time_scales = kwargs['time_scales'] if 'time_scales' in kwargs else [60, 120, 240]
        self.first_time_scale_features = {sampling_rate: {feature: [] for feature in self.first_time_scale_attributes} for sampling_rate in self.sampling_rates[self.time_scales[0]]}
        self.second_time_scale_features = {sampling_rate: {feature: [] for feature in self.features} for sampling_rate in self.sampling_rates[self.time_scales[1]]}
        self.third_time_scale_features = {sampling_rate: {feature: [] for feature in self.features} for sampling_rate in self.sampling_rates[self.time_scales[2]]}
        # self.fourth_time_scale_features = {sampling_rate: {feature: [] for feature in self.features} for sampling_rate in self.sampling_rates[self.time_scales[3]]}
        self.feature_set = kwargs["feature_set"]
        self.window = kwargs['window']
        self.s_rate = kwargs['sampling_window']
        self.device_folder = Path(r"C:\Users\amith\Documents\Uni\Masters\device_attributes") / device_name
        self.training_data = Path(r"C:\Users\amith\Documents\Uni\Masters\device_attributes") / device_name / self.feature_set/self.window/self.s_rate/"benign_"
        self.attack_data = Path(r"C:\Users\amith\Documents\Uni\Masters\device_attributes") / device_name / self.feature_set/self.window/self.s_rate/"attack_"
        self.save_plot_path = Path(r"C:\Users\amith\Documents\Uni\Masters\Graphs\Machine Learning") / device_name
        self.experiment = kwargs['experiment'] if 'experiment' in kwargs else "all"
        self.feature_map = {
            60: 'total_count',
            120: 'features',
            240: 'features'
        }
        self.local_input_model = {feature: [] for feature in self.model_features}
        self.local_output_model = {feature: [] for feature in self.model_features}
        self.internet_input_model = {feature: [] for feature in self.model_features}
        self.internet_output_model = {feature: [] for feature in self.model_features}
        self.internet_model = {}
        self.local_model = {}
        self.device_name = device_name
        print(device_name, self.feature_set, self.window, self.s_rate)
        if model_function == 'preprocess':
            self.device_traffic = kwargs['device_traffic']
            self.data_type = kwargs['data_type'] if 'data_type' in kwargs else None
            self.saved_features = kwargs['saved_features'] if 'saved_features' in kwargs else False
            self.process_all_traffic()
        else:
            self.model_function = model_function
            if model_function == 'train':
                self.train_type = kwargs['train_type'] if 'train_type' in kwargs else None
                self.boundary = 99.7
                self.create_clustering_model()
            elif model_function == 'anomaly_detection':
                self.time_scale_anomalies = None
                self.anomaly_timestamp = {}
                self.benign_model = {'internet': {}, 'local': {}}
                self.file_device_traffic_duration = {}
                self.relative_attack_timestamp = {}
                self.attack_metadata = {}
                self.test_instances = None
                self.rel_attack_time_file_filter = []
                self.anomaly_detection()
            elif model_function == 'validate':
                self.anomaly_timestamp = {}
                self.file_device_traffic_duration = {}
                self.relative_attack_timestamp = {}
                self.attack_metadata = OrderedDict
                self.validate_anomalies()

    def set_location_model(self, model, inputs, outputs):
        directions = ['inputs', 'outputs']
        for direction in directions:
            if direction == 'inputs':
                direction_model = inputs
                name = 'inputs_'
            elif direction == 'outputs':
                direction_model = outputs
                name = 'outputs_'
            for feature in direction_model:
                feature_name = name + feature
                model[feature_name] = direction_model[feature]

    def get_time_scale_features(self, device_obj):
        """TODO: Abstraction for time_scale required. Currently, only processes two time_scales at a time. """
        flows = ['local_inputs', 'local_outputs', 'internet_inputs', 'internet_outputs']
        first_time_scale = {}
        second_time_scale = {}
        third_time_scale = {}
        fourth_time_scale = {}

        def get_count(time_scale_vectors, count_type):
            def get_total(feature_vector):
                counts = []
                for time_vector in feature_vector:
                    counts.append(feature_vector[time_vector][count_type])
                return counts
            local_input_count = get_total(time_scale_vectors['local_inputs'])
            local_output_count = get_total(time_scale_vectors['local_outputs'])
            internet_input_count = get_total(time_scale_vectors['internet_inputs'])
            internet_outputs_count = get_total(time_scale_vectors['internet_outputs'])
            return local_input_count, local_output_count, internet_input_count, internet_outputs_count

        def get_count_type_features(device, time_scale_dict, count_type):
            local_input_mean, local_input_std = device.get_mean_and_std(time_scale_dict['local_inputs'], count_type)
            local_output_mean, local_output_std = device.get_mean_and_std(time_scale_dict['local_outputs'],count_type)
            internet_input_mean, internet_input_std = device.get_mean_and_std(time_scale_dict['internet_inputs'],count_type)
            internet_output_mean, internet_output_std = device.get_mean_and_std(time_scale_dict['internet_outputs'],count_type)
            return [local_input_mean, local_input_std, local_output_mean, local_output_std, internet_input_mean, internet_input_std, internet_output_mean, internet_output_std]

        def get_total_count(device_obj, time_scale_dict, count_type):
            local_input = device_obj.get_total_byte_count(time_scale_dict['local_inputs'], count_type)
            local_output = device_obj.get_total_byte_count(time_scale_dict['local_outputs'], count_type)
            internet_input = device_obj.get_total_byte_count(time_scale_dict['internet_inputs'], count_type)
            internet_output = device_obj.get_total_byte_count(time_scale_dict['internet_outputs'], count_type)
            return [local_input, local_output, internet_input, internet_output]

        def get_features(time_scale_dict, time_scale):
            # local_input_mean_bytes, local_input_std_bytes = device_obj.get_mean_and_std(time_scale_dict['local_inputs'], 'byte_count')
            # local_output_mean_bytes, local_output_std_bytes = device_obj.get_mean_and_std(time_scale_dict['local_outputs'], 'byte_count')
            # internet_input_mean_bytes, internet_input_std_bytes = device_obj.get_mean_and_std(time_scale_dict['internet_inputs'], 'byte_count')
            # internet_output_mean_bytes, internet_output_std_bytes = device_obj.get_mean_and_std(time_scale_dict['internet_outputs'], 'byte_count')
            # local_input_mean_pkts, local_input_std_pkts = device_obj.get_mean_and_std(time_scale_dict['local_inputs'], 'pkt_count')
            # local_output_mean_pkts, local_output_std_pkts = device_obj.get_mean_and_std(time_scale_dict['local_outputs'], 'pkt_count')
            # internet_input_mean_pkts, internet_input_std_pkts = device_obj.get_mean_and_std(time_scale_dict['internet_inputs'], 'pkt_count')
            # internet_output_mean_pkts, internet_output_std_pkts = device_obj.get_mean_and_std(time_scale_dict['internet_outputs'], 'pkt_count')
            if self.feature_map[time_scale] == 'total_count':
                total_bytes = get_count(time_scale_dict, 'byte_count')
                total_pkts = get_count(time_scale_dict, 'pkt_count')
                return [total_bytes, total_pkts]
            else:
                byte_features = get_count_type_features(device_obj, time_scale_dict, 'byte_count')
                pkt_features = get_count_type_features(device_obj, time_scale_dict, 'pkt_count')
                # total_bytes = get_total_count(device_obj, time_scale_dict, 'byte_count')
                # total_pkts = get_total_count(device_obj, time_scale_dict, 'pkt_count')
                return [byte_features, pkt_features]
            # return local_input_mean, local_input_std, local_output_mean, local_output_std, internet_input_mean, internet_input_std, internet_output_mean, internet_output_std

        def set_features(extracted_feat_list, global_feature_dict):
            flat_list = [item for sublist in extracted_feat_list for item in sublist]

            if len(flat_list) == len(self.first_time_scale_attributes):
                print('first time scale features list')
                feature_names = self.first_time_scale_attributes
            else:
                feature_names = self.features
            for i in range(0, len(flat_list)):
                global_feature_dict[feature_names[i]].extend(flat_list[i])

        def set_time_scale_attributes(sampling_rate):
            first_time_scale[sampling_rate] = {attr: None for attr in flows}
            second_time_scale[sampling_rate] = {attr: None for attr in flows}
            third_time_scale[sampling_rate] = {attr: None for attr in flows}
            fourth_time_scale[sampling_rate] = {attr: None for attr in flows}

        def compute_time_scale_feat(time_scale, time_scale_feature, global_feature_dict):
            # local time scale dict not initialised in for loops above as for loop necessary below i.e. less time complexity
            if time_scale == self.time_scales[0]:
                for sampling_rate in list(self.first_time_scale_features.keys()):
                    device_obj.set_sampling_rate(sampling_rate)
                    device_obj.set_location_direction_rates()
                    time_scale_feature[sampling_rate] = {attr: None for attr in flows}
                    for attribute in flows:
                        time_scale_feature[sampling_rate][attribute] = device_obj.merge_byte_pkt_count(attribute, sliding_window=time_scale)
                    # feature_cols = get_features(time_scale_feature[sampling_rate], time_scale)
                    # set_features(feature_cols, global_feature_dict[sampling_rate])
            else:
                for sampling_rate in list(global_feature_dict.keys()):
                    device_obj.set_sampling_rate(sampling_rate)
                    device_obj.set_location_direction_rates()
                    time_scale_feature[sampling_rate] = {attr: None for attr in flows}
                    for attribute in flows:
                        time_scale_feature[sampling_rate][attribute] = device_obj.create_traffic_volume_features(attribute, w_window=time_scale)
                    # feature_cols = get_features(time_scale_feature[sampling_rate], time_scale)
                    # set_features(feature_cols, global_feature_dict[sampling_rate])

        compute_time_scale_feat(self.time_scales[0], first_time_scale, self.first_time_scale_features)
        # print(first_time_scale[60]['local_inputs'][0]['byte_count'])
        # print(self.first_time_scale_features[60]['local_inputs_bytes_total'][0])
        compute_time_scale_feat(self.time_scales[1], second_time_scale, self.second_time_scale_features)
        compute_time_scale_feat(self.time_scales[2], third_time_scale, self.third_time_scale_features)
        # print('60s rate last key val', third_time_scale[60]['local_inputs'][list(third_time_scale[60]['local_inputs'].keys())[-1]])
        # print('10s rate last key val', third_time_scale[10]['local_inputs'][list(third_time_scale[10]['local_inputs'].keys())[-1]])

        def merge_time_scale_features(flow_type, traffic_model):
            """flow_type: local_inputs, local_outputs etc
            traffic_model: self.local_inputs_model...."""
            one_min_features = first_time_scale[60][flow_type]
            two_min_features = {sampling_window: second_time_scale[sampling_window][flow_type] for sampling_window in second_time_scale}
            four_min_features = {sampling_window: third_time_scale[sampling_window][flow_type] for sampling_window in third_time_scale}
            # Check that flow type is same as traffic_model?
            # Take 60s sampling rate as ground truth (10s sampling rate is an experiment)
            last_window = list(four_min_features[10].keys())[-1]
            # print(last_window)
            if len(two_min_features[10][last_window]['byte_count']['volume']) > 1 and two_min_features[10][last_window]['byte_count']['mean'] is None:
                two_min_features[10][last_window]['byte_count']['mean'] = mean(two_min_features[10][last_window]['byte_count']['volume'])
                two_min_features[10][last_window]['byte_count']['std'] = stdev(two_min_features[10][last_window]['byte_count']['volume'])
                two_min_features[10][last_window]['pkt_count']['mean'] = mean(two_min_features[10][last_window]['pkt_count']['volume'])
                two_min_features[10][last_window]['pkt_count']['std'] = mean(two_min_features[10][last_window]['pkt_count']['volume'])
            if len(four_min_features[10][last_window]['byte_count']['volume']) > 1 and four_min_features[10][last_window]['byte_count']['mean'] is None :
                four_min_features[10][last_window]['byte_count']['mean'] = mean(four_min_features[10][last_window]['byte_count']['volume'])
                four_min_features[10][last_window]['byte_count']['std'] = stdev(four_min_features[10][last_window]['byte_count']['volume'])
                four_min_features[10][last_window]['pkt_count']['mean'] = mean(four_min_features[10][last_window]['pkt_count']['volume'])
                four_min_features[10][last_window]['pkt_count']['std'] = stdev(four_min_features[10][last_window]['pkt_count']['volume'])

            for window in four_min_features[10]:
                traffic_model['one_min_byte_count'].append(one_min_features[window]['byte_count'])
                traffic_model['one_min_pkt_count'].append(one_min_features[window]['pkt_count'])
                traffic_model['two_min_byte_mean_10s'].append(two_min_features[10][window]['byte_count']['mean'])
                traffic_model['two_min_byte_mean_60s'].append(two_min_features[60][window]['byte_count']['mean'])
                traffic_model['two_min_std_10s'].append(two_min_features[10][window]['byte_count']['std'])
                traffic_model['two_min_std_60s'].append(two_min_features[60][window]['byte_count']['std'])
                traffic_model['four_min_mean_10s'].append(four_min_features[10][window]['byte_count']['mean'])
                traffic_model['four_min_mean_60s'].append(four_min_features[60][window]['byte_count']['mean'])
                traffic_model['four_min_std_10s'].append(four_min_features[10][window]['byte_count']['std'])
                traffic_model['four_min_std_60s'].append(four_min_features[60][window]['byte_count']['std'])

        merge_time_scale_features('local_inputs', self.local_input_model)
        merge_time_scale_features('local_outputs', self.local_output_model)
        merge_time_scale_features('internet_inputs', self.internet_input_model)
        merge_time_scale_features('internet_outputs', self.internet_output_model)
        self.set_location_model(self.local_model, self.local_input_model, self.local_output_model)
        self.set_location_model(self.internet_model, self.internet_input_model, self.internet_output_model)

    def process_all_traffic(self):
        if self.saved_features is False:
            i = 1
            for device_obj in self.device_traffic:
                if i < 2:
                    print("Extracting features")
                    self.get_time_scale_features(device_obj)
                else:
                    break
                i += 1
        print('finished feature extraction')
        print(self.internet_model.keys())
        print(self.local_model.keys())
        # self.save_model_data()
        # self.plot_graphs()

    def plot_graphs(self):
        print("plotting graphs")
        self.plot_attribute_cluster("first", self.sampling_rates[0])
        self.plot_attribute_cluster("second", self.sampling_rates[0])
        self.compare_sampling_window(self.first_time_scale_features, 'internet', self.time_scales[0])
        self.compare_sampling_window(self.first_time_scale_features, 'local', self.time_scales[0])
        # self.compare_sampling_window(self.second_time_scale_features, 'internet', self.time_scales[1])
        # self.compare_sampling_window(self.second_time_scale_features, 'local', self.time_scales[1])
        locations = ['local', 'internet']
        directions = ['inputs', 'outputs']
        for location in locations:
            self.plot_feature_correlation(self.first_time_scale_features, location, self.sampling_rates[0], directions[0], self.time_scales[0])
            self.plot_feature_correlation(self.first_time_scale_features, location, self.sampling_rates[0], directions[1], self.time_scales[0])
            # self.plot_feature_correlation(self.first_time_scale_features, location, self.sampling_rates[1], directions[0], self.time_scales[0])
            # self.plot_feature_correlation(self.first_time_scale_features, location, self.sampling_rates[1],directions[1], self.time_scales[0])
            self.plot_feature_correlation(self.second_time_scale_features, location, self.sampling_rates[0], directions[0], self.time_scales[1])
            self.plot_feature_correlation(self.second_time_scale_features, location, self.sampling_rates[0], directions[1], self.time_scales[1])
            # self.plot_feature_correlation(self.second_time_scale_features, location, self.sampling_rates[1], directions[0], self.time_scales[1])
            # self.plot_feature_correlation(self.second_time_scale_features, location, self.sampling_rates[1],directions[1], self.time_scales[1])

    def normalise_time_scale(self, df, ts):
        file_path = Path(r"C:\Users\amithmurthy\Documents\Uni\Masters\device_attributes") / self.device_name / "kmeans-model"/ (str(ts) +'scaler.pkl')
        headers = list(df.columns)
        if self.data_type == 'benign':
            scaler = StandardScaler()
            df[headers] = scaler.fit_transform(df.values)
            pickle.dump(scaler, open(str(file_path), 'wb'))
            # print('scaler mean', scaler.mean_)
            # print('scaler std', scaler.var_)
        elif self.data_type == 'attack':
            print('saved scaler used')
            scaler = pickle.load(open(str(file_path), 'rb'))
            df[headers] = scaler.transform(df.values)
        return df

    @staticmethod
    def get_time_scale_df(time_scale_features, time_scale):
        df = pd.DataFrame()
        for sampling_rate in time_scale_features:
            for feature in time_scale_features[sampling_rate]:
                header = str(sampling_rate) + '_' + str(time_scale) + '_' + str(feature)
                df[header] = pd.Series(time_scale_features[sampling_rate][feature])
        return df

    def z_score(self, cols, df, org_df, ts, traffic_type):
        print('calculating z-score')
        file_path = Path(
            r"C:\Users\amithmurthy\Documents\Uni\Masters\device_attributes") / self.device_name / "kmeans-model" / (
                                str(ts) + '-zscore')
        if file_path.is_dir() is False:
            file_path.mkdir()
        z_score_cols = []
        for col in cols:
            col_zscore = col + '_zscore'
            z_score_cols.append(col_zscore)
            if self.data_type == 'benign':
                mean = org_df[col].mean()
                std = org_df[col].std()
                # print('ddof=0', org_df[col].std(ddof=0))
                df[col_zscore] = (org_df[col] - mean) / std
                pickle.dump(mean, open(str(file_path / (col + traffic_type + '_mean.pickle')), 'wb'))
                pickle.dump(std, open(str(file_path / (col + traffic_type + '_std.pickle')), 'wb'))
            elif self.data_type == 'attack':
                mean = pickle.load(open(str(file_path / (col + traffic_type + '_mean.pickle')), 'rb'))
                std = pickle.load(open(str(file_path / (col + traffic_type + '_std.pickle')), 'rb'))
                df[col_zscore] = (org_df[col] - mean) / std
        return df

    def convert_to_df(self, model):
        df = pd.DataFrame()
        for feature in model:
            df[feature] = pd.Series(model[feature])
        return df

    def save_model_data(self):
        # save_path = self.device_folder / "normalised"
        save_path = Path(r"D:\thesis_journal_version\cdf_experiments\v1") / self.device_name


        internet_model = self.convert_to_df(self.internet_model)
        local_model = self.convert_to_df(self.local_model)
        internet_model.to_csv(self.device_folder / 'features' / (self.data_type + str(self.time_scales[-1])+"internet_model.csv"))
        local_model.to_csv(self.device_folder / 'features' / (self.data_type +str(self.time_scales[-1])+ 'local_model.csv'))
        local_model.replace(np.nan, 0, inplace=True)
        internet_model.replace(np.nan, 0, inplace=True)
        internet_model.to_csv(str(save_path / 'internet_model.csv'))
        local_model.to_csv(str(save_path / 'local_model.csv'))
        # self.z_score(list(internet_model.columns), pd.DataFrame(), internet_model, self.time_scales[-1],'internet_model').to_csv(str(save_path / (str(self.time_scales[-1]) + self.data_type + 'zscore_internet.csv')))
        # self.z_score(list(local_model.columns), pd.DataFrame(), local_model, self.time_scales[-1],
        #              'local_model').to_csv(
            # str(save_path / (str(self.time_scales[-1]) + self.data_type + 'zscore_local.csv')))
        # self.normalise_time_scale(internet_model, 'internet').to_csv(str(save_path / (str(self.time_scales[-1]) + self.data_type + 'standardScaler_internet.csv')))
        # self.normalise_time_scale(local_model, 'local').to_csv(str(save_path / (str(self.time_scales[-1]) + self.data_type + 'standardScaler_local.csv')))

    def save_device_traffic_attributes(self):
        """Takes in one single device instance"""
        # rows = zip(first_time_scale_cols, second_time_scale_cols)
        file_path = Path(r"C:\Users\amith\Documents\Uni\Masters\device_attributes") / self.device_name / "normalised"
        save_feature_df = self.device_folder / 'features'
        if self.saved_features is False:
            df_first_time_scale, df_second_time_scale = self.get_time_scale_df(self.first_time_scale_features, self.time_scales[0]), self.get_time_scale_df(self.second_time_scale_features, self.time_scales[1])
        else:
            df_first_time_scale, df_second_time_scale = pd.read_csv(str(save_feature_df / str(self.time_scales[0] + self.data_type + "s.csv"))), pd.read_csv(str(save_feature_df / str(self.time_scales[1] + self.data_type + "s.csv")))

        # Compute z-scores for attributes
        z_score_cols = []
        def z_score(cols, df, org_df, ts):
            print('calculating z-score')
            file_path = Path(r"C:\Users\amith\Documents\Uni\Masters\device_attributes") / self.device_name / "kmeans-model" / (str(ts) + '-zscore')
            if file_path.is_dir() is False:
                file_path.mkdir()
            for col in cols:
                col_zscore = col + '_zscore'
                z_score_cols.append(col_zscore)
                if self.data_type == 'benign':
                    mean = org_df[col].mean()
                    std = org_df[col].std()
                    print('my way',col,'std:', std)
                    print('my way',col,'mean',mean)
                    # print('ddof=0', org_df[col].std(ddof=0))
                    df[col_zscore] = (org_df[col] - mean) / std
                    pickle.dump(mean, open(str(file_path / (col+'_mean.pickle')), 'wb'))
                    pickle.dump(std, open(str(file_path / (col+'_std.pickle')), 'wb'))
                elif self.data_type == 'attack':
                    mean = pickle.load(open(str(file_path / (col+'_mean.pickle')), 'rb'))
                    std = pickle.load(open(str(file_path / (col+'_std.pickle')), 'rb'))
                    df[col_zscore] = (org_df[col] - mean) / std
            return df

        def segragate_traffic(df):
            columns = df.columns
            local_traffic = pd.DataFrame()
            internet_traffic = pd.DataFrame()
            for col in columns:
                if 'local' in col:
                    local_traffic[col] = df[col].values
                    assert local_traffic[col].equals(df[col])
                elif 'internet' in col:
                    internet_traffic[col] = df[col].values
                    assert internet_traffic[col].equals(df[col])
            return local_traffic, internet_traffic

        def save_segragation(df,time_scale,location):
            df.to_csv(str(file_path/ str(time_scale + self.data_type + location+".csv")))

        print('saving')
        df_first_time_scale.to_csv(str(save_feature_df / (str(self.time_scales[0]) + self.data_type + "s.csv")))
        df_second_time_scale.to_csv(str(save_feature_df / (str(self.time_scales[1]) + self.data_type + "s.csv")))
        df_first_time_scale = df_first_time_scale.fillna(0)
        df_second_time_scale = df_second_time_scale.fillna(0)
        # df_first_time_scale.to_csv(str(file_path / str(self.time_scales[0]))+self.data_type+".csv")
        # df_second_time_scale = self.normalise_time_scale(df_second_time_scale, self.time_scales[1])
        # df_second_time_scale.to_csv(str(file_path / str(self.time_scales[1]))+self.data_type+".csv")
        df_first_time_zscore = z_score(list(df_first_time_scale.columns), pd.DataFrame(), df_first_time_scale, self.time_scales[0])
        df_second_time_zscore = z_score(list(df_second_time_scale.columns), pd.DataFrame(), df_second_time_scale, self.time_scales[1])
        # std_scaler_test = self.normalise_time_scale(df_first_time_scale, self.time_scales[0])
        # df_first_time_zscore.to_csv(str(file_path / str(self.time_scales[0]))+self.data_type+".csv")
        # df_second_time_zscore.to_csv(str(file_path / str(self.time_scales[1]))+self.data_type+".csv")
        local_features_1, internet_features_1 = segragate_traffic(df_first_time_zscore)
        local_features_2, internet_features_2 = segragate_traffic(df_second_time_zscore)
        save_segragation(local_features_1, str(self.time_scales[0]), 'local')
        save_segragation(internet_features_1, str(self.time_scales[0]), 'internet')
        save_segragation(local_features_2, str(self.time_scales[1]), 'local')
        save_segragation(internet_features_2, str(self.time_scales[1]), 'internet')
        # std_scaler_test.to_csv(str(self.device_folder/ "standard-scaler-test.csv"))
        # test = self.clean_dataset(df_second_time_zscore)
        # df_first_time_scale = clean_dataset(df_first_time_scale)

    def create_clustering_model(self):
        """TODO: Assign the timescale dataset to a variable i.e. which timescale dataset is being trained"""
        location_models = self.get_location_models()
        print(location_models)
        if self.experiment != 'all':
            for location in location_models:
                self.train_time_scale_model(location, self.experiment)
        else:
            for location in location_models:
                for file in location_models[location]:
                    self.train_time_scale_model(location,file)

    def train_time_scale_model(self, location, file):
        """Gets csv and creates clustering model for time_scale features"""
        print('training on', location, file)
        dataset = Path(str(self.training_data)+location) / file
        df = pd.read_csv(str(dataset), index_col=0)
        if self.train_type == 'find_k':
            file_name = location + file
            if location == 'all':
                self.find_k(df, file_name)
        else:
            if 'all' in file:
                location = 'all'
            self.save_model(df, file, location)

    def get_location_models(self):
        # location_model = {'internet': [], 'local': [],'all':[]}
        location_model = {'all':[]}
        for location in location_model:
            training_data = Path(str(self.training_data)+location)
            for file in training_data.iterdir():
                if location == 'all':
                    location_model[location].append(file.name)
                else:
                    if 'standard' not in file.name:
                        continue
                    location_model[location].append(file.name)
        return location_model

    def train_model(self, df, k_clusters):
        """ Clustering model instantiated
        df: csv in pd.DataFrame format
        inspection: optional argument to return cluster model for anomaly detection
        """
        km_model = KMeans(n_clusters=k_clusters)
        data = df.values
        if self.model_function == 'anomaly_detection':
            model = self.km_model.fit(data)
            return model
        else:

            start = timeit.default_timer()
            clusters = km_model.fit_predict(data)
            stop = timeit.default_timer()
            print("training time", stop - start)
            centroids = km_model.cluster_centers_
            # df['cluster'] = self.km_model.labels_
            # dist = sdist.cdist(data, centroids)
            # print(dist)
            # self.km_model = self.km_model.fit(data)
            print("Shape of data", centroids.shape)
            # dimensionality = centroids.shape[1]
            cluster_boundary, cluster_distances = self.find_cluster_boundary(data, centroids, clusters)
            return km_model, cluster_boundary, cluster_distances

    def save_model(self, df, file, location):
        time_scale = self.window

        clusters = get_device_cluster(self.device_name, location, self.feature_set, self.window, self.s_rate)

        print('clusters',clusters)
        km_model, cluster_boundary, cluster_distances = self.train_model(df,clusters)
        folder_name = self.device_folder / "kmeans-model" / self.feature_set / self.window / self.s_rate
        if folder_name.is_dir() is False:
            folder_name.mkdir()
        file_name = folder_name / location
        if file_name.is_dir() is False:
            file_name.mkdir()
        ar = kl.archives.dir_archive(name=file_name, serialized=True, cached=True, protocol=4)
        ar['cluster_model'] = km_model
        ar['cluster_boundary'] = cluster_boundary
        ar['cluster_distances'] = cluster_distances
        ar.dump()
        ar.clear()

    def save_anomalies(self):
        file_name = self.device_folder / "kmeans-model" / self.feature_set / self.window / self.s_rate
        ar = kl.archives.dir_archive(name=file_name, serialized=True, cached=True, protocol=4)
        ar['anomalies'] = self.time_scale_anomalies
        ar.dump()
        ar.clear()

    def get_instance_distance_points(self, data, cx, cy, cz, i_centroid, cluster_labels):
        euclidean_distances = [np.sqrt((x - cx) ** 2 + (y - cy) ** 2 + (z - cz) ** 2) for (x, y, z) in
                               data[cluster_labels == i_centroid]]
        # print('centroid distances',euclidean_distances)
        return euclidean_distances

    def find_cluster_boundary(self, data, centroids, cluster_labels):
        cluster_distances = {i: [] for i in range(len(centroids))}
        test = {}
        df = pd.DataFrame({'cluster': cluster_labels})
        dists = pd.DataFrame(
            sdist.cdist(data, centroids, metric='euclidean'),
            columns=['dist_{}'.format(i) for i in range(len(centroids))],
            index=df.index)
        df = pd.concat([df, dists], axis=1)

        save_distance_path = self.device_folder / "distance_dataframe.csv"
        df.to_csv(str(save_distance_path))
        len_of_df = list(df.index.values)[-1]
        """Should be iloc? iloc gets index location"""
        for i in range(0, len_of_df+1):
            cluster = df.loc[i].cluster
            dist = 'dist_' + str(int(cluster))
            cluster_distances[cluster].append(df.loc[i][dist])

        if self.model_function == 'anomaly_detection':
            return cluster_distances
        else:
            cluster_boundary = {centroid: np.percentile(np.array(cluster_distances[centroid]), self.boundary) for centroid in
                                cluster_distances}
            # print(cluster_boundary)
            return cluster_boundary, cluster_distances

    def anomaly_detection(self):
        self.get_benign_model()
        self.time_scale_anomalies = {location: {'anomalies': [], 'anomaly_index': []} for location in self.benign_model}
        for location in self.benign_model:
            if location != 'all':
                continue
            self.inspect_traffic(location)
        self.save_anomalies()
        self.validate_anomalies()

    def inspect_traffic(self, location):
        """Cluster boundary for time_scale model are the arguments"""
        print("inspecting", location)
        benign_path = Path(str(self.training_data) + location)
        attack_path = Path(str(self.attack_data) + location)
        for file in attack_path.iterdir():
            attack_file = file.name
            print(file)
        for file in benign_path.iterdir():
            benign_data = file.name
        print("test file", attack_file)
        benign_df = pd.read_csv(str(benign_path / benign_data))
        # test = KMeans(n_clusters=5)
        # test_x = test.fit(benign_df.values)
        inspect_df = pd.read_csv(str(attack_path/attack_file), index_col=0)
        self.test_instances = len(inspect_df)
        inspect_data = inspect_df.values
        # attack_centroids = test.fit_predict(inspect_data)
        # print("attack", test.cluster_centers_.shape)
        benign_cluster_model = self.benign_model[location]['cluster_model']
        # self.validate_model(benign_cluster_model, time_scale)
        # X_test = benign_cluster_model.transform(inspect_data)

        start = timeit.default_timer()
        results = benign_cluster_model.predict(inspect_data)
        end = timeit.default_timer()
        print('predicting time', end-start)
        # print("predicted attack data")
        # cluster_points_distances = self.find_cluster_boundary(inspect_data, benign_cluster_model.cluster_centers_, results)
        cluster_points_distances = self.find_cluster_boundary(inspect_data, self.benign_model[location]['benign_centroids'], results)
        """Cluster map => instance index to its respective cluster"""
        cluster_map = pd.DataFrame()
        cluster_map['data_index'] = inspect_df.index.values
        cluster_map['cluster'] = results
        cluster_map.to_csv(str(self.device_folder/self.window)+"index_data_clusters.csv")
        cluster_boundary = self.benign_model[location]['cluster_boundary']
        self.find_anomalies(location, cluster_boundary, cluster_points_distances, cluster_map)

    def find_anomalies(self, location, cluster_boundary, cluster_distances, cluster_map):
        # print(time_scale,location, 'boundaries', cluster_boundary)
        j = 0
        start = timeit.default_timer()
        for centroid in cluster_distances:
            # print(time_scale, 'distances',  cluster_distances[centroid])
            # print('centroid', centroid, 'boundary', cluster_boundary[centroid])
            centroid_data_index = list(cluster_map[cluster_map.cluster == centroid].data_index.values)
            i = 0
            for instance in cluster_distances[centroid]:
                if float(instance) > float(cluster_boundary[centroid]):
                    j += 1
                    self.time_scale_anomalies[location]['anomalies'].append(instance)
                    self.time_scale_anomalies[location]['anomaly_index'].append(centroid_data_index[i])
                i += 1
        end = timeit.default_timer()
        print('anomaly detection time', end- start)
        print(location, 'anomalies',j)

    def  validate_anomalies(self):
        """TODO: Need to save anomaly outputs and extract for each experiment before running validation - requires methods"""
        self.correlate_index_timestamp()
        # extract attack annotations timestamp
        if self.device_name != "Light Bulbs LiFX Smart Bulb":
            self.attack_annotations()
        else:
            self.relative_attack_timestamp, self.attack_metadata = get_lifx_annotations()
        self.reconstruct_device_activity()
        # if self.validate_device_activity() is True:
        self.convert_annotations_to_timescale_index()
            # self.link_annotations_and_output()

    def validate_device_activity(self):
        # Validate total device duration in dataset
        csv_file_duration = self.get_total_device_time(int(self.window))
        last_file = list(self.relative_attack_timestamp.keys())[-1]
        pcap_duration = 0
        for i in self.file_device_traffic_duration:
            pcap_duration += self.file_device_traffic_duration[i]
        if csv_file_duration - pcap_duration < (int(self.window) * 3):
            print("device time stamp matches")
        return True

    def convert_annotations_to_timescale_index(self):
        print("convert annotations to time scale index")

        time_scale_anomaly_index = {location: [] for location in self.time_scale_anomalies}
        global_attack_timestamp = []

        def increment_device_time(file):
            files = list(self.file_device_traffic_duration.keys())
            file_index = files.index(file)
            if file_index == 0:
                return 0
            else:
                total_device_time = 0
                for i in range(0, file_index):
                    total_device_time += self.file_device_traffic_duration[files[i]]
                return total_device_time


        attack_window_instances = 0
        meta_data_keys = list(self.attack_metadata.keys())
        attack_type_instances = {}

        # print(self.relative_attack_timestamp.items())
        # print(len(self.attack_metadata))
        for file in self.relative_attack_timestamp:
            device_duration = increment_device_time(file)
            # print('device_duration', device_duration)
            # print('relative times', self.relative_attack_timestamp[file])
            for rel_attack_time in self.relative_attack_timestamp[file]:
                start = int(device_duration + rel_attack_time[0])
                end = int(device_duration + rel_attack_time[1])
                # print((start, end))
                global_attack_timestamp.append((start, end))
                duration = end - start
                attack_len = math.ceil(duration / int(self.window))
                attack_window_instances += attack_len
                attack_type = self.attack_metadata[rel_attack_time]['attack_type']
                if attack_type in attack_type_instances:
                    attack_type_instances[attack_type]['count'] += attack_len
                    attack_type_instances[attack_type]['timestamp'].append((start, end))
                else:
                    attack_type_instances[attack_type] = {'count': 0, 'detected': 0, 'timestamp': [(start, end)]}
                    attack_type_instances[attack_type]['count'] += attack_len

        print(attack_window_instances)
        # print(attack_type_instances.keys())
        # print(attack_type_instances)
        def ts_index_range(attack_timestamp, time_scale):
            time_scale = int(time_scale[:-1])
            start_i, end_i = int((attack_timestamp[0] / time_scale) - 1), int((attack_timestamp[1] / time_scale) - 1)
            return [i for i in range(start_i, end_i + 1, 1)]

        for attack_time in global_attack_timestamp:
            for location in time_scale_anomaly_index:
                for time_scale in time_scale_anomaly_index[location]:
                    time_scale_anomaly_index[location][time_scale].extend(ts_index_range(attack_time, time_scale))

        # for ts in time_scale_anomaly_index:
        #     t = int(ts[:-1])
        # rel_time = [500 * i for i in time_scale_anomaly_index['500s']]

        # tp = 0
        total = 0
        # print(global_attack_timestamp)
        # print(len(rel_time))
        int_anomalies = []
        # for time in self.anomaly_timestamp['300s']:
        #     int_anomalies.append(int(time))

        # print('300s anomalies', int_anomalies)
        tp_anomalies = {location: [] for location in self.time_scale_anomalies}

        for location in self.time_scale_anomalies:
            for anomaly in self.anomaly_timestamp[location]:
                for attack_ts in global_attack_timestamp:
                    if attack_ts[0] <= anomaly <= attack_ts[1]:
                        # get attack type
                        attack = None
                        for attack_name in attack_type_instances:
                            for timestamp in attack_type_instances[attack_name]['timestamp']:
                                if attack is None:
                                    if attack_ts == timestamp:
                                        attack = attack_name
                                else:
                                    continue
                        # if attack is None:
                        #     print(attack_ts, anomaly)
                        tp_anomalies[location].append((int(anomaly), attack))

        for location in tp_anomalies:
            for anomaly in tp_anomalies[location]:
                attack_type_instances[anomaly[1]]['detected'] += 1


        anomalies = attack_window_instances
        negatives = self.test_instances - anomalies
        output = len(self.anomaly_timestamp['all'])
        tp = len(tp_anomalies['all'])
        fp = output - tp
        fn = anomalies - tp
        tn = negatives - (fn + fp)
        fpr = ((fp / (fp + tn)) * 100)
        accuracy = ((tp + tn) / (tp + tn + fp + fn)) * 100
        print('accuracy', accuracy)
        print('FPR', fpr)
        # print(attack_type_instances)
        print('tp', tp)
        print("TP attack instances", (tp/output) * 100)
        print("TP benign instances", (tn / negatives) * 100)
        results = {}
        for attack_key in attack_type_instances:
            results[attack_key] = {'count': int(attack_type_instances[attack_key]['count']), 'detected': int(attack_type_instances[attack_key]['detected']), 'detection_rate': None}
            results[attack_key]['detection_rate'] = (int(attack_type_instances[attack_key]['detected']) / int(attack_type_instances[attack_key]['count'])) * 100

        total_rate = 0
        for i in results:
            if 'Icmp' in results or "smurf" in results or "Ping" in results:
                continue
            total_rate += results[i]['detection_rate']

        filter = []
        for i in results:
            if 'Icmp' in i or 'smurf' in i or "Ping" in i:
                if 'ping' in results:
                    print(i)
                continue
            else:
                filter.append(i)

        avg_detection_rate = total_rate / len(filter)

        def save_results():
            import csv
            fields = ['attack', 'count', 'detected', 'detection_rate']
            save_csv = Path(r"C:\Users\amith\Documents\Uni\Masters\results") / self.device_name/self.feature_set / self.window / self.s_rate
            type = get_device_type(self.device_name)
            save_device_type_results = Path(r'C:\Users\amith\Documents\Uni\Masters\results\device_type\sampling window')
            with open(str(save_csv / 'detection_results.csv'), 'w') as f:
                w = csv.DictWriter(f, fields)
                for key, val in sorted(results.items()):
                    row = {'attack': key}
                    row.update(val)
                    w.writerow(row)

            metrics = {'True Positives':None, 'False Positives':None, 'True Negatives':None, 'False Negatives':None, "FPR":None, "TP attack":None, "TP benign":None, 'N':None, 'accuracy':None, 'average detection rate':None}
            metrics['True Positives'] = tp
            metrics['False Positives'] = fp
            metrics['True Negatives'] = tn
            metrics['False Negatives'] = fn
            metrics['FPR'] = fpr
            metrics['TP attack'] = (tp/output) * 100
            metrics['TP benign'] = (tn / negatives) * 100
            metrics['N'] = self.test_instances
            metrics['accuracy'] = accuracy
            metrics['average detection rate'] = avg_detection_rate
            with open(str(save_csv/'model_accuracy.csv'), 'w') as c:
                dw = csv.writer(c)
                for key, value in metrics.items():
                    dw.writerow([key, value])

            with open(str(save_device_type_results / (self.device_name + self.s_rate+ ".csv")), 'w') as fd:
                wc = csv.writer(fd)
                for key, value in metrics.items():
                    wc.writerow([key, value])

            print("SAVED RESULTS")

        save_results()

    def link_annotations_and_output(self):
        pass


    def reconstruct_device_activity(self):
        processed_attack_traffic = r"C:\Users\amith\Documents\Uni\Masters\processed-traffic\Attack"
        network_instances = unpickle_network_trace_and_device_obj(processed_attack_traffic, devices=self.device_name)
        # file_device_traffic_duration = {network_obj.file_name: None for network_obj in network_instances}
        for network_obj in network_instances:
            for device_obj in network_instances[network_obj]:
                assert len(network_instances[network_obj]) < 2
                device_obj.update_profile([], [], compute_attributes=False)
                self.file_device_traffic_duration[network_obj.file_name[:-5]] = device_obj.set_device_activity('duration')

    def attack_annotations(self):
        """TODO: Need to refactor the process of adding to attacks dict"""
        device_mac_addr = get_mac_addr(self.device_name).replace(':', '')
        # print('device mac addr', device_mac_addr)
        annotation_path = Path(r"C:\Users\amith\Documents\Uni\Masters\Datasets\UNSW\2018\annotations\annotations") / (device_mac_addr + ".csv")
        col_names = ['start_time', 'end_time', 'attack_features', 'attack_type']
        annotations = pd.read_csv(str(annotation_path), names=col_names)
        attacks = {} #attack time for each date {'2018-06-01':[(start, end)...],...}
        def nest_metadata(key, timestamp, start_epoch):
            if key in attacks:
                attacks[key][timestamp] = {'attack_features': annotations.loc[annotations['start_time'] == start_epoch, 'attack_features'].iloc[0], 'attack_type': annotations.loc[annotations['start_time'] == start_epoch,'attack_type'].iloc[0]}
            else:
                attacks[key] = {}
                attacks[key][timestamp] = {'attack_features': annotations.loc[annotations['start_time'] == start_epoch, 'attack_features'].iloc[0], 'attack_type': annotations.loc[annotations['start_time'] == start_epoch,'attack_type'].iloc[0]}

        for start_epoch, end_epoch in zip(annotations['start_time'], annotations['end_time']):
            # start_date = time.strftime('%Y-%m-%d', time.localtime(i))
            start_date = datetime.utcfromtimestamp(start_epoch).strftime('%Y-%m-%d')
            end_date = datetime.utcfromtimestamp(end_epoch).strftime('%Y-%m-%d') #(time.strftime('%Y-%m-%d', time.localtime(j))[2:])
            start_date, end_date = start_date[2:], end_date[2:]
            if start_date == end_date:
                nest_metadata(start_date, (datetime.utcfromtimestamp(start_epoch).strftime('%H:%M:%S'), datetime.utcfromtimestamp(end_epoch).strftime('%H:%M:%S')), start_epoch)
            else:
                print('attack annotations different dates', start_epoch)
                nest_metadata(start_date, (datetime.utcfromtimestamp(start_epoch).strftime('%H:%M:%S'), "23:59:59"), start_epoch)
                nest_metadata(end_date, ("00:00:00", datetime.utcfromtimestamp(end_epoch).strftime('%H:%M:%S')), start_epoch)

        # if self.device_name == "Light Bulbs LiFX Smart Bulb":
        #     self.link_file_device_time()
        # else:
        device_first_pkt = self.get_attack_file_first_pkt_epoch(attacks)
        self.get_relative_attack_timestamps(device_first_pkt, attacks)
        # print("rel_attack_timestamp struct", self.relative_attack_timestamp)
        #Link relative time to metadata
        for date in self.relative_attack_timestamp:
            relative_timestamps = self.relative_attack_timestamp[date]
            date_timestamps = attacks[date].keys()
            for rel_time, date_time in zip(relative_timestamps, date_timestamps):
                self.attack_metadata[rel_time] = attacks[date][date_time]
        

    def get_relative_attack_timestamps(self, device_first_pkt, attack_times):

        def attack_duration(attack_datetime):
            fmt = '%H:%M:%S'
            return (datetime.strptime(attack_datetime[1], fmt) - datetime.strptime(attack_datetime[0],
                                                                                   fmt)).total_seconds()
        for file in device_first_pkt:
            # print('first pkt time in file', device_first_pkt[file])
            # print('attack timestamps in file', attack_times[file])
            if file in self.rel_attack_time_file_filter:
                continue
            self.relative_attack_timestamp[file] = []
            first_pkt_time = datetime.strptime(device_first_pkt[file], '%H:%M:%S')
            attack_timestamps = list(attack_times[file].keys())
            for attack_timestamp in attack_timestamps:
                rel_attack_start = ((datetime.strptime(attack_timestamp[0], '%H:%M:%S')) - first_pkt_time).total_seconds()
                rel_attack_duration = attack_duration(attack_timestamp)
                rel_attack_end = rel_attack_start + rel_attack_duration
                self.relative_attack_timestamp[file].append((rel_attack_start, rel_attack_end))
                if rel_attack_start < 0:
                    print('negative time', rel_attack_start, rel_attack_end)


                # print('rel_diff', rel_dif, 'file', file)
                # rel_attack_end = (datetime.strptime(attack_timestamp[1], '%H:%M:%S') - first_pkt_time).total_seconds()
        # print(self.relative_attack_timestamp)

    def get_attack_file_first_pkt_epoch(self, attack_times):
        attack_dataset = Path(r"C:\Users\amith\Documents\Uni\Masters\Datasets\UNSW\2018\Attack Data")
        first_pkt_time = {attack_file: None for attack_file in list(attack_times.keys())}
        for pcap in attack_dataset.iterdir():
            if pcap.name[:-5] in list(attack_times.keys()):
                first_pkt_epoch = self.read_pcap(FileIO(pcap))
                # print(first_pkt_epoch)
                first_pkt_time[pcap.name[:-5]] = datetime.utcfromtimestamp(first_pkt_epoch).strftime('%H:%M:%S')
                try:
                    pkt_date = datetime.utcfromtimestamp(first_pkt_epoch).strftime("%Y-%m-%d")
                    # print(pkt_date, "20" + pcap.name[:-5])
                    assert pkt_date == ("20" + pcap.name[:-5])
                except AssertionError:
                    self.rel_attack_time_file_filter.append(pcap.name[:-5])
                    print(self.rel_attack_time_file_filter)
                    print("First pkt date is different to file")
                    print("pkt date", pkt_date)
                    print("file", pcap.name)
                # print('test', datetime.utcfromtimestamp(first_pkt_epoch).strftime('%H:%M:%S'))
        return first_pkt_time

    def link_file_device_time(self):
        def get_first_pkt_time(device_obj):
            smallest_time = None
            for direction in device_obj.flows:
                for flow in device_obj.flows[direction]:
                    start_pkt = device_obj.flows[direction][flow][0]['relative_timestamp']
                    if smallest_time is None:
                        smallest_time = start_pkt
                    else:
                        if start_pkt < smallest_time:
                            smallest_time = start_pkt
                        else:
                            continue
            return smallest_time

        def map_ordinal_rel_time(file, attack_ordinals, device_obj):
            ordinal_time_map = {ordinal: None for ordinal in [element for tupl in attack_ordinals for element in tupl]}
            # print(ordinal_time_map)
            for direction in device_obj.flows:
                flow_table = device_obj.flows[direction] # Easier readibility. direction flow table
                for flow in flow_table:
                    for pkt in flow_table[flow]:
                        if pkt['ordinal'] in ordinal_time_map:
                            ordinal_time_map[pkt['ordinal']] = pkt['relative_timestamp']
            return ordinal_time_map


        processed_attack_traffic = r"D:\New back up\Takeout\Drive\UNSW device traffic\Attack"
        # Get relative ordinals of attack start, end for attack in file
        attack_file_ordinals = attack_ordinals(self.device_name)
        f = [str("_"+file) for file in attack_file_ordinals]
        print("attack ordinal file names", attack_file_ordinals.keys())
        # Get device traffic from these files
        network_instance = unpickle_network_trace_and_device_obj(processed_attack_traffic, devices=self.device_name, files=f)

        for network_obj in network_instance:
            file_rel_pkt_time = None
            for device_obj in network_instance[network_obj]:
                file_rel_pkt_time = get_first_pkt_time(device_obj)
                # Find and set rel_attack time
                attack_file_name = network_obj.file_name[:-5]
                print("attack file", attack_file_name)
                self.relative_attack_timestamp[attack_file_name] = []
                ordinal_time = map_ordinal_rel_time(attack_file_name,attack_file_ordinals[attack_file_name], device_obj)
                for attack_ordinal in attack_file_ordinals[attack_file_name]:
                    if ordinal_time[attack_ordinal[0]] is not None or ordinal_time[attack_ordinal[1]] is not None:
                        start = ordinal_time[attack_ordinal[0]]
                        end = ordinal_time[attack_ordinal[1]]
                        rel_start = start - file_rel_pkt_time
                        rel_end = end - file_rel_pkt_time
                        print('ordinal timestamp', attack_ordinal, (rel_start, rel_end))
                        self.relative_attack_timestamp[attack_file_name].append((rel_start, rel_end))
                    else:
                        print('No timestamp ordianls', attack_ordinal)
        print(self.relative_attack_timestamp)



    def read_pcap(self, pcap_file):
        device_filter = get_mac_addr(self.device_name)
        if self.device_name == "iHome" and "18-10-22.pcap" in str(pcap_file.name) :
            print('getting epoch from tools.py')
            return ihome_first_pkt_ordinal("18-10-22.pcap")
        else:
            count = 0
            print('reading',pcap_file)
            for pkt_data, pkt_metadata in RawPcapReader(pcap_file):
                count += 1
                ether_pkt = Ether(pkt_data)
                if ether_pkt.src == device_filter or ether_pkt.dst == device_filter:
                    # print('pkt ordinal', count)
                    return ((pkt_metadata.tshigh << 32) | pkt_metadata.tslow) / pkt_metadata.tsresol
                else:
                    continue

    def correlate_index_timestamp(self):
        for location in self.time_scale_anomalies:
            # total_device_time = self.get_total_device_time(time_scale)
            # print(time_scale, 'total duration', total_device_time)
            # Data structure to store anomaly timestamp (anomaly_timestamp) is intiated
            self.anomaly_timestamp[location] = []
            for centroid in self.time_scale_anomalies[location]:
                if centroid != 'anomaly_index':
                    continue
                for anomaly_index in self.time_scale_anomalies[location][centroid]:
                    anomaly_timestamp = (anomaly_index + 1) * int(self.window)
                    self.anomaly_timestamp[location].append(anomaly_timestamp)
                        # self.anomaly_timestamp[time_scale].append(anomaly_index)
            # print(time_scale, 'anomaly timestamp', self.anomaly_timestamp[time_scale])


    def get_total_device_time(self, time_scale):
        file_in = self.device_folder / (str(time_scale) + "index_data_clusters.csv")
        cluster_map = pd.read_csv(str(file_in))
        last_index = list(cluster_map.data_index.values)[-1]
        return (last_index + 1) * time_scale

    def get_benign_model(self):
        saved_model = self.device_folder / "kmeans-model" / self.feature_set / self.window / self.s_rate
        time_scale_boundary = {}
        locations = ['all', 'internet', 'local']
        # locations = ['all']
        # time_scale_boundary = {time_scale.name: None for time_scale in saved_model.iterdir()}
        # self.benign_distances = {time_scale.name: None for time_scale in saved_model.iterdir()}
        for model in saved_model.iterdir():
            # Folder names greater than len 4 are not km model
            # if 'internet' not in model.name and 'local' not in model.name:
            #     continue
            if model.name not in locations:
                continue
            # print(model.name)
            # location = 'internet' if 'internet' in model.name else 'local'
            if 'internet' in model.name:
                location = 'internet'
            elif 'local' in model.name:
                location = 'local'
            elif 'all' in model.name:
                location = 'all'
            # for time_scale_model in model.iterdir():
            db = saved_model / location
            d = kl.archives.dir_archive(name=db, serialized=True)
            d.load('cluster_boundary')
            d.load('cluster_distances')
            d.load('cluster_model')
            # time_scale_boundary[time_scale.name] = d['cluster_boundary']
            # model_features = ['cluster_model', 'cluster_distances', 'cluster_boundary']
            self.benign_model[location] = {}
            self.benign_model[location]['cluster_model'] = d['cluster_model']
            self.benign_model[location]['benign_distances'] = d['cluster_distances']
            self.benign_model[location]['benign_centroids'] = d['cluster_model'].cluster_centers_
            self.benign_model[location]['cluster_boundary'] = d['cluster_boundary']
        # print(time_scale_boundary)
        # print('time_scale_boundary', time_scale_boundary)
        # return time_scale_boundary

    def plot_pca_components(self, df, time_scale):
        fig = plt.figure()
        ax = fig.add_subplot(1, 1, 1)
        ax.scatter(df['0'], df['1'])
        ax.set_xlabel("Principal Component 1")
        ax.set_ylabel("Principal Component 2")
        ax.set_title("Reduced dimension")
        plt.savefig(time_scale + "PCA.png")
        plt.show()

    def find_k(self, df, file):
        print('finding K', file)
        save_path = Path(r"C:\Users\amith\Documents\Uni\Masters\Graphs\k") / self.device_name / self.feature_set/self.window/(self.s_rate+'s')
        print(self.training_data)
        x = df.values
        K = [2**x for x in range(2,8)]
        # K = [2, 4, 6, 8, 10, 12, 14, 16, 18, 20, 22, 24, 26, 28, 30]
        print(K)
        inertia = []
        for k in K:
            km = KMeans(n_clusters=k)
            km = km.fit(x)
            inertia.append(km.inertia_)
        plt.plot(K, inertia, 'bx-')
        plt.xlabel('Number of clusters')
        plt.ylabel('Inertia')
        # time_scale = re.search('(.+?)b', str(file)).group(1)
        time_scale = '4 min'
        # location = 'internet' if 'internet' in str(file) else 'local'
        location = 'all'
        name = location + " model" + " "
        plt.title(name)
        plt.savefig(str(save_path / name)+'elbowmethod2.png')
        print("elbow method printed in machine learning plot folder")
        plt.show()
        # print(inertia)
        self.compute_silhouette_score(df, name)

    def compute_silhouette_score(self, df, name):
        # if self.device_name == 'Belkin Wemo switch':
        #     K = list(i for i in range(2,41))
        # else:
        K = [2**x for x in range(2,10)]
        # K = [2, 4, 6, 8, 10, 12, 14, 16, 18, 20, 22, 24, 26, 28, 30]
        # K = range(2,50)
        x = df.values
        save_path = Path(r"C:\Users\amith\Documents\Uni\Masters\Graphs\k") / self.device_name / self.feature_set/self.window/(self.s_rate + 's')
        scores = []
        for k in K:
            k_model = KMeans(n_clusters=k).fit(x)
            label = k_model.labels_
            sil_coeff = silhouette_score(x, label, metric='euclidean')
            scores.append(sil_coeff)
            # print("For n_clusters={}, The Silhouette Coefficient is {}".format(k, sil_coeff))
        fig = plt.figure()
        ax = fig.add_subplot(1,1,1)
        ax.plot(K, scores, 'bx-')
        ax.set_xlabel('Number of clusters')
        ax.set_ylabel("silhoutte score")
        t = name + " silhouette scores"
        ax.set_title(t)
        plt.savefig(str(save_path / name) + 'silhouette.png')
        plt.show()

    def compare_sampling_window(self, time_scale, location, w_window):
        """time_scale = time_scale_features"""
        fig = plt.figure()
        ax = fig.add_subplot(1, 1, 1)
        name = "Sliding window " + str(w_window) +location + self.data_type + " singature"
        ax.set_title(name)
        ax.set_xlabel("mean (bytes)")
        ax.set_ylabel("standard deviation (bytes)")
        sample_rate_1 = time_scale[self.sampling_rates[0]]
        # sample_rate_2 = time_scale[self.sampling_rates[1]]
        ax.scatter(sample_rate_1[location+'_inputs_mean_bytes'], sample_rate_1[location+'_inputs_std_bytes'], label= str(self.sampling_rates[0])+" "+location+' inputs', color='g', alpha=0.6)
        # ax.scatter(sample_rate_2[location+'_inputs_mean_bytes'], sample_rate_2[location+'_inputs_std_bytes'], label= str(self.sampling_rates[1])+" "+location+' inputs', color='c', alpha=0.6)
        ax.scatter(sample_rate_1[location+'_outputs_mean_bytes'], sample_rate_1[location+'_outputs_std_bytes'], label= str(self.sampling_rates[0])+" "+location+' outputs', color='r', alpha=0.6)
        # ax.scatter(sample_rate_2[location+'_outputs_mean_bytes'], sample_rate_2[location+'_outputs_std_bytes'], label= str(self.sampling_rates[1])+" "+location+' outputs', color='b', alpha=0.6)
        plt.legend(loc='best')
        plt.savefig(str(self.save_plot_path / self.device_name) + name + ".png")
        plt.show()

    def plot_feature_correlation(self, time_scale_features, location, sampling_rate, direction, time_scale):
        fig = plt.figure()
        ax = fig.add_subplot(1,1,1)
        name = str(time_scale) +" window" +" "+ str(sampling_rate) + " sampling rate"
        ax.set_title(name)
        ax.set_ylabel('Byte count (KB)')
        ax.set_xlabel('Packet count')
        save_path = self.save_plot_path / 'packet_size'
        location_direction = ['local_inputs', 'local_outputs', 'internet_inputs', 'internet_outputs']
        if save_path.is_dir() is False:
            save_path.mkdir()
            for x in location_direction:
                save_folder = save_path / x
                if save_folder.is_dir() is False:
                    save_folder.mkdir()

        def convert_to_KB(input_data):
            return [x / 1000 for x in input_data]

        ax.scatter(convert_to_KB(time_scale_features[sampling_rate][location+'_'+direction+'_mean_bytes']),
                   convert_to_KB(time_scale_features[sampling_rate][location+'_'+direction+'_std_bytes']))
        plt.savefig(str(self.save_plot_path/'packet_size'/ (location + '_'+ direction) / (name + '.png')))
        plt.show()

    def plot_attribute_cluster(self, time_scale_dict, sampling_rate):
        fig = plt.figure()
        ax = fig.add_subplot(1,1,1)
        if time_scale_dict == "first":
            time_scale = self.first_time_scale_features[sampling_rate]
            w_window = str(self.time_scales[0])
            name = self.device_name + " "+ w_window + " " + self.data_type
        elif time_scale_dict == "second":
            time_scale = self.second_time_scale_features[sampling_rate]
            w_window = str(self.time_scales[1])
            name = self.device_name +" "+ w_window + " " + self.data_type
        ax.set_title(name+" signature")
        ax.set_xlabel("mean (bytes)")
        ax.set_ylabel("standard deviation (bytes)")
        ax.scatter(time_scale['local_inputs_mean_bytes'], time_scale['local_inputs_std_bytes'], label="local inputs", color='r', alpha=0.6)
        ax.scatter(time_scale['local_outputs_mean_bytes'], time_scale['local_outputs_std_bytes'], label="local outputs", color='b', alpha=0.6)
        ax.scatter(time_scale['internet_inputs_mean_bytes'], time_scale['internet_inputs_std_bytes'], label='internet inputs', color='g', alpha=0.6)
        ax.scatter(time_scale['internet_outputs_mean_bytes'], time_scale['internet_outputs_std_bytes'], label='internet outputs', color='c', alpha=0.6)
        plt.legend(loc='best')
        plt.savefig(str(self.save_plot_path / self.device_name) + name + str(sampling_rate) +"attributes.png")
        plt.show()

    def clean_dataset(self, df):
        df.dropna(inplace=True)
        indices_to_keep = ~df.isin([np.nan, np.inf, -np.inf]).any(1)
        return df[indices_to_keep].astype(np.float64)

