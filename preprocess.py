from sklearn.decomposition import PCA
import matplotlib.pyplot as plt
from sklearn.preprocessing import StandardScaler, MinMaxScaler
from sklearn.pipeline import Pipeline
from sklearn.cluster import KMeans
import csv
from scapy.all import *
from scapy.layers.l2 import Ether
import klepto as kl
from multiprocessing import Pool
# import tensorflow as tf
from pathlib import Path
import pandas as pd
import numpy as np
from tools import get_mac_addr, unpickle_network_trace_and_device_obj
import time
from datetime import datetime
from io import FileIO
""" Functions for normalising data """

class ModelDevice:
    global first_headers
    global second_headers
    first_headers = ["250_local_inputs_mean", "250_local_inputs_std", "250_local_outputs_mean",
                     "250_local_outputs_std",
                     "250_internet_inputs_mean", "250_internet_inputs_std", "250_internet_outputs_mean",
                     "250_internet_outputs_std"]
    second_headers = ["500_local_inputs_mean", "500_local_inputs_std", "500_local_outputs_mean",
                      "500_local_outputs_std",
                      "500_internet_inputs_mean", "500_internet_inputs_std", "500_internet_outputs_mean",
                      "500_internet_outputs_std"]

    def __init__(self, model_function, device_name, **kwargs):
        self.features = ['local_inputs_mean', 'local_inputs_std', 'local_outputs_mean', 'local_outputs_std',
                    'internet_inputs_mean',
                    'internet_inputs_std', 'internet_outputs_mean', 'internet_outputs_std']
        self.first_time_scale_features = {feature:[] for feature in self.features}
        self.second_time_scale_features = {feature:[] for feature in self.features}
        self.device_folder = Path(r"C:\Users\amith\Documents\Uni\Masters\device_attributes") / device_name
        self.training_data = Path(r"C:\Users\amith\Documents\Uni\Masters\device_attributes") / device_name / "Benign"
        self.attack_data = Path(r"C:\Users\amith\Documents\Uni\Masters\device_attributes") / device_name / "Attack"
        self.save_plot_path = Path(r"C:\Users\amith\Documents\Uni\Masters\Graphs\Machine Learning") / device_name
        if model_function == 'preprocess':
            self.device_traffic = kwargs['device_traffic']
            self.process_all_traffic()
        else:
            self.km_model = KMeans(n_clusters=6, init='random', n_init=10)
            self.model_function = model_function
            if model_function == 'train':
                self.create_clustering_model()
            elif model_function == 'anomaly_detection':
                self.time_scale_anomalies = None
                self.anomaly_timestamp = {}
                self.benign_model = {}
                self.file_device_traffic_duration = {}
                self.relative_attack_timestamp = {}
                self.anomaly_detection()
            elif model_function == 'validate':
                self.anomaly_timestamp = {}
                self.file_device_traffic_duration = {}
                self.relative_attack_timestamp = {}
                self.device_name = device_name
                self.validate_anomalies()


    def get_time_scale_features(self, device_obj):
        flows = ['local_inputs', 'local_outputs', 'internet_inputs', 'internet_outputs']
        first_time_scale = {attr: None for attr in flows}
        second_time_scale = {attr: None for attr in flows}
        print("Getting time scale features...")
        for attribute in flows:
            first_time_scale[attribute] = device_obj.create_traffic_volume_features(attribute, w_window=250)
            second_time_scale[attribute] = device_obj.create_traffic_volume_features(attribute, w_window=500)

        def get_features(time_scale_dict, time_scale_feature):
            local_input_mean, local_input_std = device_obj.get_mean_and_std(time_scale_dict['local_inputs'])
            local_output_mean, local_output_std = device_obj.get_mean_and_std(time_scale_dict['local_outputs'])
            internet_input_mean, internet_input_std = device_obj.get_mean_and_std(time_scale_dict['internet_inputs'])
            internet_output_mean, internet_output_std = device_obj.get_mean_and_std(time_scale_dict['internet_outputs'])
            return local_input_mean, local_input_std, local_output_mean, local_output_std, internet_input_mean, internet_input_std, internet_output_mean, internet_output_std

        def set_features(time_scale_feat,time_scale_feat_dict):
            for i in range(0, len(self.features)):
                time_scale_feat_dict[self.features[i]].extend(time_scale_feat[i])

        first_time_scale_feat = get_features(first_time_scale, self.first_time_scale_features)
        second_time_scale_feat = get_features(second_time_scale, self.second_time_scale_features)
        set_features(first_time_scale_feat, self.first_time_scale_features)
        set_features(second_time_scale_feat, self.second_time_scale_features)

    def process_all_traffic(self):
        for device_obj in self.device_traffic:
            # print(device_obj)
            self.get_time_scale_features(device_obj)
        self.save_device_traffic_attributes()
        # self.plot_attribute_cluster("first")
        # self.plot_attribute_cluster("second")

    def plot_attribute_cluster(self, time_scale_dict):
        fig = plt.figure()
        ax = fig.add_subplot(1,1,1)
        if time_scale_dict == "first":
            time_scale = self.first_time_scale_features
        elif time_scale_dict == "second":
            time_scale = self.second_time_scale_features
        ax.set_title(time_scale_dict + " time scale cluster")
        ax.set_xlabel("mean (bytes)")
        ax.set_ylabel("standard deviation (bytes)")
        ax.scatter(time_scale['local_inputs_mean'], time_scale['local_inputs_std'], label="local inputs", color='r', alpha=0.6)
        ax.scatter(time_scale['local_outputs_mean'],
                   time_scale['local_outputs_std'], label="local outputs", color='b', alpha=0.6)
        ax.scatter(time_scale['internet_inputs_mean'], time_scale['internet_inputs_std'], label='internet inputs', color='g', alpha=0.6)
        ax.scatter(time_scale['internet_outputs_mean'],
                   time_scale['internet_outputs_std'], label='internet outputs', color='c', alpha=0.6)
        plt.legend(loc='best')
        plt.savefig(str(self.device_folder) + time_scale_dict + "attributes.png")
        plt.show()

    def save_device_traffic_attributes(self):
        """Takes in one single device instance"""
        # rows = zip(first_time_scale_cols, second_time_scale_cols)

        file_path = Path(r"C:\Users\amith\Documents\Uni\Masters\device_attributes") / self.device_traffic[0].device_name

        df_first_time_scale, df_second_time_scale = pd.DataFrame(), pd.DataFrame()

        print(self.first_time_scale_features.keys())


        for key in self.first_time_scale_features:
            try:
                # df[first_headers[i]] = pd.Series(first_time_scale_cols[i])
                header = "250_" + str(key)
                df_first_time_scale[header] = pd.Series(self.first_time_scale_features[key])
                # print(first_headers[i], len(first_time_scale_cols[i]))
            except ValueError as e:
                print(header)
                print(e)
        for key in self.second_time_scale_features:
            # df[second_headers[i]] = pd.Series(second_time_scale_cols[i])
            header = "500_" + str(key)
            df_second_time_scale[header] = pd.Series(self.second_time_scale_features[key])
            # print(second_headers[i], len(second_time_scale_cols[i]))

        df_first_time_scale.to_csv(str(file_path) + "second.csv")
        # Compute z-scores for attributes
        # cols = list(df.columns)
        z_score_cols = []
        def z_score(cols, df, org_df):
            for col in cols:
                col_zscore = col + '_zscore'
                z_score_cols.append(col_zscore)
                df[col_zscore] = (org_df[col] - org_df[col].mean()) / org_df[col].std()
            return df

        df_first_time_scale = df_first_time_scale.fillna(0)
        df_second_time_scale = df_second_time_scale.fillna(0)
        df_first_time_zscore = z_score(list(df_first_time_scale.columns), pd.DataFrame(), df_first_time_scale)
        df_second_time_zscore = z_score(list(df_second_time_scale.columns), pd.DataFrame(), df_second_time_scale)
        df_first_time_zscore.to_csv(str(file_path) + "attackfirstzscore.csv")
        df_second_time_zscore.to_csv(str(file_path)+"attacksecondscore.csv")
        # df_first_time_scale.to_csv(str(file_path))
        # test = self.clean_dataset(df_second_time_zscore)
        # df_first_time_scale = clean_dataset(df_first_time_scale)
        print("finished saving csv")

    def create_clustering_model(self):
        """TODO: Assign the timescale dataset to a variable i.e. which timescale dataset is being trained"""
        time_scale_files = self.get_time_scale_files()
        p = Pool(len(time_scale_files))
        # print('time_scale_files', time_scale_files)
        # p.map(self.train_time_scale_model, time_scale_files)
        for file in time_scale_files:
            self.train_time_scale_model(file)

    def train_time_scale_model(self, file):
        """Gets csv and creates clustering model for time_scale features"""
        dataset = self.training_data / file
        df = pd.read_csv(str(dataset))
        self.save_model(df, file)
        # self.find_k(df)

    def get_time_scale_files(self):
        time_scale_files = []
        for file in self.training_data.iterdir():
            time_scale_files.append(file.name)
        return time_scale_files

    def train_model(self, df):
        """ Clustering model instantiated
        df: csv in pd.DataFrame format
        inspection: optional argument to return cluster model for anomaly detection
        """
        data = df.values
        if self.model_function == 'anomaly_detection':
            model = self.km_model.fit(data)
            return model
        else:
            clusters = self.km_model.fit_predict(data)
            centroids = self.km_model.cluster_centers_
            # self.km_model = self.km_model.fit(data)
            print("Shape of data", centroids.shape)
            return self.find_cluster_boundary(data, centroids, clusters)

    def save_model(self, df, file):
        cluster_boundary, cluster_distances = self.train_model(df)
        file_name = self.device_folder / "kmeans-model" /str(file)[:-4]
        ar = kl.archives.dir_archive(name=file_name, serialized=True, cached=True, protocol=4)
        ar['cluster_model'] = self.km_model
        ar['cluster_boundary'] = cluster_boundary
        ar['cluster_distances'] = cluster_distances
        ar.dump()
        ar.clear()

    def save_anomalies(self):
        file_name = self.device_folder / "kmeans-model"
        ar = kl.archives.dir_archive(name=file_name, serialized=True, cached=True, protocol=4)
        ar['anomalies'] = self.time_scale_anomalies
        ar.dump()
        ar.clear()

    def get_instance_distance_points(self, data, cx, cy, cz, i_centroid, cluster_labels):
        euclidean_distances = [np.sqrt((x - cx) ** 2 + (y - cy) ** 2 + (z - cz) ** 2) for (x, y, z) in
                               data[cluster_labels == i_centroid]]

        # print('centroid distances',euclidean_distances)
        return euclidean_distances

    def find_cluster_boundary(self, data, centroids, clusters):
        cluster_distances = {}

        for i, (cx, cy, cz) in enumerate(centroids):
            if i not in cluster_distances:
                cluster_distances[i] = self.get_instance_distance_points(data, cx, cy,cz, i, clusters)
            # centroid_distances[i].extend(distance)

        if self.model_function == 'anomaly_detection':
            return cluster_distances
        else:
            cluster_boundary = {centroid: np.percentile(np.array(cluster_distances[centroid]), 97.5) for centroid in
                                cluster_distances}
            return cluster_boundary, cluster_distances

    def anomaly_detection(self):
        self.get_benign_model()
        self.time_scale_anomalies = {time_scale: {'anomalies':[], 'anomaly_index':[]} for time_scale in self.benign_model}
        p = Pool(len(self.benign_model.keys()))
        # p.map(self.inspect_traffic, self.benign_model.keys())
        for time_scale in self.benign_model:
            self.inspect_traffic(time_scale)
        self.save_anomalies()
        self.validate_anomalies()

        # print(self.time_scale_anomalies['250s'])
        # print(self.time_scale_anomalies['500s'])

    def inspect_traffic(self, time_scale):
        """Cluster boundary for time_scale model are the arguments"""
        benign_time_scale_data = self.device_folder / "Benign" / (str(time_scale) + '.csv')
        attack_file = self.device_folder/ "Attack"/ (str(time_scale) + '.csv')
        benign_df = pd.read_csv(str(benign_time_scale_data))
        inspect_df = pd.read_csv(str(attack_file))
        inspect_data = inspect_df.values
        benign_cluster_model = self.benign_model[time_scale]['cluster_model']
        # self.validate_model(benign_cluster_model, time_scale)
        results = benign_cluster_model.predict(inspect_data)
        cluster_points_distances = self.find_cluster_boundary(inspect_data, benign_cluster_model.cluster_centers_, results)
        cluster_map = pd.DataFrame()
        cluster_map['data_index'] = inspect_df.index.values
        cluster_map['cluster'] = results
        cluster_map.to_csv(str(self.device_folder/time_scale)+"index_data_clusters.csv")
        cluster_boundary = self.benign_model[time_scale]['cluster_boundary']
        self.find_anomalies(time_scale, cluster_boundary, cluster_points_distances, cluster_map)

    def find_anomalies(self, time_scale, cluster_boundary, cluster_distances, cluster_map):
        # print(time_scale, 'boundaries', cluster_boundary)
        for centroid in cluster_distances:
            # print(time_scale, 'distances',  cluster_distances[centroid])
            centroid_data_index = list(cluster_map[cluster_map.cluster == centroid].data_index.values)
            i = 0
            for instance in cluster_distances[centroid]:
                if instance >= cluster_boundary[centroid]:
                    self.time_scale_anomalies[time_scale]['anomalies'].append(instance)
                    self.time_scale_anomalies[time_scale]['anomaly_index'].append(centroid_data_index[i])
                i += 1

    def validate_anomalies(self):
        """TODO: Need to save anomaly outputs and extract for each experiment before running validation - requires methods"""
        # self.correlate_index_timestamp()
        # extract attack annotations timestamp
        self.attack_annotations()
        self.reconstruct_device_activity()
        self.convert_annotations_to_timescale_index()
        # self.link_annotations_and_output()

    def convert_annotations_to_timescale_index(self):
        if self.model_function == 'validate':
            time_scales = ['250s', '500s']
        else:
            time_scales = list(self.time_scale_anomalies.keys())
        time_scale_anomaly_index = {time_scale: [] for time_scale in time_scales}
        global_attack_timestamp = []

        def increment_device_time(file):
            files = list(self.file_device_traffic_duration.keys())
            file_index = files.index(file)
            if file_index == 0:
                return 0
            else:
                total_device_time = 0
                for i in range(0,file_index):
                    total_device_time += self.file_device_traffic_duration[files[i]]
                return total_device_time

        print(self.file_device_traffic_duration)
        for file in self.relative_attack_timestamp:
            device_duration = increment_device_time(file)
            print('device_duration', device_duration)
            print('relative times', self.relative_attack_timestamp[file])
            for rel_attack_time in self.relative_attack_timestamp[file]:
                start = device_duration + rel_attack_time[0]
                end = device_duration + rel_attack_time[1]
                global_attack_timestamp.append((start, end))

        def ts_index_range(attack_timestamp, time_scale):
            time_scale = int(time_scale[:-1])
            start_i, end_i = int((attack_timestamp[0] / time_scale) - 1), int((attack_timestamp[1] / time_scale) - 1)
            return [i for i in range(start_i, end_i + 1, 1)]

        for attack_time in global_attack_timestamp:
            for time_scale in time_scale_anomaly_index:
                time_scale_anomaly_index[time_scale].extend(ts_index_range(attack_time, time_scale))

        # for ts in time_scale_anomaly_index:
        #     t = int(ts[:-1])
        #     print([t* i for i in time_scale_anomaly_index[ts]])

    def link_annotations_and_output(self):
        pass


    def reconstruct_device_activity(self):
        processed_attack_traffic = r"C:\Users\amith\Documents\Uni\Masters\processed-traffic\Attack"
        network_instances = unpickle_network_trace_and_device_obj(processed_attack_traffic, devices=self.device_name)
        # file_device_traffic_duration = {network_obj.file_name: None for network_obj in network_instances}
        for network_obj in network_instances:
            for device_obj in network_instances[network_obj]:
                assert len(network_instances[network_obj]) < 2
                device_obj.update_profile([],[],compute_attributes=False)
                self.file_device_traffic_duration[network_obj.file_name[:-5]] = device_obj.set_device_activity('duration')

    def attack_annotations(self):
        device_mac_addr = get_mac_addr(self.device_name).replace(':', '')
        # print('device mac addr', device_mac_addr)
        annotation_path = Path(r"C:\Users\amith\Documents\Uni\Masters\Datasets\UNSW\2018\annotations\annotations") / (device_mac_addr + ".csv")
        annotations = pd.read_csv(str(annotation_path), header=None)
        attack_times = {} #attack time for each date {'2018-06-01':[(start, end)...],...}
        for i, j in zip(annotations[0], annotations[1]):
            # start_date = time.strftime('%Y-%m-%d', time.localtime(i))
            start_date = datetime.utcfromtimestamp(i).strftime('%Y-%m-%d')
            end_date = datetime.utcfromtimestamp(j).strftime('%Y-%m-%d') #(time.strftime('%Y-%m-%d', time.localtime(j))[2:])
            start_date, end_date = start_date[2:], end_date[2:]
            if start_date in attack_times:
                if start_date == end_date:
                    attack_times[start_date].append((datetime.utcfromtimestamp(i).strftime('%H:%M:%S'), datetime.utcfromtimestamp(j).strftime('%H:%M:%S')))
                    # attack_times[start_date].append((time.strftime('%H:%M:%S', time.localtime(i)), time.strftime('%H:%M:%S', time.localtime(j))))
                else:
                    print("start date and end date are different - fix data structure")
                    print("VALIDATION WILL NOT WORK")
            else:
                attack_times[start_date] = []
                attack_times[start_date].append((datetime.utcfromtimestamp(i).strftime('%H:%M:%S'), datetime.utcfromtimestamp(j).strftime('%H:%M:%S')))
                # attack_times[start_date].append((time.strftime('%H:%M:%S', time.localtime(i)), time.strftime('%H:%M:%S', time.localtime(j))))


        device_first_pkt = self.get_attack_file_first_pkt_epoch(attack_times)
        self.get_relative_attack_timestamps(device_first_pkt, attack_times)
        # self.reconstruct_device_activity()

    def get_relative_attack_timestamps(self, device_first_pkt, attack_times):

        def attack_duration(attack_datetime):
            fmt = '%H:%M:%S'
            return (datetime.strptime(attack_datetime[1], fmt) - datetime.strptime(attack_datetime[0], fmt)).total_seconds()
        for file in device_first_pkt:
            # print('first pkt time in file', device_first_pkt[file])
            # print('attack timestamps in file', attack_times[file])
            self.relative_attack_timestamp[file] = []
            first_pkt_time = datetime.strptime(device_first_pkt[file], '%H:%M:%S')
            for attack_timestamp in attack_times[file]:
                rel_attack_start = (datetime.strptime(attack_timestamp[0], '%H:%M:%S') - first_pkt_time).total_seconds()
                rel_attack_duration = attack_duration(attack_timestamp)
                rel_attack_end = rel_attack_start + rel_attack_duration
                self.relative_attack_timestamp[file].append((rel_attack_start, rel_attack_end))
                # print('rel_diff', rel_dif, 'file', file)
                # rel_attack_end = (datetime.strptime(attack_timestamp[1], '%H:%M:%S') - first_pkt_time).total_seconds()
        # print(self.relative_attack_timestamp)

    def get_attack_file_first_pkt_epoch(self, attack_times):
        attack_dataset = Path(r"C:\Users\amith\Documents\Uni\Masters\Datasets\UNSW\2018\Attack Data")
        first_pkt_time = {attack_file: None for attack_file in attack_times}
        for pcap in attack_dataset.iterdir():
            if pcap.name[:-5] in list(attack_times.keys()):
                first_pkt_epoch = self.read_pcap(FileIO(pcap))
                first_pkt_time[pcap.name[:-5]] = datetime.utcfromtimestamp(first_pkt_epoch).strftime('%H:%M:%S')
        return first_pkt_time

    def read_pcap(self, pcap_file):
        device_filter = get_mac_addr(self.device_name)
        count = 0
        # print(pcap_file)
        for pkt_data, pkt_metadata in RawPcapReader(pcap_file):
            count += 1
            ether_pkt = Ether(pkt_data)
            if ether_pkt.src == device_filter or ether_pkt.dst == device_filter:
                # print(count, pcap_file)
                return (((pkt_metadata.tshigh << 32) | pkt_metadata.tslow) / pkt_metadata.tsresol)
            else:
                continue

    def correlate_index_timestamp(self):
        for time_scale in self.time_scale_anomalies:
            # total_device_time = self.get_total_device_time(time_scale)
            # print(time_scale, 'total duration', total_device_time)
            # Data structure to store anomaly timestamp
            self.anomaly_timestamp[time_scale] = []
            for centroid in self.time_scale_anomalies[time_scale]:
                for anomaly_index in self.time_scale_anomalies[time_scale][centroid]:
                    anomaly_timestamp = (anomaly_index + 1) * int(time_scale[:-1])
                    self.anomaly_timestamp[time_scale].append(anomaly_timestamp)
            print(time_scale, 'anomaly timestamp', self.anomaly_timestamp[time_scale])

    def get_total_device_time(self, time_scale):
        file_in = self.device_folder / (str(time_scale) + "index_data_clusters.csv")
        cluster_map = pd.read_csv(str(file_in))
        last_index = list(cluster_map.data_index.values)[-1]
        return (last_index + 1) * int(time_scale[:-1])

    def get_benign_model(self):
        saved_model = self.device_folder / "kmeans-model"
        time_scale_boundary = {}
        # time_scale_boundary = {time_scale.name: None for time_scale in saved_model.iterdir()}
        # self.benign_distances = {time_scale.name: None for time_scale in saved_model.iterdir()}
        for time_scale in saved_model.iterdir():
            if len(time_scale.name) > 7:
                continue
            db = saved_model / time_scale.name
            d = kl.archives.dir_archive(name=db, serialized=True)
            d.load('cluster_boundary')
            d.load('cluster_distances')
            d.load('cluster_model')
            # time_scale_boundary[time_scale.name] = d['cluster_boundary']
            self.benign_model[time_scale.name] = {}
            self.benign_model[time_scale.name]['cluster_model'] = d['cluster_model']
            self.benign_model[time_scale.name]['benign_distances'] = d['cluster_distances']
            self.benign_model[time_scale.name]['benign_centroids'] = d['cluster_model'].cluster_centers_
            self.benign_model[time_scale.name]['cluster_boundary'] = d['cluster_boundary']
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

    def find_k(self, df):
        cols = ['P1','P2']
        x = df.values
        K = range(2,15)
        inertia = []
        for k in K:
            km = KMeans(n_clusters=k, init="random",n_init=10)
            km = km.fit_predict(x)
            inertia.append(km.inertia_)
        plt.plot(K, inertia, 'bx-')
        plt.xlabel('k')
        plt.ylabel('Inertia')
        plt.title('Elbow method')
        plt.savefig(str(self.file_path)+'500secelbowmethod.png')
        plt.show()
        print(inertia)

    def clean_dataset(self, df):
        df.dropna(inplace=True)
        indices_to_keep = ~df.isin([np.nan, np.inf, -np.inf]).any(1)
        return df[indices_to_keep].astype(np.float64)
