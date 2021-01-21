from sklearn.decomposition import PCA
import matplotlib.pyplot as plt
from sklearn.preprocessing import StandardScaler, MinMaxScaler
from sklearn.pipeline import Pipeline
from sklearn.cluster import KMeans
import csv
import klepto as kl
from multiprocessing import Pool
# import tensorflow as tf
from pathlib import Path
import pandas as pd
import numpy as np
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
        elif model_function == 'train':
            self.create_clustering_model()
        elif model_function == 'anomaly_detection':
            self.time_scale_anomalies = None
            self.anomaly_detection()

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
            # time_scale_feature['local_input_mean'].extend(local_input_mean)
            # time_scale_feature['local_input_std'].extend(local_input_std)
            local_output_mean, local_output_std = device_obj.get_mean_and_std(time_scale_dict['local_outputs'])
            # time_scale_feature['local_output_mean'].extend(local_output_mean)
            # time_scale_feature['local_output_std'].extend(local_output_std)
            internet_input_mean, internet_input_std = device_obj.get_mean_and_std(time_scale_dict['internet_inputs'])
            # time_scale_feature['internet_input_mean'].extend(internet_input_mean)
            # time_scale_feature['internet_input_std'].extend(internet_input_std)
            internet_output_mean, internet_output_std = device_obj.get_mean_and_std(time_scale_dict['internet_outputs'])
            # time_scale_feature['internet_output_mean'].extend(internet_output_mean)
            # time_scale_feature['internet_output_std'].extend(internet_output_std)
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
        # print(len(first_time_scale_cols + second_time_scale_cols))
        # df = pd.DataFrame()

        # all_features = first_time_scale_cols + second_time_scale_cols
        # print('all features len', len(all_features))
        # print("headers len", len(headers))

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

        ##Find the eigen values and vectors
        # x = df_first_time_scale.loc[:, first_headers].values
        # x = StandardScaler().fit_transform(x)
        # print(x)
        # data = df_first_time_scale.loc[:, first_headers].values
        # pipeline = Pipeline([('scaling', StandardScaler()), ('pca', PCA())])
        # pipeline.fit_transform(data)
        # x.dropna(inplace=True)
        # pca = PCA(n_components=0.95)
        # X_pca = pca.fit(df_first_time_zscore)
        # print(X_pca.components_)
        # X_reduced.to_csv(str(file_path))
        # write_csv_file(first_time_scale_cols + second_time_scale_cols, headers)

        print("finished saving csv")

    def create_clustering_model(self):
        """TODO: Assign the timescale dataset to a variable i.e. which timescale dataset is being trained"""
        time_scale_files = self.get_time_scale_files()
        p = Pool(len(time_scale_files))
        p.map(self.train_time_scale_model, time_scale_files)

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

    def train_model(self, df, *inspection):
        """ Clustering model instantiated
        df: csv in pd.DataFrame format
        inspection: optional argument to return cluster model for anomaly detection
        """
        data = df.values
        km = KMeans(n_clusters=6, init='random', n_init=10)
        clusters = km.fit_predict(data)
        centroids = km.cluster_centers_
        print("Shape of data", centroids.shape)
        if inspection:
            return clusters
        return self.find_cluster_boundary(data, centroids, clusters)

    def save_model(self, df, file):
        cluster_boundary, cluster_distances = self.train_model(df)
        file_name = self.device_folder / "kmeans-model" /str(file)[:-4]
        ar = kl.archives.dir_archive(name=file_name, serialized=True, cached=True, protocol=4)

        ar['cluster_boundary'] = cluster_boundary
        ar['cluster_distances'] = cluster_distances
        ar.dump()
        ar.clear()

    def get_instance_distance_points(self, data, cx, cy, cz, i_centroid, cluster_labels):
        euclidean_distances = [np.sqrt((x - cx) ** 2 + (y - cy) ** 2 + (z - cz) ** 2) for (x, y, z) in
                               data[cluster_labels == i_centroid]]
        # print('centroid distances',euclidean_distances)
        return euclidean_distances

    def find_cluster_boundary(self, data, centroids, clusters, *return_type):
        cluster_distances = {}

        for i, (cx, cy, cz) in enumerate(centroids):
            if i not in cluster_distances:
                cluster_distances[i] = self.get_instance_distance_points(data, cx, cy,cz, i, clusters)
            # centroid_distances[i].extend(distance)

        cluster_boundary = {centroid: np.percentile(np.array(cluster_distances[centroid]), 97.5) for centroid in cluster_distances}
        if return_type:
            return cluster_distances
        else:
            return cluster_boundary, cluster_distances

    def anomaly_detection(self):
        time_scale_boundary = self.get_benign_cluster_boundary()
        self.time_scale_anomalies = {time_scale: [] for time_scale in time_scale_boundary}
        p = Pool(len(time_scale_boundary.keys()))
        p.map(self.inspect_traffic, time_scale_boundary.items())
        print(self.time_scale_anomalies)

    def inspect_traffic(self, time_scale_info):
        time_scale = time_scale_info[0]
        benign_time_scale_data = self.device_folder / "Benign" / (str(time_scale) + '.csv')
        inspect_data = self.device_folder/ "Attack"/ (str(time_scale) + '.csv')
        benign_df = pd.read_csv(str(benign_time_scale_data))
        inspect_df = pd.read_csv(str(inspect_data))
        inspect_df = inspect_df.values
        benign_cluster_model = self.train_model(benign_df, "return")
        results = benign_cluster_model.predict(inspect_df)
        cluster_points_distances = self.find_cluster_boundary(inspect_df, benign_cluster_model.cluster_centers_, results, return_type="cluster_distances")
        self.def_find_anomalies(time_scale, time_scale_info[1], cluster_points_distances)

    def find_anomalies(self, time_scale, cluster_boundary, cluster_distances):
        for centroid in cluster_distances:
            for instance in cluster_distances[centroid]:
                if instance >= cluster_boundary[centroid]:
                    self.time_scale_anomalies[time_scale].append(instance)


    def get_benign_cluster_boundary(self):
        saved_model = self.device_folder / "kmeans-model"
        time_scale_boundary = {time_scale.name: None for time_scale in saved_model.iterdir()}
        for time_scale in saved_model.iterdir():
            db = saved_model / time_scale.name
            d = kl.archives.dir_archive(name=db, serialized=True)
            d.load('cluster_boundary')
            time_scale_boundary[time_scale.name] = d['cluster_boundary']
        # print(time_scale_boundary)
        return time_scale_boundary


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
