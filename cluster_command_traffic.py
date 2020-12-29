# import numpy as np
# import pandas as pd
# import matplotlib.pyplot as plt
# import seaborn as sns
# import plotly.offline as pyo
# pyo.init_notebook_mode()
# import plotly.graph_objs as go
# from plotly import tools
# from plotly.subplots import make_subplots
# import plotly.offline as py
# import plotly.express as px
# from sklearn.cluster import DBSCAN
# from sklearn.neighbours import NearestNeighbors
# from sklearn.metrics import silhouetter_score
# from sklearn.preprocessing import StandardScaler
# from sklearn.decomposition import PCA
#
# def cluster_commands(command_stats):
#     df = pd.DataFrame.from_dict(command_stats)


# Online Python compiler (interpreter) to run Python online.
# Write Python 3 code in this online editor and run it.
pairs = [("C-50", "S-90"), ("C-50", 0), ("S-150", "C-500"), ("C-50", 0)]

pairs2 = [("C-50", 0), ("C-50", 0), ("C-90", "S-100")]

pkts = ["C50", "S90", "C50", "S150", "C500", "C50"]
pkts2 = ["C50", "C50", "C90", "S100"]
pkt_index_step = 0
pkt_index = 0
sequences = []
sequenced_pairs_index = []

i = 0

while i < len(pairs2):
    print(sequenced_pairs_index)
    p1 = pairs2[i]
    if i <= len(pairs2) - 2:
        p2 = pairs2[i + 1]
    if i == len(pairs2) - 1:
        break
    if i in sequenced_pairs_index:
        continue

    seq_len = 0
    p1_pkt = pkt_index
    if 0 in p1:
        seq_len += 1
        # i = 1
        # pkt_index += 1
    if 0 not in p1:
        seq_len += 2
    p2_pkt = p1_pkt + seq_len
    # check whether p1 is before p2
    if p1_pkt == p2_pkt - seq_len:
        # print("sequence pairs:", p1, p2)
        sequenced_pairs_index.append(i)
        sequenced_pairs_index.append(i + 1)
        step = 2
        sequences.append((p1, p2))
        if 0 in p2:
            seq_len += 1
        if 0 not in p2:
            seq_len += 2
    else:
        step = 1

    pkt_index += seq_len
    i = i + step


