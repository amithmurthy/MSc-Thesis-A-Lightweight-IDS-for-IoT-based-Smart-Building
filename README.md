# MSc Thesis: A Lightweight IDS for IoT-based Smart Building

### DISCLAIMER: 
This is by no means production level code, it is grad student code (!!) developed, under the pressure of deadlines, to fulfill research project requirements and therefore has some inefficiencies. This project consists of many parts (as described below) which requires attention to detail to function properly, and calls for hacks to make things work. The code needs to be cleaned and I will try to do so as much as possible to make it more readable, as well as provide instructions on where it can be modified for conducting experiments to investigate anomaly detection semantics, such as feature engineering, data preprocessing etc. **:construction_worker::hammer: (Readme not yet complete and file naming convention needs to be changed)** :hammer::construction_worker:

## General notes about the code:

* Packet Parser:
   * Uses the Scapy library, which is slow but was chosen due to my proficiency with it. 
   * Designed primarily for parsing the [UNSW](https://iotanalytics.unsw.edu.au/attack-data) and 
      [Mon(IoT)r](https://moniotrlab.ccis.neu.edu/imc19/) datasets (pcaps) e.g., LLC frame packets are dropped. 
       *  Note: carefully read analyse_pcap() in trace_filtering.py to understand what data is being extracted from the pcaps e.g., TCP flags are not extracted 
        and logic will need to be added in order to do so. 
   * Defines the packet direction for each packet in terms of: local_network -> iot, iot -> local_network, 
      internet -> iot, iot -> internet, iot -> iot
   * Extracts protocol, payload size, ip src, ip dst, src and dst ports (if applicable) from packet headers and 
      appends info to a flow table, where keys are MAC address in the network and values are a list of extracted 
      packet header info (dictionaries) - amounting to a device's traffic in the pcap.  
   * Once pcap is parsed, mac addresses (keys) from flow table is instantiated as DeviceProfile() class objects and serialised using Klepto. This allows for on-the-fly analysis of device/network traffic in the pcap.
        * Note: the path for storing this is according to my local machine. 
   * All logic such as timestamp conversion, payload size (TCP/UDP/IPv6/IPv4/ARP/ICMP) etc., has been rigoriously checked and validated using Wireshark.
 
 * Data-Preprocessing & Feature Engineering:
 
      *  All serialised objects are loaded, per specified IoT device, from the directory and device traffic in the dataset is sorted into flows coarse-grained over location and direction of traffic. This creates 4 flow tuples = local_inputs, local_outputs, internet_inputs, internet_outputs
      *  The flows are computed into time series vectors, where vector elements contain the amount of traffic (bytes and packets) over the flow in consecutive s-second samples i.e., throughput of flow (e.g., internet_outputs) by the device sampled at a configurable s-second rate. 
      *  Vectors are further divided into a larger (configurable) w-second window to extract two-element features: mean and standard deviation of bytes/packets. 
      *  These features, and others, are computed at multiple time scales (e.g., 1 min, 2 min, 4min) to accurately characterise long range dependent traffic. **experiments can be conducted on the impact of time scale windows on attack detection accuracy by configuring the time_scale array when instantiating ModelDevice()**
    *  Extracted features are then normalised, dimensionality reduction (PCA) is applied and the resulting data is saved in CSV format. 

* Classification models & Validation: 

    * Classification models are device-specific and are instantiated in ModelDevice() by passing in 'train'. Anomaly detection semantics, such as cluster boundary, number of clusters/ finding optimal clusters, distance function (e.g., euclidean/manhattan) etc, can be configured in class constructor. 
    * Anomalies are validated by converting [attack flow timestamps](https://iotanalytics.unsw.edu.au/attack-data) into the configured time scale window from preprocessing.

* Misc:
    
    *  PacketLevelSignatures, as outlined by [Trimananda et al.](https://www.ndss-symposium.org/wp-content/uploads/2020/02/24097.pdf) in NDSS, distinctly capture the event-driven communication behaviour of IoT devices which can possibly be leveraged as a feature. Due to time constraints this was not properly explored, but the signature extraction methodology is implemented in packet_level_signature.py. 
    *  Data visualisation functions contain "plot" (naming convention) to graph feature correlation,devive traffic fingerprints, classification model performance plots, and much more. 


 
