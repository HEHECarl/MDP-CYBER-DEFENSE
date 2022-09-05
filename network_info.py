import imp
import networkx as nx
import matplotlib.pyplot as plt
import numpy as np
import random
from vulnerability_info import VulnerabilityInfo
from mitigation_info import Mitigation

VUL_PROB = 1.0  # Define the probability host will only have one vul
LINK_COF = 1.5  # The number of links compare to hosts, for example with LINK_COF = 1.5, 10 hosts will have 15 links


class NetworkInfo:
    def __init__(self, host_number, max_vul_each_host):
        self.hosts_number = host_number
        self.max_vul_each_host = max_vul_each_host
        self.network = None

    def generate_random_network(self):
        vul_id = 0
        self.network = nx.gnm_random_graph(self.hosts_number, int(self.hosts_number * LINK_COF))
        for host in self.get_hosts():
            self.network.nodes[host]['vuls'] = []
            self.network.nodes[host]['comp'] = False
            self.network.nodes[host]['cvss'] = random.randint(0, 20) / 20
            if random.random() < VUL_PROB:
                vul_id += 1
                self.network.nodes[host]['vuls'].append(VulnerabilityInfo().random_generate(vul_id))
            else:
                for count in range(random.randint(0, self.max_vul_each_host)):
                    vul_id += 1
                    self.network.nodes[host]['vuls'].append(VulnerabilityInfo().random_generate(vul_id))

    def get_hosts(self):
        if self.network is not None:
            return self.network.nodes
        else:
            print("Network Info not Initialized")

    def get_vuls(self, host):
        if self.network is not None:
            return self.network.nodes[host]['vuls']
        else:
            print("Network Info not Initialized")

    def get_cvss(self, host):
        if self.network is not None:
            return self.network.nodes[host]['cvss']
        else:
            print("Network Info not Initialized")

    def is_comp(self, host):
        if self.network is not None:
            return self.network.nodes[host]['comp']
        else:
            print("Network Info not Initialized")

    def draw_network(self):
        color_map = []
        for host in self.get_hosts():
            if self.is_comp(host):
                color_map.append('red')
            else:
                color_map.append('green')
        nx.draw(self.network, node_color=color_map, with_labels=True)
        plt.title = "Network Structure"
        plt.show()