import networkx as nx
import matplotlib.pyplot as plt
import numpy as np
import random

VUL_PROB = 0.9


class NetworkInfo:
    def __init__(self, host_number, max_vul_each_host):
        self.hosts_number = host_number
        self.max_vul_each_host = max_vul_each_host
        self.network = None

    def generate_random_network(self):
        self.network = nx.gnm_random_graph(self.hosts_number, int(self.hosts_number * 1.5))
        for host in self.get_hosts():
            self.network.nodes[host]['vuls'] = {}
            self.network.nodes[host]['comp'] = False
            if random.random() < VUL_PROB:
                self.network.nodes[host]['vuls'][0] = random.randint(0, 20) / 20
            else:
                for count in range(random.randint(0, self.max_vul_each_host)):
                    self.network.nodes[host]['vuls'][count] = random.randint(0, 20) / 20
        print(self.network.nodes[0])

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


class VulnerabilityInfo:
    def __init__(self):
        