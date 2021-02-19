import numpy as np
import mdptoolbox
import mdptoolbox.example
from numpy import loadtxt
from model import *
import operator
from network_info import *


def main():
    ni = NetworkInfo(3, 2)
    G = nx.Graph()

    v0 = VulnerabilityInfo()
    v0.id = 0
    v0.prob_success = 0.3
    v0.cost = 1

    v1 = VulnerabilityInfo()
    v1.id = 1
    v1.prob_success = 0.
    v1.cost = 0.4

    v2 = VulnerabilityInfo()
    v2.id = 2
    v2.prob_success = 0.5
    v2.cost = 0.9

    v3 = VulnerabilityInfo()
    v3.id = 3
    v3.prob_success = 0.5
    v3.cost = 0.9
    G.add_nodes_from([
        (0, {"comp": False, 'vuls': [v0], 'cvss': 0.3}),
        (1, {"comp": False, 'vuls': [v1], 'cvss': 0.5}),
        (2, {"comp": False, 'vuls': [v2], 'cvss': 0.9}),
        (3, {"comp": False, 'vuls': [v3], 'cvss': 0.9}),
    ])

    G.add_edges_from([(0, 1), (1, 2), (1, 3)])
    # ni.generate_random_network()
    ni.network = G
    ni.draw_network()
    model = ModelGenerator(ni)
    model.train_model(0.9, 0.1, 0.5, 1000)
    print(model.trans)


if __name__ == "__main__":
    main()
