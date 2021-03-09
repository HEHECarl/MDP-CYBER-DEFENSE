import numpy as np
import mdptoolbox
import mdptoolbox.example
from numpy import loadtxt
from model import *
import operator
from network_info import *


def main():
    ni = NetworkInfo(3, 2)

    # G = nx.DiGraph()
    #
    # v1 = VulnerabilityInfo()
    # v1.id = 1
    # v1.prob_success = 1
    # v1.cost = 0.5
    #
    # v2 = VulnerabilityInfo()
    # v2.id = 2
    # v2.prob_success = 1
    # v2.cost = 0.75
    #
    # v3 = VulnerabilityInfo()
    # v3.id = 3
    # v3.prob_success = 1
    # v3.cost = 0.2
    #
    # v4 = VulnerabilityInfo()
    # v4.id = 4
    # v4.prob_success = 1
    # v4.cost = 0.5
    #
    # G.add_nodes_from([
    #     (0, {"comp": True, 'vuls': [], 'cvss': 0}),
    #     (1, {"comp": False, 'vuls': [v1], 'cvss': 0.43}),
    #     (2, {"comp": False, 'vuls': [v2], 'cvss': 0.21}),
    #     (3, {"comp": False, 'vuls': [v3], 'cvss': 1}),
    #     (4, {"comp": False, 'vuls': [v4], 'cvss': 0.43}),
    # ])
    #
    # G.add_edges_from([(0, 1), (1, 0),
    #                   (0, 2), (2, 0),
    #                   (1, 2), (2, 1),
    #                   (1, 3), (3, 1),
    #                   (2, 4), (4, 2),
    #                   (3, 4), (4, 3)])
    # ni.network = G
    # #ni.draw_network()
    #
    # actions = [Action(PATCH, target=3, vul=v3),
    #            Action(PATCH, target=2, vul=v2),
    #            Action(BLOCK, target=1, subtarget=0),
    #            Action(BLOCK, target=4, subtarget=2)]

    G = nx.DiGraph()

    v1 = VulnerabilityInfo()
    v1.id = 1
    v1.prob_success = 1
    v1.cost = 0.5

    v2 = VulnerabilityInfo()
    v2.id = 2
    v2.prob_success = 1
    v2.cost = 0.75


    G.add_nodes_from([
        (0, {"comp": True, 'vuls': [], 'cvss': 0}),
        (1, {"comp": False, 'vuls': [v1], 'cvss': 0.43}),
        (2, {"comp": False, 'vuls': [v2], 'cvss': 0.21}),
    ])

    G.add_edges_from([(0, 1), (1, 0),
                      (0, 2), (2, 0),
                      (1, 2), (2, 1)])
    ni.network = G
    #ni.draw_network()

    actions = [Action(PATCH, target=2, vul=v2),
               Action(PATCH, target=1, vul=v1),
               Action(BLOCK, target=1, subtarget=0),
               Action(BLOCK, target=2, subtarget=0)]

    model = ModelGenerator(ni, actions)

    model.train_model(0.9, 0.1, 1, 1000)
    print()


if __name__ == "__main__":
    main()
