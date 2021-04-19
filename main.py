import numpy as np
import mdptoolbox
import mdptoolbox.example
from numpy import loadtxt
from model import *
import operator
from network_info import *

ACTIONS = ["IDLE", "ATTACK", "PATCH", "BLOCK"]


def save_model(model):
    file = open("model.txt", "w")
    file.write("        ")
    for a in model.q_actions:
        file.write("{0} {1} {2} {3} ||".format(ACTIONS[a.action], "None" if a.target is None else a.target,
                                             "None" if a.subtarget is None else a.subtarget,
                                             "None" if a.vul is None else a.vul.id).rjust(20))
    file.write("States \n".rjust(30))
    for i in range(len(model.states)):
        for q in model.q_table[i]:
            file.write("{0}".format(q).rjust(20))

        file.write("        ||Comp Host: {0} ||Links: {1} || ".format(model.states[i].compromised_hosts, model.states[i].edges))
        for value in model.states[i].vulnerabilities.values():
            for v in value:
                file.write("VID:{0} ".format(v.id))
        file.write("\n")


def example_network1():
    ni = NetworkInfo(3, 2)

    G = nx.DiGraph()

    v0 = VulnerabilityInfo()
    v0.id = 0
    v0.prob_success = 1
    v0.cost = 0.9

    v1 = VulnerabilityInfo()
    v1.id = 1
    v1.prob_success = 1
    v1.cost = 0.5

    v2 = VulnerabilityInfo()
    v2.id = 2
    v2.prob_success = 1
    v2.cost = 0.6

    G.add_nodes_from([
        (0, {"comp": False, 'vuls': [v0], 'cvss': 0.1}),
        (1, {"comp": False, 'vuls': [v1], 'cvss': 0.55}),
        (2, {"comp": False, 'vuls': [v2], 'cvss': 0.85}),
    ])

    fromnodes = [0, 0, 1, 1, 1, 1, 1, 2, 2, 2, 2, 7, 7, 7, 7]
    tonodes = [1, 2, 2, 3, 4, 5, 6, 3, 4, 5, 6, 3, 4, 5, 6]

    for x, y in zip(fromnodes, tonodes):
        G.add_edge(x, y)
        G.add_edge(y, x)

    ni.network = G
    # ni.draw_network()

    actions = [Action(PATCH, target=1, vul=v1),
               Action(PATCH, target=2, vul=v2),
               Action(BLOCK, target=1, subtarget=0),
               Action(BLOCK, target=2, subtarget=0)]

    attack_path = [0, 2]

    model = ModelGenerator(ni, actions, attack_path)

    model.train_model(0.9, 0.1, 1, 1000)
    save_model(model)

    return model


def example_network2():
    ni = NetworkInfo(7, 2)

    G = nx.DiGraph()

    v1 = VulnerabilityInfo()
    v1.id = 1
    v1.prob_success = 1
    v1.cost = 8

    v2 = VulnerabilityInfo()
    v2.id = 2
    v2.prob_success = 1
    v2.cost = 5

    v3 = VulnerabilityInfo()
    v3.id = 3
    v3.prob_success = 1
    v3.cost = 6.5

    v4 = VulnerabilityInfo()
    v4.id = 4
    v4.prob_success = 1
    v4.cost = 3.5

    v5 = VulnerabilityInfo()
    v5.id = 5
    v5.prob_success = 1
    v5.cost = 4

    v6 = VulnerabilityInfo()
    v6.id = 6
    v6.prob_success = 1
    v6.cost = 5

    v7 = VulnerabilityInfo()
    v7.id = 7
    v7.prob_success = 1
    v7.cost = 6

    G.add_nodes_from([
        (0, {"comp": True, 'vuls': [], 'cvss': 0}),
        (1, {"comp": False, 'vuls': [v1], 'cvss': 4.3}),
        (2, {"comp": False, 'vuls': [v2], 'cvss': 2.1}),
        (3, {"comp": False, 'vuls': [v3], 'cvss': 10}),
        (4, {"comp": False, 'vuls': [v4], 'cvss': 4.3}),
        (5, {"comp": False, 'vuls': [v5], 'cvss': 7.2}),
        (6, {"comp": False, 'vuls': [v6], 'cvss': 8.8}),
        (7, {"comp": False, 'vuls': [v7], 'cvss': 8.8}),
    ])

    fromnodes = [0, 0, 1, 1, 1, 1, 1, 2, 2, 2, 2, 7, 7, 7, 7]
    tonodes   = [1, 2, 2, 3, 4, 5, 6, 3, 4, 5, 6, 3, 4, 5, 6]

    for x, y in zip(fromnodes, tonodes):
        G.add_edge(x, y)
        G.add_edge(y, x)

    ni.network = G
    ni.draw_network()

    actions = [Action(BLOCK, target=1, subtarget=0),
               Action(PATCH, target=7, vul=v7),
               Action(BLOCK, target=2, subtarget=0),
               Action(BLOCK, target=7, subtarget=3),
               Action(PATCH, target=4, vul=v4),
               Action(PATCH, target=6, vul=v6)]

    attack_path = [2, 4, 6, 7]

    model = ModelGenerator(ni, actions, attack_path)

    model.train_model(0.9, 0.1, 0.8, 5000)
    save_model(model)

    return model


def main():
    model = example_network2()
    print(model)


if __name__ == "__main__":
    main()
