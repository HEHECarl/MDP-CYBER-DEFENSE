from copy import deepcopy

class State:
    """A state model describing the current network

    Args:
        vulnerabilities (2d string list): All the vulnerabilities each host has
        compromised (int list): List of hosts which has already been attacked
    """
    def __init__(self, vulnerabilities, compromised, edges):
        self.vulnerabilities = deepcopy(vulnerabilities)
        self.compromised_hosts = sorted(deepcopy(compromised))
        self.edges = sorted(deepcopy(edges))
        self.id = None

    def __eq__(self, other):
        if self.vulnerabilities == other.vulnerabilities \
                and set(self.compromised_hosts) == set(other.compromised_hosts)\
                and set(self.edges) == set(other.edges):
            return True
        else:
            return False

    def get_vulnerabilities(self):
        return self.vulnerabilities

    def get_compromised_hosts(self):
        return self.compromised_hosts

    def get_edges(self):
        return self.edges

    def get_id(self):
        return self.id


class Action:
    def __init__(self, action, target=None, subtarget=None, vul=None):
        self.action = action
        self.target = target
        self.subtarget = subtarget
        self.vul = vul

    def __eq__(self, other):
        if self.action == other.action and self.target == other.target \
                and self.subtarget == other.subtarget and self.vul == other.vul:
            return True
        else:
            return False

    def get_action(self):
        return self.action

    def get_target(self):
        return self.target

    def get_vul(self):
        return self.vul


class Transition:
    def __init__(self, action, rate, reward_success, reward_fail):
        self.action = action
        self.rate = rate
        self.reward_success = reward_success
        self.reward_fail = reward_fail