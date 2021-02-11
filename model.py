from copy import deepcopy
from network_info import *
import collections

ATTACK = 0
PATCH = 1


class ModelGenerator:
    def __init__(self, networkInfo):
        self.networkInfo = networkInfo
        self.states = []
        self.actions = []
        self.trans = []
        self.vuls = {}

    def initialize_vuls(self):
        for host in self.networkInfo.get_hosts():
            vul_list = []
            for vul in self.networkInfo.get_vuls(host):
                vul_list.append(vul)
            self.vuls[host] = vul_list

    def initialize_states(self):
        state_id = 0
        self.initialize_vuls()
        queue_states = [State(deepcopy(self.vuls), [])]
        while queue_states:
            current_state = queue_states.pop(0)
            if current_state not in self.states:
                state_id += 1
                current_state.id = state_id
                self.states.append(current_state)
                next_states = self.generate_next_states(deepcopy(current_state))
                if next_states:
                    queue_states.extend(next_states)

    def generate_next_states(self, current_state):
        """ Function to generate the next possible states based on current state

            The function now only support patch vulnerability and one attacker only
        """
        next_states = []
        vulnerabilities = current_state.get_vulnerabilities()
        compromised_hosts = current_state.get_compromised_hosts()

        if not compromised_hosts:
            for host in self.networkInfo.get_hosts():
                if vulnerabilities[host]:
                    s = State(vulnerabilities, compromised_hosts + [host])
                    next_states.append(s)
        else:

            for host in self.networkInfo.get_hosts():
                # Attacker move to next host
                # The host need to be not compromised
                # The host need to have vulnerability
                if host not in compromised_hosts and vulnerabilities[host] != []:
                    for adj in self.networkInfo.network.adj[host]:
                        if adj in compromised_hosts:
                            s = State(vulnerabilities, compromised_hosts + [host])
                            next_states.append(s)

        # Patch Vulnerability
        # Is it necessary to patch a vulnerabilities to a host already compromised?
        for host in self.networkInfo.get_hosts():
            if host not in compromised_hosts and vulnerabilities[host] != []:
                for vul in vulnerabilities[host]:
                    new_vulnerabilities = deepcopy(vulnerabilities)
                    new_vulnerabilities[host].remove(vul)
                    s = State(new_vulnerabilities, compromised_hosts)
                    next_states.append(s)

            # Block Port

            # Disable Service

        return next_states

    def initialize_transition_table(self):
        state_size = len(self.states)
        self.trans = [[0 for x in range(state_size)] for y in range(state_size)]
        for state in self.states:
            vulnerabilities = state.get_vulnerabilities()
            compromised_hosts = state.get_compromised_hosts()
            if not compromised_hosts:
                for host in self.networkInfo.get_hosts():
                    if vulnerabilities[host]:
                        a = Action(ATTACK, host)
                        s = State(vulnerabilities, compromised_hosts + [host])
                        if a not in self.actions:
                            self.actions.append(a)
                        self.trans[self.states.index(state)][self.states.index(s)] = 1

            else:

                for host in self.networkInfo.get_hosts():
                    # Attacker move to next host
                    # The host need to be not compromised
                    # The host need to have vulnerability
                    if host not in compromised_hosts and vulnerabilities[host] != []:
                        for adj in self.networkInfo.network.adj[host]:
                            if adj in compromised_hosts:
                                a = Action(ATTACK, host)
                                s = State(vulnerabilities, compromised_hosts + [host])
                                if a not in self.actions:
                                    self.actions.append(a)
                                self.trans[self.states.index(state)][self.states.index(s)] = 1

            # Patch Vulnerability
            # Is it necessary to patch a vulnerabilities to a host already compromised?
            for host in self.networkInfo.get_hosts():
                if host not in compromised_hosts and vulnerabilities[host] != []:
                    for vul in vulnerabilities[host]:
                        new_vulnerabilities = deepcopy(vulnerabilities)
                        new_vulnerabilities[host].remove(vul)
                        a = Action(PATCH, host, vul)
                        s = State(new_vulnerabilities, compromised_hosts)
                        if a not in self.actions:
                            self.actions.append(a)
                        self.trans[self.states.index(state)][self.states.index(s)] = 1

    # def initialize_q_table(self):






# class ModelGenerator:
#     """ModelGenerator to generator input for markov decision process model
#
#     Args:
#         hosts_number (int): Number of hosts in the network
#         adjacency_matrix (2d int list): A adjacency matrix describing the network
#         vulnerabilities (list of dictionary): All the vulnerabilities each host has with difficulties
#         target (int): Target host
#         attacker_entry_point (int): Where attack will enter the network,
#             null means every host can be potentially attacked first
#         states (State list): all the possible states, one of the MDP model parameters
#
#     """
#     def __init__(self):
#         self.hosts_number = None
#         self.target = None
#         self.attacker_entry_point = None
#         self.defense_probability = None
#
#         self.total_vulnerabilities_count = 0
#
#         self.adjacency_matrix = []
#         self.vulnerabilities = []
#         self.rewards_weights = []
#         self.states = []
#
#     def get_states(self):
#         return self.states
#
#     def import_data(self, path):
#         f = open(path, "r")
#         while True:
#             line = f.readline()
#             if not line:
#                 break
#             if "// Number of Hosts" in line:
#                 self.hosts_number = int(f.readline())
#             elif "// Adjacency Matrix" in line:
#                 for i in range(self.hosts_number):
#                     adj = []
#                     row = f.readline()
#                     for j in range(self.hosts_number):
#                         adj.append(int(row[j]))
#                     self.adjacency_matrix.append(adj)
#             elif "// Vulnerabilities" in line:
#                 for i in range(self.hosts_number):
#                     vul = {}
#                     row = f.readline().split()
#                     count = int(row[0])
#                     self.total_vulnerabilities_count += count
#                     for j in range(count):
#                         vul[row[j * 2 + 1]] = float(row[j * 2 + 2])
#                     self.vulnerabilities.append(vul)
#             elif "// Attack Defend Ratio" in line:
#                 self.defense_probability = float(f.readline())
#             elif "// Rewards Weight V C T" in line:
#                 row = f.readline().split()
#                 self.rewards_weights.append(float(row[0]))
#                 self.rewards_weights.append(float(row[1]))
#                 self.rewards_weights.append(float(row[2]))
#                 self.rewards_weights.append(float(row[3]))
#
#     def set_target(self, target):
#         self.target = target
#
#     def set_attacker_entry_point(self, position):
#         self.attacker_entry_point = position
#
#     def generate_states(self):
#         """ Function to generate a finite states for MDP model
#
#             The function use Breath First Search algorithm to generate all the possible states
#         """
#         queue_states = []
#         # Add Attacker Entry Point
#         if self.attacker_entry_point is not None:
#             queue_states.append(State(self.attacker_entry_point, self.target, self.vulnerabilities,
#                                       [self.attacker_entry_point]))
#         else:
#             for host in range(self.hosts_number):
#                 queue_states.append(State(host, self.target, self.vulnerabilities, [host]))
#
#         while queue_states:
#             current_state = queue_states.pop(0)
#             if current_state not in self.states:
#                 self.states.append(current_state)
#                 if not current_state.is_target_compromised():
#                     next_states = self.generate_next_states(deepcopy(current_state))
#                     if next_states:
#                         queue_states.extend(next_states)
#
#     def generate_next_states(self, current_state):
#         """ Function to generate the next possible states based on current state
#
#             The function now only support patch vulnerability and one attacker only
#         """
#         next_states = []
#         attacker = current_state.get_attacker_position()
#         vulnerabilities = current_state.get_vulnerabilities()
#         compromised_hosts = current_state.get_compromised_hosts()
#
#         for i in range(self.hosts_number):
#             # Attacker move to next host
#             # The host need to be not compromised
#             # The host need to have vulnerability
#             if i not in compromised_hosts and self.adjacency_matrix[attacker][i] == 1 and vulnerabilities[i]:
#                 next_states.append(State(i, self.target, vulnerabilities, compromised_hosts + [i]))
#
#             # Patch Vulnerability
#             # Is it necessary to patch a vulnerabilities to a host already compromised?
#             if i not in compromised_hosts and vulnerabilities[i]:
#                 for v in vulnerabilities[i]:
#                     new_vulnerabilities = deepcopy(vulnerabilities)
#                     new_vulnerabilities[i].pop(v)
#                     next_states.append(State(attacker, self.target, new_vulnerabilities, compromised_hosts))
#
#             # Block Port
#
#             # Disable Service
#
#         return next_states
#
#     def get_state_score(self, state):
#         v = self.rewards_weights[0]*(self.total_vulnerabilities_count - state.get_vulnerabilities_count()) / float(
#             self.total_vulnerabilities_count)
#         c = self.rewards_weights[1]*(self.hosts_number - len(state.get_compromised_hosts())) / float(
#             self.hosts_number)
#         a = 0
#         if state.is_target_compromised():
#             t = self.rewards_weights[2]
#         else:
#             t = 0
#             if state.is_network_safe(self.adjacency_matrix, self.hosts_number):
#                 a = self.rewards_weights[3]
#
#         return round(v + c - t + a, 5)
#
#
class State:
    """A state model describing the current network

    Args:
        vulnerabilities (2d string list): All the vulnerabilities each host has
        compromised (int list): List of hosts which has already been attacked
    """
    def __init__(self, vulnerabilities, compromised):
        self.vulnerabilities = deepcopy(vulnerabilities)
        self.compromised_hosts = sorted(deepcopy(compromised))
        self.id = None

    def __eq__(self, other):
        if self.vulnerabilities == other.vulnerabilities \
                and set(self.compromised_hosts) == set(other.compromised_hosts):
            return True
        else:
            return False

    def get_vulnerabilities(self):
        return self.vulnerabilities

    def get_compromised_hosts(self):
        return self.compromised_hosts

    def get_id(self):
        return self.id


class Action:
    def __init__(self, action, target, vul=None):
        self.action = action
        self.target = target
        self.vul = vul

    def __eq__(self, other):
        if self.action == other.action and self.target == other.target and self.vul == other.vul:
            return True
        else:
            return False

    def get_action(self):
        return self.action

    def get_target(self):
        return self.target

    def get_vul(self):
        return  self.vul

