from copy import deepcopy
from network_info import *
import numpy as np
import collections

IDLE = 0
ATTACK = 1
PATCH = 2
BLOCK = 3


class ModelGenerator:
    def __init__(self, networkInfo, actions):
        self.networkInfo = networkInfo
        self.actions = deepcopy(actions)
        self.q_actions = deepcopy(actions)
        self.q_actions.insert(0, Action(IDLE))
        self.state_id = 0
        self.states = []
        self.queue_states = []
        self.trans = []
        self.q_table = []

        self.initialize_states()
        self.initialize_q_table()

    def initialize_states(self):
        initial_state = State(self.get_initial_vuls(), self.get_initial_comps(), self.networkInfo.network.edges)
        initial_state.id = self.state_id
        self.state_id += 1

        self.queue_states = [initial_state]
        self.trans = np.array([[None]])

        while self.queue_states:
            current_state = self.queue_states.pop(0)
            self.states.append(current_state)
            self.generate_next_states(current_state)

    def generate_next_states(self, current_state):
        """ Function to generate the next possible states based on current state

            The function now only support patch vulnerability and one attacker only
        """
        vulnerabilities = current_state.get_vulnerabilities()
        compromised_hosts = current_state.get_compromised_hosts()
        edges = current_state.get_edges()

        if not compromised_hosts:
            for host in self.networkInfo.get_hosts():
                if vulnerabilities[host]:
                    s = State(vulnerabilities, compromised_hosts + [host], edges)
                    a = Action(ATTACK, host)
                    self.add_new_state(s, current_state, a, 1, -self.networkInfo.get_cvss(host), 0)

        else:
            for host in compromised_hosts:
                # Attacker move to next host
                # The host need to be not compromised
                # The host need to have vulnerability
                for adj in self.get_adjs(host, edges):
                    if adj not in compromised_hosts and vulnerabilities[adj]:
                        s = State(vulnerabilities, compromised_hosts + [adj], edges)
                        a = Action(ATTACK, host)
                        self.add_new_state(s, current_state, a, 1, -self.networkInfo.get_cvss(host), 0)

        # Patch Vulnerability
        # Is it necessary to patch a vulnerabilities to a host already compromised?
        for action in self.actions:
            if action.action == PATCH:
                if action.target not in compromised_hosts and action.vul in vulnerabilities[action.target]:
                    new_vulnerabilities = deepcopy(vulnerabilities)
                    new_vulnerabilities[action.target].remove(action.vul)
                    s = State(new_vulnerabilities, compromised_hosts, edges)
                    self.add_new_state(s, current_state, action, action.vul.prob_success, -action.vul.cost, -action.vul.cost)
            elif action.action == BLOCK:
                if (action.subtarget, action.target) in edges and action.target not in compromised_hosts:
                    new_edges = deepcopy(edges)
                    new_edges.remove((action.subtarget, action.target))
                    s = State(vulnerabilities, compromised_hosts, new_edges)
                    self.add_new_state(s, current_state, action, 1, 0.5, 0)

    def initialize_q_table(self):
        self.q_table = [[0 for x in range(len(self.actions))] for y in range(len(self.states))]

    def train_model(self, gamma, lrn_rate, epsilon, max_epochs):
        for i in range(max_epochs):
            # curr_s = np.random.randint(0, len(self.states))
            curr_s = 0
            while True:
                if random.uniform(0, 1) < epsilon:  # Explore: select a random action
                    a = self.get_random_next_action(curr_s)
                else:   # Exploit: select the action with max value (future reward)
                    a = self.get_max_next_action(curr_s)

                if a == 0:
                    n_s = self.get_random_attack_state(curr_s)
                    if n_s is None:
                        break
                else:
                    n_s = self.get_state_from_action(curr_s, self.actions[a])

                if random.uniform(0, 1) < self.trans[curr_s][n_s].rate:
                    reward = self.trans[curr_s][n_s].reward_success
                else:
                    reward = self.trans[curr_s][n_s].reward_fail
                    n_s = curr_s

                n_a = self.get_max_next_action(n_s)
                nn_q = self.q_table[n_s][n_a]

                self.q_table[curr_s][a] = ((1 - lrn_rate) * self.q_table[curr_s][a]) + \
                                          (lrn_rate * (reward + (gamma * nn_q)))

                curr_s = n_s

    def get_next_actions(self, state_index):
        actions = [0]
        for j in range(len(self.trans[state_index])):
            if self.trans[state_index][j] is not None:
                for a in self.actions:
                    if self.trans[state_index][j].action == a:
                        actions.append(self.actions.index(a))

        return actions

    def get_random_next_action(self, state_index):
        actions = self.get_next_actions(state_index)
        if actions:
            return actions[np.random.randint(0, len(actions))]
        else:
            return None

    def get_max_next_action(self, state_index):
        actions = self.get_next_actions(state_index)
        if actions:
            max_q = -9999.99
            action = None
            for a in actions:
                q = self.q_table[state_index][a]
                if q > max_q:
                    max_q = q
                    action = a
            return action
        else:
            return None

    def get_state_from_action(self, curr_s, action):
        for j in range(len(self.trans[curr_s])):
            if self.trans[curr_s][j] is not None:
                if self.trans[curr_s][j].action == action:
                    return j

    def get_random_attack_state(self, curr_s):
        l = []
        for j in range(len(self.trans[curr_s])):
            if self.trans[curr_s][j] is not None:
                if self.trans[curr_s][j].action.action == 1:
                    l.append(j)
        if len(l) == 0:
            return None
        else:
            return l[np.random.randint(0, len(l))]

    def add_new_state(self, s, current_state, action, rate, reward_success, reward_fail):
        if s not in self.states and s not in self.queue_states:
            s.id = self.state_id
            self.state_id += 1
            self.queue_states.append(s)

            self.trans = np.pad(self.trans, ((0, 1), (0, 1)), mode='constant', constant_values=None)
            self.trans[current_state.id][s.id] = Transition(action, rate, reward_success, reward_fail)
        else:
            self.trans[current_state.id][self.get_state_id(s)] = Transition(action, rate, reward_success, reward_fail)

    def get_state_id(self, s):
        for state in self.states:
            if state == s:
                return state.id
        for state in self.queue_states:
            if state == s:
                return state.id

    def get_adjs(self, host, edges):
        adjs = []
        for edge in edges:
            if edge[0] == host:
                adjs.append(edge[1])
        return adjs

    def get_initial_vuls(self):
        vul_list = {}
        for host in self.networkInfo.get_hosts():
            l = []
            for vul in self.networkInfo.get_vuls(host):
                l.append(vul)
            vul_list[host] = l
        return vul_list

    def get_initial_comps(self):
        for host in self.networkInfo.get_hosts():
            com_list = []
            if self.networkInfo.is_comp(host):
                com_list.append(host)
            return com_list


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

