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
        self.rewards_success = []
        self.rewards_fail = []
        self.vuls = {}
        self.q_table = []

        self.initialize_states()
        self.initialize_transition_table()
        self.initialize_q_table()

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
        self.rewards = [[0 for x in range(state_size)] for y in range(state_size)]
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
                        self.trans[self.states.index(state)][self.states.index(s)] = 1 - self.networkInfo.get_cvss(host)
                        self.rewards_success[self.states.index(state)][self.states.index(s)] = -self.networkInfo.get_cvss(host)
                        self.rewards_fail[self.states.index(state)][self.states.index(s)] = 0
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
                                self.trans[self.states.index(state)][self.states.index(s)] = 1 - self.networkInfo.get_cvss(host)
                                self.rewards_success[self.states.index(state)][self.states.index(s)] = -self.networkInfo.get_cvss(host)
                                self.rewards_fail[self.states.index(state)][self.states.index(s)] = 0

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
                        self.trans[self.states.index(state)][self.states.index(s)] = vul.prob_success
                        self.rewards_success[self.states.index(state)][
                            self.states.index(s)] = -vul.cost
                        self.rewards_fail[self.states.index(state)][
                            self.states.index(s)] = -vul.cost

    def initialize_q_table(self):
        self.q_table = [[0 for x in range(len(self.states))] for y in range(len(self.states))]

    def get_next_states(self, state_index):
        return_list = []
        for i in range(len(self.trans[state_index])):
            if self.trans[state_index][i] != 0:
                return_list.append(i)
        return return_list

    def get_random_next_state(self, state_index):
        return_list = self.get_next_states(state_index)
        if return_list:
            return return_list[np.random.randint(0, len(return_list))]
        else:
            return None

    def get_max_next_state(self, state_index):
        return_list = self.get_next_states(state_index)
        if return_list:
            max_q = -9999.99
            return_state = None
            for j in range(len(return_list)):
                n_s = return_list[j]
                q = self.q_table[state_index][n_s]
                if q > max_q:
                    max_q = q
                    return_state = n_s
            return return_state
        else:
            return None

    def get_reward(self, current_s, next_s, success):
        if success:
            return self.rewards_success[current_s][next_s]
        else:
            return self.rewards_fail[current_s][next_s]

    def train_model(self, gamma, lrn_rate, epsilon, max_epochs):
        for i in range(max_epochs):
            curr_s = np.random.randint(0, len(self.states))

            while True:
                if random.uniform(0, 1) < epsilon:  # Explore: select a random action
                    n_s = self.get_random_next_state(curr_s)
                else:   # Exploit: select the action with max value (future reward)
                    n_s = self.get_max_next_state(curr_s)

                if not n_s:
                    break

                if random.uniform(0, 1) < self.trans[curr_s][n_s]:
                    reward = self.get_reward(curr_s, n_s, 1)
                else:
                    reward = self.get_reward(curr_s, n_s, 0)
                    n_s = curr_s

                nn_s = self.get_max_next_state(n_s)

                if nn_s:
                    nn_q = self.q_table[n_s][self.get_max_next_state(n_s)]
                else:
                    nn_q = 0

                self.q_table[curr_s][n_s] = ((1 - lrn_rate) * self.q_table[curr_s][n_s]) + \
                                            (lrn_rate * (reward + (gamma * nn_q)))

                curr_s = n_s

                if not self.get_next_states(curr_s):
                    break


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
        return self.vul

