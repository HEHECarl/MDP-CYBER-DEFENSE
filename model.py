from copy import deepcopy
import collections


class MDPModel:
    """The markov decision process model

    Args:
        hosts_number (int): Number of hosts in the network
        adjacency_matrix (2d int list): A adjacency matrix describing the network
        vulnerabilities (2d string list): All the vulnerabilities each host has
        target (int): Target host
        attacker_entry_point (int): Where attack will enter the network,
            null means every host can be potentially attacked first
        states (State list): all the possible states, one of the MDP model parameters

    """
    def __init__(self):
        self.hosts_number = None
        self.adjacency_matrix = []
        self.vulnerabilities = []
        self.target = None
        self.attacker_entry_point = None
        self.states = []

    def get_states(self):
        return self.states

    def import_data(self, path):
        f = open(path, "r")
        while True:
            line = f.readline()
            if not line:
                break
            if "// Number of Hosts" in line:
                self.hosts_number = int(f.readline())
            elif "// Adjacency Matrix" in line:
                for i in range(self.hosts_number):
                    adj = []
                    row = f.readline()
                    for j in range(self.hosts_number):
                        adj.append(int(row[j]))
                    self.adjacency_matrix.append(adj)
            elif "// Vulnerabilities" in line:
                for i in range(self.hosts_number):
                    vul = []
                    row = f.readline().split()
                    count = int(row[0])
                    for j in range(count):
                        vul.append(row[j + 1])
                    self.vulnerabilities.append(vul)

    def set_target(self, target):
        self.target = target

    def set_attacker_entry_point(self, position):
        self.attacker_entry_point = position

    def generate_states(self):
        """ Function to generate a finite states for MDP model

            The function use Breath First Search algorithm to generate all the possible states
        """
        queue_states = []
        # Add Attacker Entry Point
        if self.attacker_entry_point is not None:
            queue_states.append(State(self.attacker_entry_point, self.target, self.vulnerabilities,
                                      [self.attacker_entry_point], None))
        else:
            for host in range(self.hosts_number):
                queue_states.append(State(host, self.target, self.vulnerabilities, [host], None))

        while queue_states:
            current_state = queue_states.pop(0)
            if current_state not in self.states:
                self.states.append(current_state)
                next_states = self.generate_next_states(deepcopy(current_state))
                if next_states:
                    queue_states.extend(next_states)

    def generate_next_states(self, current_state):
        """ Function to generate the next possible states based on current state

            The function now only support patch vulnerability and one attacker only
        """
        next_states = []
        attacker = current_state.get_attacker_position()
        vulnerabilities = current_state.get_vulnerabilities()
        fail_hosts = current_state.get_fail_hosts()

        for i in range(self.hosts_number):
            # Attacker move to next host
            # The host need to be not fail
            # The host need to have vulnerability
            if i not in fail_hosts and self.adjacency_matrix[attacker][i] == 1 and vulnerabilities[i]:
                next_states.append(State(i, self.target, vulnerabilities, fail_hosts + [i], current_state))

            # Patch Vulnerability
            # Is it necessary to patch a vulnerabilities to a host already failed?
            if i not in fail_hosts and vulnerabilities[i]:
                for v in vulnerabilities[i]:
                    new_vulnerabilities = deepcopy(vulnerabilities)
                    new_vulnerabilities[i].remove(v)
                    next_states.append(State(attacker, self.target, new_vulnerabilities, fail_hosts, current_state))

            # Block Port

            # Disable Service

        return next_states


class State:
    """A state model describing the current network

    Args:
        attacker_position (int): Where attacker at
        vulnerabilities (2d string list): All the vulnerabilities each host has
        target (int): Target host
        fail_hosts (int list): List of hosts which has already been attacked
        previous_state (State): Previous state to reach this state

    """
    def __init__(self, attacker, target, vulnerabilities, fail, previous_state):
        self.attacker_position = attacker
        self.target = target
        self.vulnerabilities = deepcopy(vulnerabilities)
        self.fail_hosts = deepcopy(fail)
        self.previous_state = previous_state

    def __eq__(self, other):
        if self.attacker_position == other.attacker_position \
                and self.target == other.target \
                and sorted(self.vulnerabilities) == sorted(other.vulnerabilities) \
                and set(self.fail_hosts) == set(other.fail_hosts):
            return True
        else:
            return False

    def get_attacker_position(self):
        return self.attacker_position

    def get_vulnerabilities(self):
        return self.vulnerabilities

    def get_fail_hosts(self):
        return self.fail_hosts

    def get_previous_state(self):
        return self.previous_state

    def get_score(self):
        raise NotImplementedError
