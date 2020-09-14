class MDPModel:
    def __init__(self):
        self.hosts_number = None
        self.adjacency_matrix = None
        self.vulnerabilities = None
        self.target = None
        self.attacker_entry_point = None
        self.states = None

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
        if self.attacker_entry_point is not None:
            self.states.append(State(self.attacker_entry_point, self.target, self.vulnerabilities,
                                     [self.attacker_entry_point]))
        else:
            for host in range(self.hosts_number):
                self.states.append(State(host, self.target, self.vulnerabilities, [host]))


class State:
    def __init__(self, attacker, target, vulnerabilities, fail):
        self.attacker_position = attacker
        self.target = target
        self.vulnerabilities = vulnerabilities
        self.fail_hosts = fail

    def get_attacker_position(self):
        return self.attacker_position

    def get_vulnerabilities(self):
        return self.vulnerabilities

    def get_fail_hosts(self):
        return self.fail_hosts

    def get_score(self):
        raise NotImplementedError