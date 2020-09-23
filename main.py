import numpy as np
import mdptoolbox
import mdptoolbox.example
from numpy import loadtxt
from model import *
import operator


def main():
    m = ModelGenerator()
    m.import_data("input.txt")
    m.set_attacker_entry_point(0)
    m.set_target(4)
    m.generate_states()
    states = m.get_states()
    states = sorted(states, key=operator.attrgetter('attacker_position'))
    states = sorted(states, key=operator.attrgetter('compromised_hosts'))

    for state in states:
        print("Attacker Position {0} | Failed Host {1} | Vulnerabilities {2} | Score {3}".\
              format(state.attacker_position, state.compromised_hosts, state.vulnerabilities, m.get_state_score(state)))


if __name__ == "__main__":
    main()
