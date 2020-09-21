import numpy as np
import mdptoolbox
import mdptoolbox.example
from numpy import loadtxt
from model import *


def main():
    m = ModelGenerator()
    m.import_data("input.txt")
    m.set_attacker_entry_point(0)
    m.generate_states()
    states = m.get_states()

    for state in states:
        print("Attacker Position {0} | Failed Host {1} | Vulnerabilities {2} | Score {3}".\
              format(state.attacker_position, state.compromised_hosts, state.vulnerabilities, m.get_state_score(state)))


if __name__ == "__main__":
    main()
