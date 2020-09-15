import numpy as np
import mdptoolbox
import mdptoolbox.example
from numpy import loadtxt
from model import *


def main():
    m = MDPModel()
    m.import_data("input.txt")
    m.set_attacker_entry_point(0)
    m.generate_states()
    states = m.get_states()

    for state in states:
        print("Attacker Position {0} | Failed Host {1} | Vulnerabilities {2}".\
              format(state.attacker_position, state.fail_hosts, state.vulnerabilities))


if __name__ == "__main__":
    main()
