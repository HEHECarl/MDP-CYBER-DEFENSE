import numpy as np
import mdptoolbox
import mdptoolbox.example
from numpy import loadtxt
from model import *
import operator
from network_info import *


def main():
    ni = NetworkInfo(3, 2)
    ni.generate_random_network()
    ni.draw_network()
    model = ModelGenerator(ni)
    model.initialize_states()
    model.initialize_transition_table()
    print(model.trans)


if __name__ == "__main__":
    main()
