import numpy as np
import mdptoolbox
import mdptoolbox.example
from numpy import loadtxt
from model import *


def main():
    m = MDPModel()
    m.import_data("input.txt")
    m.generate_states()


if __name__ == "__main__":
    main()
