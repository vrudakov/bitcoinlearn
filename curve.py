import numpy as np
import matplotlib
import matplotlib.pyplot as plt

def main():
    a = len("vitaly")
    b = len("rudakov")
    y, x = np.ogrid[-5:5:100j, -5:5:100j]
    plt.contour(x.ravel(), y.ravel(), pow(y, 2) - pow(x, 3) - x * a - b, [0])
    plt.grid()
    plt.savefig('graph.png')

if __name__ == '__main__':
    main()