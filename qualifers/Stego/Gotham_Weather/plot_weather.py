from datetime import datetime
import numpy as np
import matplotlib.pyplot as plt
import os

os.chdir("./Stego/Gotham_Weather")

def read_obs(path):
    '''Read temperatures in observation files.
    '''

    data = np.load(path).T
    return data

if __name__ == '__main__':
    for station in ['Blackgate']    :
        data = read_obs(f'{station}.npy')
        plt.plot([datetime.utcfromtimestamp(d) for d in data[0]], data[1], label = station)
    plt.xlabel('Date')
    plt.ylabel('Temperature (C)')
    plt.legend(title='Location')
    plt.show()
