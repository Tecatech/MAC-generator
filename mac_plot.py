#!/usr/bin/env python3
import matplotlib.pyplot as plt
import pandas as pd

def mac_plot(mode):
    plt.rcParams['figure.figsize'] = [7.50, 3.50]
    plt.rcParams['figure.autolayout'] = True
    
    headers = ['mac_len', mode + '_time']
    
    df = pd.read_csv(mode + '_plot.csv', sep = ' ', names = headers)
    df.set_index('mac_len').plot()
    
    plt.savefig('images/' + mode + '_plot.png')

if __name__ == '__main__':
    mac_plot('omac')
    mac_plot('hmac')