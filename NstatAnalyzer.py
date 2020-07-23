#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Auther: 2020, Mayed Alm
# NstatAnalyzer: netstat analyzing tool to work with analyzing NstatLogger csv files.
# version: 1.0

import sys
import pandas as pd
import networkx as nx
import matplotlib.pyplot as plt



banner = '''
    _   __     __        __  ___                __                     
   / | / /____/ /_____ _/ /_/   |  ____  ____ _/ /_  ______  ___  _____
  /  |/ / ___/ __/ __ `/ __/ /| | / __ \/ __ `/ / / / /_  / / _ \/ ___/
 / /|  (__  ) /_/ /_/ / /_/ ___ |/ / / / /_/ / / /_/ / / /_/  __/ /    
/_/ |_/____/\__/\__,_/\__/_/  |_/_/ /_/\__,_/_/\__, / /___/\___/_/     
                                              /____/ v1.0         ©Mayed.alm                  

'''



def argparse():
    #taking file as input
    print(banner)
    if len(sys.argv) < 2:
        sys.exit('[!] NstatAnalyzer: netstat analyzing tool to work with analyzing NstatLogger csv files.\n[+] Usage: NstatAnalyzer <file.csv>')
    elif sys.argv == '-h':
        sys.exit('[!] NstatAnalyzer: netstat analyzing tool to work with analyzing NstatLogger csv files.\n[+] Usage: NstatAnalyzer <file.csv>')
    elif len(sys.argv) > 2:
        sys.exit('[!] NstatAnalyzer: netstat analyzing tool to work with analyzing NstatLogger csv files.\n[+] Usage: NstatAnalyzer <file.csv>')
    else:
        analyzer(sys.argv[1])

def analyzer(file):
    G = nx.Graph(day="NstatAnalyzer")
    try:
        df_nodes = pd.read_csv(file)
    except FileNotFoundError:
        sys.exit('[!] Error reading file, file does not exist!')
    for index, row in df_nodes.iterrows():
        try: #adding two nodes (Remote address and Process name) to the graph
            G.add_node(row['RemoteAddress'], group=row['ProgramName'])
        except KeyError:
            sys.exit('[!] Error reading file, make sure it is an NstatLogger csv file!')
    for index, row in df_nodes.iterrows(): #analyticly connecting the created nodes
        G.add_edge(row['ProgramName'], row['RemoteAddress'])
    plt.figure(figsize=(40,40))
    #Graph settings
    options = {
        'width': 2,
        'with_labels': True,
        'font_weight': 'bold',
        'font_size': 7,
        'edge_color':'red',
        'node_color':'skyblue',
        'node_shape':'o',
        'node_size':3500}
    nx.draw(G, pos=nx.spring_layout(G, k=0.30, iterations=60), **options)
    nx.all_pairs_shortest_path_length(G)
    ax = plt.gca()
    ax.collections[0].set_edgecolor("#555555") 
    plt.show()
    
if __name__ == '__main__':
    argparse()