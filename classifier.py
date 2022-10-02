#
#   Projekt name:   Identification of Mobile Traffic using TLS Fingerprinting
#   Author:         Martin krajči
#   Date:           25.4.2021
#

import sqlite3
import os
import csv
import seaborn as sn
import matplotlib.pyplot as plt
from numpy import average
import sklearn.metrics

def classify():
    db = sqlite3.connect("fingerprints.db")
    cur = db.cursor()


    file_names = set(map(lambda x: os.path.splitext(x)[0], os.listdir("ja3+ja3s_rd")))
    file_names_t = set(map(lambda x: os.path.splitext(x)[0][:-5], os.listdir("ja3_classif")))

    y_true = []
    y_pred = []
    found_match = False

    # Fingerprints comparison.
    for file_name_t in file_names_t:
        fingerprints = open("ja3_classif/" + file_name_t + "_test.csv")
        fingerprints_rows = csv.reader(fingerprints, delimiter=';', quotechar='"', quoting=csv.QUOTE_MINIMAL)

        for row in fingerprints_rows:
            for file_name in file_names:
                cur.execute("SELECT * FROM " + file_name + " WHERE ja3=? AND sni=? AND ja3s=?;", row)
                #cur.execute("SELECT * FROM " + file_name + " WHERE ja3=? AND ja3s=?;", [row[0], row[2]])
                #cur.execute("SELECT * FROM " + file_name + " WHERE ja3=? AND sni=?;", row[:-1])
                #cur.execute("SELECT * FROM " + file_name + " WHERE sni=?;", [row[1]])
                if len(cur.fetchall()) != 0:
                    y_true.append(file_name_t)
                    y_pred.append(file_name)
                    found_match = True
            if not found_match:
                y_true.append(file_name_t)
                y_pred.append("others")
            found_match = False

    # Printing accuracy, recall and precision.
    print("Accuracy: ", sklearn.metrics.accuracy_score(y_true, y_pred))
    print("Recall: ", sklearn.metrics.recall_score(y_true, y_pred, average=None, zero_division=True).mean())
    print("Precision: ", sklearn.metrics.precision_score(y_true, y_pred, average=None).mean())

    # Confusion matrix creation.
    matrix = sklearn.metrics.confusion_matrix(y_true, y_pred, labels=["aliexpress", "discord", "gmail",
    "messenger", "msteams", "paypal", "snapchat", "spotify", "steam", "yeelight", "others"])

    # Printing of confusion matrix.
    sn.set(font_scale=0.9)
    sn.heatmap(matrix, linewidths=1, annot=True, annot_kws={"size": 10}, xticklabels=["aliexpress", "discord", "gmail",
    "messenger", "msteams", "paypal", "snapchat", "spotify", "steam", "yeelight", "others"], 
    yticklabels=["aliexpress", "discord", "gmail", "messenger", "msteams", "paypal", "snapchat",
    "spotify", "steam", "yeelight", "others"])
    plt.show()