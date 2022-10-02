import imp
import sys
from pcap2ja3 import *
from classifier import classify

if __name__ == "__main__":
    train_data = False
    classif_data = False
    classifier = False
    for i in range(1, len(sys.argv)):
        if sys.argv[i] == "-t" or sys.argv[i] == "-a":
            train_data = True
        if sys.argv[i] == "-c" or sys.argv[i] == "-a":
            classif_data = True
        if sys.argv[i] == "-x" or sys.argv[i] == "-a":
            classifier = True

    if train_data:
        ja3_and_ja3s("train")
        concat_ja3_and_ja3s()
        remove_duplicates_from_csv()
        create_fingerprints_db()
    if classif_data:
        ja3_and_ja3s("classif")
    if classifier:
        classify()