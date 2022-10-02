#
#   Projekt name:   Identification of Mobile Traffic using TLS Fingerprinting
#   Author:         Martin krajči
#   Date:           25.4.2021
#

import os
from pandas.core.reshape.merge import merge
import pyshark
import hashlib
import csv
import pandas as pd
import sqlite3
import nest_asyncio
nest_asyncio.apply()

Ext_group_grease = ["2570", "6682", "10794", "14906", "19018", "23130", "27242", "31354",
                 "35466", "39578", "43690", "47802", "51914", "56026", "60138", "64250"]

Suites_grease = ["10", "26", "42", "58", "74", "90", "106", "122", "138", "154", 
                    "170", "186", "202", "218", "234", "250"]

# Calculation of JA3 and JA3S fingerprints.
def ja3_and_ja3s(model):

    pcap_files = os.listdir("pcaps_" + model)

    for pcap in pcap_files:
        cap = pyshark.FileCapture("pcaps_" + model + "/" + pcap, display_filter="tls and (tls.handshake.type == 1 or tls.handshake.type == 2)")

        ja3_output = open("ja3_" + model + "/" + os.path.splitext(pcap)[0] + ".csv", mode='w')
        ja3_writer = csv.writer(ja3_output, delimiter=';', quotechar='"', quoting=csv.QUOTE_MINIMAL)

        ja3_dict = {}
        for packet in cap:
            if "tls" in packet:
                if packet.tls.handshake_type == "1":
                    ja3(packet, ja3_dict)
                else:
                    ja3s(packet, ja3_dict)
                
        for key in ja3_dict:
            if len(ja3_dict[key]) == 3:
                ja3_writer.writerow(ja3_dict[key])

# Calculation of JA3 fingerprints.
def ja3(packet, ja3_dict):

    ja3 = str(packet.tls.handshake_version.int_value) + ','

    suites = []
    not_read_next = False
    for suit_index in range(len(packet.tls.handshake_ciphersuites.fields)-1):
        if not_read_next:
            not_read_next = False
            continue
        if packet.tls.handshake_ciphersuites.fields[suit_index].show in Suites_grease:
            if packet.tls.handshake_ciphersuites.fields[suit_index + 1].show == \
            packet.tls.handshake_ciphersuites.fields[suit_index].show:
                not_read_next = True
                continue
            else:
                suites.append(packet.tls.handshake_ciphersuites.fields[suit_index].show)
        else:
            suites.append(packet.tls.handshake_ciphersuites.fields[suit_index].show)
    if not not_read_next:
        suites.append(packet.tls.handshake_ciphersuites.fields[-1].show)

    ja3 += '-'.join(suites) + ','

    extensions = []
    for ext in packet.tls.handshake_extension_type.fields:
        if ext.show not in Ext_group_grease:
            extensions.append(ext.show)
    ja3 += '-'.join(extensions) + ','

    groups = []
    for group in packet.tls.handshake_extensions_supported_group.fields:
        if str(int(group.show, 16)) not in Ext_group_grease:
            groups.append(str(int(group.show, 16)))
    ja3 += '-'.join(groups) + ','

    if hasattr(packet.tls, "handshake_extensions_ec_point_format"):
        ja3 += packet.tls.handshake_extensions_ec_point_format.show
    else:
        ja3 += '/'

    if hasattr(packet.tls, "handshake_extensions_server_name"):
        SNI = packet.tls.handshake_extensions_server_name.show
    else:
        SNI = ""

    dst_ip_and_port = str(packet.ip.dst) + ":" + str(packet.tcp.dstport)

    ja3_hash = hashlib.md5(ja3.encode()).hexdigest()

    ja3_dict[dst_ip_and_port] = [ja3_hash, SNI]

# Calculation of JA3S fingerprints.
def ja3s(packet, ja3_dict):

    ja3s = str(packet.tls.handshake_version.int_value) + ','

    ja3s += packet.tls.handshake_ciphersuite + ','

    extensions = []
    for ext in packet.tls.handshake_extension_type.fields:
        if ext.show not in Ext_group_grease:
            extensions.append(ext.show)
    ja3s += '-'.join(extensions) + ','

    src_ip_and_port = str(packet.ip.src) + ":" + str(packet.tcp.srcport)

    ja3s_hash = hashlib.md5(ja3s.encode()).hexdigest()

    if src_ip_and_port in ja3_dict:
        if len(ja3_dict[src_ip_and_port]) < 3:
            ja3_dict[src_ip_and_port].append(ja3s_hash)

# Concatination of csv files from phase 1 and phase 2.
def concat_ja3_and_ja3s():

    file_names = set(map(lambda x: os.path.splitext(x)[0][:-1], os.listdir("ja3_train")))

    for file_name in file_names:

        ja3_csv1 = pd.read_csv("ja3_train/" + os.path.splitext(file_name)[0] + "1.csv", delimiter=';')
        ja3_csv2 = pd.read_csv("ja3_train/" + os.path.splitext(file_name)[0] + "2.csv", delimiter=';')

        ja3_csv1.columns = ["ja3", "sni", "ja3s"]
        ja3_csv2.columns = ["ja3", "sni", "ja3s"]

        merged = pd.concat([ja3_csv1, ja3_csv2])
        merged.to_csv("ja3_train/" + file_name + ".csv", index=False, sep=';', header=False)
        os.remove("ja3_train/" + os.path.splitext(file_name)[0] + "1.csv")
        os.remove("ja3_train/" + os.path.splitext(file_name)[0] + "2.csv")

# Remove any duplicates from fingerprint database.
def remove_duplicates_from_csv():

    file_names = os.listdir("ja3_train")
    for file_name in file_names:
        fingerprints = open("ja3_train/" + file_name, mode="r")
        fingerprints_rd = open("ja3+ja3s_rd/" + file_name, mode="w")
        fingerprint_found = set()
        for fingerprint in fingerprints:
            if fingerprint in fingerprint_found:
                continue
            fingerprint_found.add(fingerprint)
            fingerprints_rd.write(fingerprint)
        fingerprints.close()
        fingerprints_rd.close()

# Creation of sqlite database
def create_fingerprints_db():
    
    db = sqlite3.connect("fingerprints.db")
    cur = db.cursor()
    file_names = os.listdir("ja3+ja3s_rd")

    for file_name in file_names:
        fingerprints = open("ja3+ja3s_rd/" + file_name)
        fingerprints_rows = csv.reader(fingerprints, delimiter=';', quotechar='"', quoting=csv.QUOTE_MINIMAL)

        cur.execute("CREATE TABLE IF NOT EXISTS " + os.path.splitext(file_name)[0] + " (ja3, sni, ja3s);")
        cur.executemany("INSERT INTO " + os.path.splitext(file_name)[0] + " VALUES (?, ?, ?);", fingerprints_rows)

    db.commit()
    db.close

__all__ = ["ja3_and_ja3s", "concat_ja3_and_ja3s", "remove_duplicates_from_csv", "create_fingerprints_db"]