# Data Communications, Computer Networks and Protocols
## Identification of Mobile Traffic using TLS Fingerprinting
Python script used for extraction of usefull attributes from pcap files, JA3+JA3S fingerprinting and performance evaluation.

## Requirements
Install requeirements and start enviroment with:
```bash
$ pipenv install
```

## Run
Tool can be run by running 4 different options.

### -t
```bash
$ python run.py -t
```
Use for creation of SQLite database with JA3+JA3S fingerprints from training data.

### -c
```bash
$ python run.py -c
```
Use for creation of csv files with JA3+JA3S fingerprints from data intended for classification.

### -x
```bash
$ python run.py -x
```
Use to classify created csv files against created database and print confusion matrix, accuracy, recall and precision.

### -a
```bash
$  python run.py -a
```
Same as:

```bash
$  python run.py -t -c -x
```