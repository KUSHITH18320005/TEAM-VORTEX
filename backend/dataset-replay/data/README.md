# Dataset CSV Drop Location (`backend/dataset-replay/data/`)

Place manually downloaded CSV files from the Canadian Institute for Cybersecurity (UNB) into this directory.

Supported filenames / structures:
- `CICIDS2017.csv` or `CICIDS2017/*.csv` (e.g. `Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv`, `Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv`, `Wednesday-workingHours.pcap_ISCX.csv`)
- `CIC-IoT2023.csv` or `CIC-IoT2023/*.csv` (e.g. `part-00000-*.csv`)
- `CIC-MalMem2022.csv` or `CIC-MalMem2022/*.csv` (e.g. `Obfuscated-MalMem2022.csv`)
- `NSL-KDD.csv` or `NSL-KDD/*.csv` (e.g. `KDDTrain+.csv`)

If CSV files are not present in this folder, `import.py` automatically synthesizes high-fidelity, schema-exact telemetry based on the exact features specified in `categories.json`.
