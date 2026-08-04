# 📡 Network Packet Capture & Analysis Tool

A Python-based packet sniffer built using **Scapy** to capture and analyze live network traffic. This project helps understand how network packets are transmitted by displaying protocol information, IP addresses, ports, packet length, and payload details.

---

## 📌 Features

- Capture live network packets
- Analyze Ethernet, IPv4, IPv6, TCP, UDP, ICMP, ARP, and DNS packets
- Display source and destination IP addresses
- Show source and destination ports
- Display packet size
- Preview packet payload
- Apply custom packet filters
- List available network interfaces
- Generate packet capture summary

---

## 🛠 Technologies Used

- Python 3
- Scapy

---

## 📂 Project Structure

```
Packet_Sniffer/
│── images/
│── packet_sniffer.py
│── README.md
│── requirements.txt
```

---

## 📥 Installation

Install Scapy:

```bash
pip install -r requirements.txt
```

or

```bash
pip install scapy
```

---

## ▶️ Run the Program

Linux/macOS

```bash
sudo python packet_sniffer.py
```

Windows (Run Command Prompt as Administrator)

```bash
python packet_sniffer.py
```

Capture only 50 packets

```bash
python packet_sniffer.py -c 50
```

Capture HTTP traffic

```bash
python packet_sniffer.py -f "tcp port 80"
```

List Interfaces

```bash
python packet_sniffer.py --list-interfaces
```

---

## 📊 Sample Output

(Add your screenshots inside the **images** folder.)

```text
[21:03:18] #1 TCP len=74
192.168.1.10:53124 -> 142.250.182.78:443

[21:03:19] #2 DNS
192.168.1.10 -> 8.8.8.8
```

---

## 📷 Screenshots

After running the project, save screenshots inside:

```
images/
```

Example:

```
images/output.png
```

Then display them like this:

```markdown
![Output](images/output.png)
```

---

## 🚀 Future Improvements

- GUI Interface
- Export packet logs to CSV
- Save captured packets as PCAP
- Packet search and filtering
- Real-time graphs

---

## 👨‍💻 Author

**Singarapu Thanushka**