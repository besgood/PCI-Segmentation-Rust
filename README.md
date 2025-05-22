# 🔐 PCI Segmentation Scanner (Rust)

A fast, resumable, and standards-aligned PCI segmentation testing tool written in Rust. Supports both **Nmap** and **Masscan**, with flexible output formats including **Excel**, **CSV**, **HTML**, and **JSON**.

---

## ✨ Features

- ✅ TCP, UDP, or both protocol scans  
- 🚀 Scanner engine toggle: use **Nmap** or **Masscan**  
- 🎯 Port scope selection: `top100`, `top1000`, `top10000`, or `all`  
- 🧠 Resume support for interrupted scans  
- ⚙️ Masscan throttling to prevent network overload (`--rate`)  
- 📊 Compliance logic: PASS/FAIL based on open ports  
- 📁 Reports:
  - Excel (`.xlsx`)
  - HTML (interactive)
  - CSV
  - JSON  
- 🖥️ CLI-based workflow with interactive batch handling

---

## 📦 Installation

Make sure you have Rust installed:

```bash
curl https://sh.rustup.rs -sSf | sh
```

Clone the repo:

```bash
git clone https://github.com/yourusername/pci-segmentation-scanner.git
cd pci-segmentation-scanner
cargo build --release
```

---

## 🛠️ Usage

```bash
./target/release/pci_scanner \
  --hostfile targets.txt \
  --portscope top1000 \
  --protocol both \
  --scanner nmap \
  --output results \
  --rate 1000
```

### Arguments

| Flag            | Description                                      |
|-----------------|--------------------------------------------------|
| `--hostfile`    | File with target IPs (one per line)             |
| `--portscope`   | `top100`, `top1000`, `top10000`, `all`          |
| `--protocol`    | `tcp`, `udp`, `both`                            |
| `--scanner`     | `nmap` or `masscan`                             |
| `--output`      | Base name for report files                      |
| `--rate`        | (Masscan only) packets/sec (default: 1000)      |

---

## 📄 Example Output

After a scan, the following files are generated:

- `results_report.xlsx`
- `results_report.html`
- `results_report.csv`
- `results_report.json`

---

## 🧪 Compliance Logic

Hosts are marked as:

- ✅ **PASS** – No open ports
- ❌ **FAIL** – One or more open ports found

---

## 📋 License

MIT License © [Your Name or Organization]

---

## 🤝 Contributing

Pull requests welcome! Please open an issue to discuss improvements or new features.