# 🛡️ SafeRansomLab — Ransomware Simulator (Educational)

![Python](https://img.shields.io/badge/Python-3.8%2B-blue?logo=python)
![Security](https://img.shields.io/badge/Safe-Sandboxed-green)
![UI](https://img.shields.io/badge/GUI-Tkinter-orange?logo=python)
![Status](https://img.shields.io/badge/Project-Educational-red)
![Made By](https://img.shields.io/badge/Made%20By-DE(Vishux777)-purple)

---

⚠️ **WARNING:** This project simulates ransomware behavior for **educational and research purposes only.**  
Do **NOT** run this code on your real system outside a controlled sandbox, virtual machine, or isolated environment.  
It encrypts files inside a **sandbox directory** only (`./SafeRansomLab_Sandbox`).  

---

## 🚀 Features

✅ Encrypts and decrypts files inside the sandbox folder  
✅ Simulates ransomware file deletion by moving originals to `.deleted/`  
✅ Uses a simple XOR-based stream cipher with SHA-256 keystream  
✅ Provides a **demo lock screen** with Tkinter (fullscreen popup)  
✅ Includes demo key: **`RlVDS1dPUkxE(Decrypt its BASE64)`**  
✅ Safe — operates **only** inside `./SafeRansomLab_Sandbox`  

---

## 📂 Project Structure

```
SafeRansomLab/
│── ransomware_simulator.py   # Main script
│── SafeRansomLab_Sandbox/    # Sandbox directory (auto-created)
│   ├── readme.txt
│   ├── notes.txt
│   ├── hello.txt
│   ├── data.csv
│   └── .deleted/             # Holds originals after encryption
```

---

## ⚙️ Installation

### Requirements
- Python **3.8+**  
- Tkinter (for lock screen UI, usually preinstalled with Python)

Clone this repo and navigate into it:

```bash
https://github.com/vishux777/Ransomware_Simulation.git
cd SafeRansomLab
```

---

## 🧪 Usage

### Create demo files
```bash
python3 ransomware_simulator.py --make-demo
```

### Encrypt files
```bash
python3 ransomware_simulator.py --mode encrypt
```

### Decrypt files
```bash
python3 ransomware_simulator.py --mode decrypt
```

### Show ransomware demo lock screen
```bash
python3 ransomware_simulator.py --make-demo --mode encrypt --show-demo-lock
```

---

## 🔑 Demo Key

The hardcoded demo decryption key is:

```
RlVDS1dPUkxE       (Decode this is BASE64)
```

---

## 🛡️ Security Guardrails

- Operates **only** inside `./SafeRansomLab_Sandbox`.  
- Skips symlinks and prevents traversal outside sandbox.  
- Encrypted files get `.srl` extension.  
- Original files are moved to `.deleted/` for recovery.  

---

## 📚 Educational Use Cases

- Study how ransomware encrypts and hides files.  
- Learn about safe ransomware simulation.  
- Use as a **CTF challenge** or **training exercise**.  
- Demonstrate **incident response** in a sandboxed environment.  

---

## ⚠️ Disclaimer

This project is for **research and educational purposes only.**  
The author is **not responsible** for any misuse of this code.  
Running this outside a sandbox/VM may cause **data loss**.  

---

### ✨ Made by **DE (Vishux777)**
