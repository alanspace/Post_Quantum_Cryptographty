

Post-Quantum Key Exchange: A Kyber (ML-KEM) Simulation
This repository contains a Python script that simulates and explains the Kyber (ML-KEM) algorithm, the primary post-quantum key exchange mechanism selected for standardization by NIST.

The script demonstrates how two parties, Alice and Bob, can establish a shared secret key over an insecure channel, safe from attacks by both classical and quantum computers. It then uses this shared key in a hybrid encryption scheme with AES-GCM to send secure messages.

The primary goal of this script is educational: to provide a clear, hands-on demonstration of how a Post-Quantum Cryptography (PQC) Key Encapsulation Mechanism (KEM) works and to highlight the real-world trade-offs between different security levels.

✨ Features
Full KEM Simulation: Simulates the complete Kyber key exchange process: keygen, encaps (encapsulation), and decaps (decapsulation).
NIST Security Levels: Runs simulations for all three official ML-KEM variants, corresponding to NIST's security levels 1, 3, and 5:
ML-KEM-512
ML-KEM-768
ML-KEM-1024
Performance & Size Analysis: For each variant, the script measures and reports key metrics, including:
Public & Private Key Sizes
Ciphertext Size
Execution time for key generation, encapsulation, and decapsulation.
Practical Application: Demonstrates how the derived 32-byte shared secret can be used with a standard symmetric cipher (AES-GCM) for secure messaging.
⚙️ How It Works
The script follows the standard KEM flow in a "hybrid encryption" model:

Asymmetric Key Exchange (Kyber):
Bob (Recipient): Generates a public/private key pair (ek_B, dk_B) and sends his public key ek_B to Alice.
Alice (Sender): Uses Bob's public key ek_B to encapsulate a secret. This process generates two items: a shared secret (key_A) and a ciphertext (ct). She sends only the ct to Bob.
Bob (Recipient): Uses his private key dk_B to decapsulate the ciphertext ct, deriving the exact same shared secret (key_B).
Now, both Alice and Bob possess an identical shared secret, while an eavesdropper with ek_B and ct cannot compute it.
Symmetric Encryption (AES-GCM):
The 32-byte (256-bit) shared secret derived from Kyber is used as the key for the highly efficient and secure AES-GCM algorithm.
Alice and Bob can now encrypt and decrypt messages to each other using this key.
📋 Prerequisites
Python 3.7+
The kyber-py and cryptography libraries.
We can install the required libraries using pip:

Generated bash
pip install kyber-py cryptography```

## 🚀 Usage

Simply run the script from terminal. It requires no command-line arguments.

```bash
python kyber_simulation.py
Use code with caution.
Bash
The script will automatically execute the simulation for all three Kyber variants and print a detailed report and a final summary of the observations.

Example Output
Generated code
============================================================
🚀 Running Simulation for: ML-KEM-768 (Security Level 3)
============================================================

--- Step 1: Kyber Key Exchange ---
👤 Bob: Generated my key pair (ek_B, dk_B).
📡 Bob -> Alice: Sending my public key (ek_B)...

👤 Alice: Received Bob's public key.
👤 Alice: Generated a shared secret (key_A) and a ciphertext (ct).
📡 Alice -> Bob: Sending the ciphertext (ct)...

👤 Bob: Received the ciphertext from Alice.
👤 Bob: Decapsulated the ciphertext to get my shared secret (key_B).

--- Verification ---
✅ Success! Alice and Bob have the same shared secret.

--- Step 2: Secure Messaging with AES-GCM ---
...

--- Performance & Size Report ---
Parameter             | Value
----------------------|---------------------------------
Public Key (ek) Size  | 1184 bytes
Private Key (dk) Size | 2400 bytes
Ciphertext (ct) Size  | 1088 bytes
Shared Key Size       | 32 bytes (256-bit)
----------------------|---------------------------------
Key Generation Time   | 0.2514 ms
Encapsulation Time    | 0.3688 ms
Decapsulation Time    | 0.3105 ms
----------------------------------------------------------
Use code with caution.
📊 Key Takeaways
The final output of the script summarizes the fundamental trade-offs in PQC:

Security vs. Size: Higher security levels (e.g., ML-KEM-1024) require significantly larger public keys and ciphertexts, increasing the amount of data that must be transmitted for the key exchange.
Security vs. Performance: The computational complexity increases with the security level, making key generation and encapsulation/decapsulation slower for higher-security variants.
README for the Python Port Scanner Script
Python Port Scanner with Basic and Nmap Modes
This repository contains a versatile network port scanning tool written in Python. It is designed for both quick checks and in-depth analysis by offering two distinct scanning modes:

Basic Mode: A lightweight, fast scanner built using Python's native socket library. Ideal for quickly checking if a set of common ports are open.
Advanced Mode: A powerful scanner that leverages the Nmap engine (via the python-nmap library) to perform service and version detection on open ports, providing much richer information.
The tool also includes a built-in dictionary to provide context on common ports, explaining their typical services and potential security risks.

✨ Features
Dual-Mode Scanning: Choose between a fast, simple scan or a detailed, comprehensive one.
Service & Version Detection: Advanced mode identifies the software and version running on open ports.
Port Analysis: Provides human-readable descriptions and security considerations for well-known ports (e.g., 21, 22, 80, 443, 3389).
User-Friendly Interface: Simple command-line prompts guide the user.
Robust Error Handling: Gracefully handles unreachable hosts and cases where Nmap is not installed.
Clean, Organized Reports: Presents scan results in a clear and structured format.
📋 Prerequisites
For Both Modes:
Python 3.7+
For Advanced (Nmap) Mode Only:
Nmap Installation: The Nmap network scanner must be installed on the system.
Linux (Debian/Ubuntu): sudo apt-get update && sudo apt-get install nmap
Linux (Fedora/CentOS): sudo dnf install nmap
macOS (using Homebrew): brew install nmap
Windows: Download the installer from the Nmap official website.
Python Library: We need the python-nmap library.
Generated bash
pip install python-nmap
Use code with caution.
Bash
🚀 Usage
Clone this repository or download the script.
Run the script from the terminal:
Generated bash
python port_scanner.py
Use code with caution.
Bash
Follow the on-screen prompts:
Enter the target hostname (e.g., google.com) or IP address (e.g., 8.8.8.8).
Choose the desired scanning mode (1 for Basic, 2 for Advanced).
Example Session
Generated bash
$ python port_scanner.py
Enter the target domain or IP address: scanme.nmap.org
Select scanner type:
1. Basic (socket)
2. Advanced (Nmap)
Enter choice (1 or 2): 2

[*] Attempting to resolve scanme.nmap.org...
[*] Target IP resolved to: 45.33.32.156
[*] Starting Nmap scan...
[*] Host: 45.33.32.156 (scanme.nmap.org) is up.

--- Scan Results ---

[!] Open Port: 22
    - Service:       ssh
    - Purpose:       Provides secure remote login and other secure network services.
    - Security Risk: If misconfigured or using weak credentials, it can be a primary vector for unauthorized access. Keep software updated and use strong authentication (keys preferred over passwords).

[!] Open Port: 80
    - Service:       http
    - Purpose:       Transmits web page data. The foundation of data communication for the World Wide Web.
    - Security Risk: Unencrypted communication. Sensitive data can be intercepted. Always prefer HTTPS (port 443).

--- End of Report ---


For more information on post quantum cryptography:

https://github.com/GiacomoPope/kyber-py

https://pq-crystals.org/kyber/

https://docs.openssl.org/master/

https://cryptography.io/en/latest/

