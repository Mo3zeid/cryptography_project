# 🔐 cryptography_project

A Python-based educational toolkit that demonstrates **secure communication** and **digital signature systems** using modern cryptographic methods.

## 🧠 Project Overview

This project consists of two main parts:

### ✅ Part A: Secure Chat with ECC
A GUI-based secure chat demo between Alice and Bob using:
- **Elliptic Curve Diffie-Hellman (ECDH)** for shared key exchange
- **AES-GCM** for authenticated encryption
- **ECDSA** for digital signatures

### ✅ Part B: Digital Signature Forgery Simulation (RSA)
A console-based demonstration of:
- **RSA key generation, signing, and verification**
- **Signature forgery attack simulation** (highlighting dangers of signing without hashing)



---

## 🛠 Features Implemented

- 🔐 **ECC Key Exchange** using ECDH
- 🔏 **AES-GCM Encryption** for confidentiality and integrity
- ✍️ **ECDSA Digital Signatures** for secure message authentication
- 🔓 **RSA Digital Signatures** with custom implementation
- ⚠️ **Forgery Simulation** to show insecurity of signing raw messages with RSA

---

## 💡 Educational Goals

- Understand how **public key cryptography** ensures confidentiality and authenticity.
- Explore why **hashing before signing** is critical in digital signatures.
- Learn about **attacks** like **existential forgery** in poorly implemented systems.

---

## 🚀 How to Run

### Requirements
- Python 3.8+
- Dependencies (install via pip):
```bash
pip install cryptography pycryptodome
