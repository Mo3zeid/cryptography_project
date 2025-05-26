import tkinter as tk
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os

# === Cryptography Functions ===
def generate_ecdh_key():
    return ec.generate_private_key(ec.SECP256R1())

def derive_shared_key(private_key, peer_public_key):
    shared_key = private_key.exchange(ec.ECDH(), peer_public_key)
    derived_key = HKDF(
        algorithm=hashes.SHA256(), length=32, salt=None, info=b"handshake"
    ).derive(shared_key)
    return derived_key

def encrypt_message(key, plaintext):
    iv = os.urandom(12)
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext.encode()) + encryptor.finalize()
    return iv, ciphertext, encryptor.tag

def decrypt_message(key, iv, ciphertext, tag):
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag))
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()

def sign_message(private_key, message):
    return private_key.sign(message, ec.ECDSA(hashes.SHA256()))

def verify_signature(public_key, message, signature):
    try:
        public_key.verify(signature, message, ec.ECDSA(hashes.SHA256()))
        return True
    except Exception:
        return False

# === Key Setup ===
alice_private = generate_ecdh_key()
bob_private = generate_ecdh_key()

alice_public = alice_private.public_key()
bob_public = bob_private.public_key()

alice_shared_key = derive_shared_key(alice_private, bob_public)
bob_shared_key = derive_shared_key(bob_private, alice_public)

# === GUI Setup ===
window = tk.Tk()
window.title("Secure Chat using ECDH + AES + Signatures")

# Chat areas
alice_chat = tk.Text(window, height=15, width=60)
bob_chat = tk.Text(window, height=15, width=60)
alice_chat.grid(row=0, column=0, padx=10, pady=10)
bob_chat.grid(row=0, column=1, padx=10, pady=10)
alice_chat.insert(tk.END, "--- Alice's View ---\n")
bob_chat.insert(tk.END, "--- Bob's View ---\n")

# Message entries
alice_entry = tk.Entry(window, width=40)
bob_entry = tk.Entry(window, width=40)
alice_entry.grid(row=1, column=0, padx=10)
bob_entry.grid(row=1, column=1, padx=10)

# Send functions
def send_from_alice():
    msg = alice_entry.get()
    alice_entry.delete(0, tk.END)
    iv, ciphertext, tag = encrypt_message(alice_shared_key, msg)
    signature = sign_message(alice_private, msg.encode())
    decrypted = decrypt_message(bob_shared_key, iv, ciphertext, tag).decode()
    is_valid = verify_signature(alice_public, decrypted.encode(), signature)
    alice_chat.insert(tk.END, f"Alice (sent): {msg}\nSignature: {signature.hex()}\n")
    bob_chat.insert(tk.END, f"Alice (received): {decrypted}\nSignature valid: {is_valid}\n")

def send_from_bob():
    msg = bob_entry.get()
    bob_entry.delete(0, tk.END)
    iv, ciphertext, tag = encrypt_message(bob_shared_key, msg)
    signature = sign_message(bob_private, msg.encode())
    decrypted = decrypt_message(alice_shared_key, iv, ciphertext, tag).decode()
    is_valid = verify_signature(bob_public, decrypted.encode(), signature)
    bob_chat.insert(tk.END, f"Bob (sent): {msg}\nSignature: {signature.hex()}\n")
    alice_chat.insert(tk.END, f"Bob (received): {decrypted}\nSignature valid: {is_valid}\n")

# Buttons
tk.Button(window, text="Send from Alice", command=send_from_alice).grid(row=2, column=0, pady=5)
tk.Button(window, text="Send from Bob", command=send_from_bob).grid(row=2, column=1, pady=5)

window.mainloop()