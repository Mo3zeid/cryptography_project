from Crypto.Util.number import getPrime, inverse


# RSA Key Generation (simplified)
def generate_keys(bits=16):
    p = getPrime(bits)
    q = getPrime(bits)
    n = p * q
    phi = (p - 1) * (q - 1)

    # Common public exponent
    e = 65537
    d = inverse(e, phi)
    return (n, e), (n, d)


# Signing (m^d mod n)
def sign(message, priv_key):
    n, d = priv_key
    return pow(message, d, n)


# Verifying (s^e mod n)
def verify(signature, pub_key):
    n, e = pub_key
    return pow(signature, e, n)


# -----------------------------
# Part (a): Eve wants to forge signature for m = 123456789
def eve_cannot_forge_signature(m, pub_key):
    n, e = pub_key
    print(f"Eve cannot easily find s such that s^e ≡ {m} mod {n}")
    print("Because it would require solving the RSA problem (modular root).")


# -----------------------------
# Part (b): Eve chooses signature s and computes message m = s^e mod n
def eve_forge_message_from_signature(s, pub_key):
    m = verify(s, pub_key)
    print(f"Eve forged a valid signature!\nSignature s = {s}")
    print(f"This corresponds to message m = {m}")
    return m


# -----------------------------
# Main Simulation
if __name__ == "__main__":
    pub_key, priv_key = generate_keys()

    print("Public Key (n, e):", pub_key)
    print("Private Key (n, d):", priv_key)

    print("\n--- Part (a): Eve cannot forge signature for fixed m ---")
    eve_cannot_forge_signature(123456789, pub_key)

    print("\n--- Part (b): Eve forges signature s = 112090305 ---")
    s = 112090305
    m = eve_forge_message_from_signature(s, pub_key)

    # Alice would think s is a signature on m:
    print("\nVerification by Alice (s^e mod n):", verify(s, pub_key))
