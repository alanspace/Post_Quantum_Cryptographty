import time
import os
import sys

# Try to import Kyber and cryptography libraries
try:
    from kyber_py.ml_kem import ML_KEM_512, ML_KEM_768, ML_KEM_1024
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
except ImportError:
    print("Error: Required libraries not found.")
    print("Please install them using: pip install kyber-py cryptography")
    sys.exit(1)

# --- Symmetric Encryption Helper Functions (using AES-GCM) ---
# AES-GCM provides both confidentiality and integrity.

def encrypt_aes_gcm(key: bytes, plaintext: bytes) -> bytes:
    """
    Encrypts plaintext using AES-GCM with the given key.
    A random 12-byte nonce is generated and prepended to the ciphertext.
    """
    # The Kyber shared secret is 32 bytes, which is a perfect 256-bit key for AES.
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)  # GCM standard nonce size
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)
    return nonce + ciphertext

def decrypt_aes_gcm(key: bytes, ciphertext_with_nonce: bytes) -> bytes:
    """
    Decrypts AES-GCM ciphertext using the given key.
    Assumes a 12-byte nonce is prepended to the ciphertext.
    """
    aesgcm = AESGCM(key)
    nonce = ciphertext_with_nonce[:12]
    ciphertext = ciphertext_with_nonce[12:]
    try:
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
        return plaintext
    except Exception as e:
        print(f"Decryption failed: {e}")
        return b"*** DECRYPTION FAILED ***"

# --- Main Simulation and Comparison Function ---

def run_simulation(variant_name, kyber_variant):
    """
    Runs the full simulation for a given Kyber variant.
    1. Simulates Kyber key exchange.
    2. Measures performance (time and size).
    3. Simulates secure messaging using the derived shared key.
    """
    print(f"\n{'='*60}")
    print(f"🚀 Running Simulation for: {variant_name}")
    print(f"{'='*60}\n")

    # --- 1. Kyber Key Exchange Simulation ---
    # In a KEM, the party who will receive the secret (Bob) generates a key pair.
    # The party sending the secret (Alice) uses Bob's public key to encapsulate a secret.

    print("--- Step 1: Kyber Key Exchange ---")

    # Bob generates his key pair (encapsulation key, decapsulation key)
    start_time = time.perf_counter()
    ek_bob, dk_bob = kyber_variant.keygen()
    keygen_time = (time.perf_counter() - start_time) * 1000  # in ms
    print("👤 Bob: Generated my key pair (ek_B, dk_B).")
    # Bob sends his public encapsulation key (ek_bob) to Alice over an insecure channel.
    print("📡 Bob -> Alice: Sending my public key (ek_B)...")

    # Alice receives Bob's public key and generates a shared secret and a ciphertext.
    print("\n👤 Alice: Received Bob's public key.")
    start_time = time.perf_counter()
    shared_key_alice, ct = kyber_variant.encaps(ek_bob)
    encaps_time = (time.perf_counter() - start_time) * 1000  # in ms
    print("👤 Alice: Generated a shared secret (key_A) and a ciphertext (ct).")
    # Alice sends the ciphertext (ct) back to Bob over the insecure channel.
    print("📡 Alice -> Bob: Sending the ciphertext (ct)...")

    # Bob receives the ciphertext and uses his private key to derive the same shared secret.
    print("\n👤 Bob: Received the ciphertext from Alice.")
    start_time = time.perf_counter()
    shared_key_bob = kyber_variant.decaps(dk_bob, ct)
    decaps_time = (time.perf_counter() - start_time) * 1000 # in ms
    print("👤 Bob: Decapsulated the ciphertext to get my shared secret (key_B).")

    # Verification
    print("\n--- Verification ---")
    if shared_key_alice == shared_key_bob:
        print("✅ Success! Alice and Bob have the same shared secret.")
    else:
        print("❌ Failure! Shared secrets do not match.")
        return # Stop simulation if key exchange failed

    # --- 2. Secure Messaging using the Shared Key ---
    print("\n--- Step 2: Secure Messaging with AES-GCM ---")

    # Alice sends a message to Bob
    alice_message = b"Hello Bob! This is a secret message from Alice. Post-quantum is cool!"
    print(f"\n[Alice's Original Message]: {alice_message.decode()}")

    encrypted_message = encrypt_aes_gcm(shared_key_alice, alice_message)
    print(f"📡 Alice -> Bob: Sending encrypted message (length: {len(encrypted_message)} bytes)...")

    # Bob decrypts the message
    decrypted_message = decrypt_aes_gcm(shared_key_bob, encrypted_message)
    print(f"[Bob's Decrypted Message]: {decrypted_message.decode()}")
    assert alice_message == decrypted_message

    # Bob sends a reply to Alice
    bob_message = b"Hi Alice! I got your message loud and clear. Kyber works!"
    print(f"\n[Bob's Original Message]: {bob_message.decode()}")

    encrypted_reply = encrypt_aes_gcm(shared_key_bob, bob_message)
    print(f"📡 Bob -> Alice: Sending encrypted reply (length: {len(encrypted_reply)} bytes)...")
    
    # Alice decrypts the reply
    decrypted_reply = decrypt_aes_gcm(shared_key_alice, encrypted_reply)
    print(f"[Alice's Decrypted Message]: {decrypted_reply.decode()}")
    assert bob_message == decrypted_reply


    # --- 3. Performance and Size Comparison ---
    print("\n--- Performance & Size Report ---")
    print(f"Parameter             | Value")
    print(f"----------------------|---------------------------------")
    # Sizes
    print(f"Public Key (ek) Size  | {len(ek_bob)} bytes")
    print(f"Private Key (dk) Size | {len(dk_bob)} bytes")
    print(f"Ciphertext (ct) Size  | {len(ct)} bytes")
    print(f"Shared Key Size       | {len(shared_key_alice)} bytes (256-bit)")
    print(f"----------------------|---------------------------------")
    # Timings
    print(f"Key Generation Time   | {keygen_time:.4f} ms")
    print(f"Encapsulation Time    | {encaps_time:.4f} ms")
    print(f"Decapsulation Time    | {decaps_time:.4f} ms")
    print(f"----------------------------------------------------------")


if __name__ == "__main__":
    # Define the variants to test
    kyber_variants = [
        ("ML-KEM-512 (Security Level 1)", ML_KEM_512),
        ("ML-KEM-768 (Security Level 3)", ML_KEM_768),
        ("ML-KEM-1024 (Security Level 5)", ML_KEM_1024),
    ]

    for name, variant in kyber_variants:
        run_simulation(name, variant)

    print("\n\n" + "="*60)
    print("✅ All Simulations Complete")
    print("="*60)
    print("""
    Observations & Trade-offs:

    1.  Security vs. Size:
        As the security level increases (512 -> 768 -> 1024), the sizes of the public
        key (ek), private key (dk), and the Kyber ciphertext (ct) all increase
        significantly. This means more data needs to be transmitted over the
        network for the key exchange. The shared secret key size remains constant
        at 32 bytes for all variants.

    2.  Security vs. Performance:
        Higher security levels require more complex mathematical operations on larger
        lattices. Consequently, the execution times for key generation, encapsulation,
        and decapsulation all increase with the security level. ML-KEM-512 is the
        fastest, while ML-KEM-1024 is the slowest.

    3.  Conclusion:
        The choice of a Kyber variant is a trade-off. For applications requiring the
        highest security guarantees (e.g., long-term archives), ML-KEM-1024 might be
        appropriate, despite its performance overhead. For typical applications like
        secure web browsing (TLS), where performance is critical, ML-KEM-512 or
        ML-KEM-768 offer a better balance between strong post-quantum security
        and efficiency.
    """)