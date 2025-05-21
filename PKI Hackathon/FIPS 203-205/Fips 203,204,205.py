from pqcrypto.kem.ml_kem_512 import generate_keypair as ml_kem_keypair, encrypt as ml_kem_encrypt, decrypt as ml_kem_decrypt
from pqcrypto.sign.ml_dsa_87 import generate_keypair as ml_dsa_keypair, sign as ml_dsa_sign, verify as ml_dsa_verify # Using ml_dsa_44 for variety, _87 is also fine
from pqcrypto.sign.sphincs_sha2_256f_simple import generate_keypair as slh_dsa_keypair, sign as slh_dsa_sign, verify as slh_dsa_verify
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os

# --- KEY GENERATION (Alice) ---
print("--- ALICE: Key Generation ---")

# Alice generates ML-KEM keypair (FIPS 203 - for confidentiality)
kem_public_key_alice, kem_secret_key_alice = ml_kem_keypair()
# For a real scenario, Alice would get Bob's KEM public key.
# For this demo, we'll simulate Bob having his own keys later.
# Let's assume Alice wants to send to Bob, so Bob needs KEM keys.
kem_public_key_bob, kem_secret_key_bob = ml_kem_keypair()
print("Alice has Bob's KEM Public Key.")
print("Alice generated her own KEM keys (not used for sending to Bob in this flow).")


# Alice generates ML-DSA signature keypair (FIPS 204 - for authenticity option 1)
mldsa_sig_public_key_alice, mldsa_sig_secret_key_alice = ml_dsa_keypair()
print("Alice generated ML-DSA (Dilithium) signing keypair.")

# Alice generates SLH-DSA signature keypair (FIPS 205 - for authenticity option 2)
slhdsa_sig_public_key_alice, slhdsa_sig_secret_key_alice = slh_dsa_keypair()
print("Alice generated SLH-DSA (SPHINCS+) signing keypair.")
print("-" * 30)

# --- ENCRYPTION & SIGNING (Alice sends to Bob) ---
print("\n--- ALICE: Encryption & Signing ---")

# Alice prepares the message she wants to send securely to Bob
message = b"PKI{PQC_FIPS_203_204_205_demo_works!}"
print(f"Original Message: {message.decode()}")

# 1. KEM for Shared Secret: Alice uses Bob's KEM public key to derive a shared AES key
# Alice sends ciphertext_kem to Bob
kem_ciphertext_for_bob, shared_secret_alice = ml_kem_encrypt(kem_public_key_bob)
print(f"KEM Ciphertext (for Bob): {kem_ciphertext_for_bob.hex()}")
print(f"Shared Secret (Alice's side): {shared_secret_alice.hex()}")

# Alice derives AES-256 key from the shared secret
# FIPS 203 ML-KEM specifies output shared secret sizes (e.g., 32 bytes for ML-KEM-512/768/1024)
# So shared_secret_alice should already be the correct length for an AES-256 key.
aes_key_alice = shared_secret_alice # No need to slice if using a KEM variant that outputs 32 bytes

# Alice encrypts the message using AES-GCM
aesgcm = AESGCM(aes_key_alice)
nonce = os.urandom(12)  # Alice generates a random nonce for this session
# Alice sends ciphertext_aes and nonce to Bob
ciphertext_aes = aesgcm.encrypt(nonce, message, None)
print(f"AES-GCM Nonce: {nonce.hex()}")
print(f"AES-GCM Ciphertext: {ciphertext_aes.hex()}")

# 2. SIGNING: Alice signs the AES-GCM ciphertext
# Option 1: Sign with ML-DSA (Dilithium)
mldsa_signature = ml_dsa_sign(mldsa_sig_secret_key_alice, ciphertext_aes)
print(f"ML-DSA Signature: {mldsa_signature.hex()}")

# Option 2: Sign with SLH-DSA (SPHINCS+)
# SPHINCS+ can be slower for signing, especially for larger parameter sets
slhdsa_signature = slh_dsa_sign(slhdsa_sig_secret_key_alice, ciphertext_aes)
print(f"SLH-DSA Signature: {slhdsa_signature.hex()}")
print("-" * 30)

# Alice sends to Bob:
#   → kem_ciphertext_for_bob (KEM ciphertext)
#   → nonce (AES-GCM)
#   → ciphertext_aes (AES encrypted message)
#   → EITHER mldsa_signature AND mldsa_sig_public_key_alice (or a way for Bob to get it)
#   → OR slhdsa_signature AND slhdsa_sig_public_key_alice (or a way for Bob to get it)
#   For this demo, Bob will try verifying with both if he has both public keys.

# --- VERIFICATION & DECRYPTION (Bob receives from Alice) ---
print("\n--- BOB: Verification & Decryption ---")

# Bob receives: kem_ciphertext_for_bob, nonce, ciphertext_aes
# And potentially one or both signatures and the corresponding public keys.
# We assume Bob has Alice's mldsa_sig_public_key_alice and slhdsa_sig_public_key_alice

# Step 1: Bob verifies the signature on the AES-GCM ciphertext

# Try ML-DSA verification
mldsa_verified = ml_dsa_verify(mldsa_sig_public_key_alice, ciphertext_aes, mldsa_signature)
if mldsa_verified:
    print("[✓] ML-DSA Signature VERIFIED!")
else:
    print("[✗] ML-DSA Signature verification FAILED.")

# Try SLH-DSA verification
slhdsa_verified = slh_dsa_verify(slhdsa_sig_public_key_alice, ciphertext_aes, slhdsa_signature)
if slhdsa_verified:
    print("[✓] SLH-DSA Signature VERIFIED!")
else:
    print("[✗] SLH-DSA Signature verification FAILED.")

# In a real protocol, Bob would likely expect one type of signature, or there'd be an indicator.
# For this demo, we proceed if at least one valid signature type was hypothetically used and verified.
# Let's assume the protocol decided to use ML-DSA for this exchange, or that Bob trusts if any known signature scheme verifies.
# A more robust check might be: `if mldsa_verified or slhdsa_verified:`
# For simplicity, we'll proceed if the ML-DSA one verified, as an example.

if mldsa_verified: # Or use a flag to indicate which signature scheme was intended
    print("Proceeding with decryption as signature is considered valid...")

    # Step 2: Bob decrypts the KEM ciphertext to get the shared secret
    # Bob uses HIS OWN KEM secret key corresponding to the kem_public_key_bob Alice used.
    shared_secret_bob = ml_kem_decrypt(kem_secret_key_bob, kem_ciphertext_for_bob)
    print(f"Shared Secret (Bob's side): {shared_secret_bob.hex()}")
    aes_key_bob = shared_secret_bob # KEM output is the key

    # Assert that shared secrets match (for demo purposes)
    assert shared_secret_alice == shared_secret_bob, "KEM shared secrets do not match!"
    print("[✓] KEM Shared secrets match between Alice and Bob.")

    # Step 3: Bob decrypts the AES-GCM ciphertext to recover the message
    aesgcm_recv = AESGCM(aes_key_bob)
    try:
        plaintext = aesgcm_recv.decrypt(nonce, ciphertext_aes, None)
        print(f"Decrypted message: {plaintext.decode()}")
        assert plaintext == message, "Decrypted message does not match original!"
        print("[✓] Message successfully decrypted and matches original.")
    except Exception as e: # Catches InvalidTag from AESGCM if decryption fails
        print(f"[✗] AES-GCM decryption FAILED: {e}")
else:
    print("[✗] Signature verification failed (example using ML-DSA). Message rejected.")

print("-" * 30)