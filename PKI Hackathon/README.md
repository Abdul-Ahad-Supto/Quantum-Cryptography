# PQC Secure Message Demo: FIPS 203, 204 & 205 in Python

This Python script demonstrates a secure message exchange protocol combining Post-Quantum Cryptography (PQC) algorithms standardized by NIST:
*   **FIPS 203 (ML-KEM / CRYSTALS-Kyber):** For key encapsulation (confidentiality).
*   **FIPS 204 (ML-DSA / CRYSTALS-Dilithium):** For digital signatures (authenticity and integrity).
*   **FIPS 205 (SLH-DSA / SPHINCS+):** An alternative stateless hash-based digital signature algorithm.

The script simulates an interaction where Alice sends an encrypted and signed message to Bob.

## Features

*   **Key Encapsulation:** Uses ML-KEM (CRYSTALS-Kyber) to establish a shared secret between Alice and Bob.
*   **Symmetric Encryption:** Employs AES-256-GCM to encrypt the actual message using the KEM-derived shared secret.
*   **Digital Signatures:**
    *   Demonstrates signing the encrypted message with ML-DSA (CRYSTALS-Dilithium).
    *   Demonstrates signing the encrypted message with SLH-DSA (SPHINCS+).
*   **Verification:** Shows how Bob verifies the signatures and decrypts the message.
*   **Educational:** Clearly outlines the steps involved in a PQC-secured communication flow.

## Algorithms Used

*   **Key Encapsulation (FIPS 203):**
    *   `ML-KEM-512` (from `pqcrypto.kem.ml_kem_512`)
*   **Digital Signature (FIPS 204):**
    *   `ML-DSA-87` (from `pqcrypto.sign.ml_dsa_87`) - Note: The script uses `ml_dsa_87`, not `_44` as a comment previously indicated.
*   **Digital Signature (FIPS 205):**
    *   `SPHINCS+-SHA2-256f-simple` (from `pqcrypto.sign.sphincs_sha2_256f_simple`)
*   **Symmetric Encryption:**
    *   AES-256-GCM (from `cryptography.hazmat.primitives.ciphers.aead.AESGCM`)

## How it Works

The script simulates the following workflow:

**Alice (Sender):**
1.  **Key Generation:**
    *   Generates her own ML-KEM key pair (not used for sending in this specific Alice->Bob flow but good practice for a complete entity).
    *   Generates Bob's ML-KEM key pair (simulating Alice having access to Bob's public KEM key).
    *   Generates her ML-DSA (Dilithium) signing key pair.
    *   Generates her SLH-DSA (SPHINCS+) signing key pair.
2.  **Message Preparation:**
    *   Defines a plaintext message.
3.  **Key Encapsulation (FIPS 203):**
    *   Alice uses Bob's public KEM key (`kem_public_key_bob`) to encapsulate a shared secret. This produces a KEM ciphertext (`kem_ciphertext_for_bob`) and the `shared_secret_alice`.
4.  **Symmetric Encryption (AES-GCM):**
    *   The `shared_secret_alice` is used as the key for AES-256-GCM.
    *   Alice encrypts her plaintext message using AES-GCM with a unique nonce, producing `ciphertext_aes`.
5.  **Digital Signing (FIPS 204 & FIPS 205):**
    *   Alice signs the `ciphertext_aes` using her ML-DSA private key, producing `mldsa_signature`.
    *   Alice also signs the `ciphertext_aes` using her SLH-DSA private key, producing `slhdsa_signature`.
    *   *(Note: In a real protocol, typically only one signature scheme would be used per message, or a hybrid signature structure might be employed. Both are shown here for demonstration.)*

**Bob (Receiver):**
1.  **Receives Data:** Bob (conceptually) receives:
    *   `kem_ciphertext_for_bob`
    *   `nonce` (for AES-GCM)
    *   `ciphertext_aes`
    *   `mldsa_signature` (and Alice's ML-DSA public key)
    *   `slhdsa_signature` (and Alice's SLH-DSA public key)
2.  **Signature Verification (FIPS 204 & FIPS 205):**
    *   Bob verifies the `mldsa_signature` against `ciphertext_aes` using Alice's ML-DSA public key.
    *   Bob verifies the `slhdsa_signature` against `ciphertext_aes` using Alice's SLH-DSA public key.
    *   If verification for the intended scheme fails, the message is rejected. The script proceeds if ML-DSA verification passes.
3.  **Key Decapsulation (FIPS 203):**
    *   Bob uses his private KEM key (`kem_secret_key_bob`) and the received `kem_ciphertext_for_bob` to decapsulate and retrieve the same shared secret (`shared_secret_bob`).
4.  **Symmetric Decryption (AES-GCM):**
    *   Bob uses the `shared_secret_bob` and the received `nonce` to decrypt `ciphertext_aes` and recover the original plaintext message.

## Prerequisites

*   Python 3.x
*   Required Python packages:
    *   `pqcrypto`
    *   `cryptography`

You can install them using pip:
```bash
pip install pqcrypto cryptography
```