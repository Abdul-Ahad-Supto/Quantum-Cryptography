# PKI Certificate Chain Validator

This Python script demonstrates a fundamental aspect of Public Key Infrastructure (PKI): **validating a digital certificate's trust chain**. It specifically focuses on how to traverse this chain by:

1.  **Decoding PEM-encoded certificates.**
2.  **Extracting issuer information** from a given certificate.
3.  **Locating the issuer's certificate** based on this information.
4.  Repeating the process until a self-signed Root Certificate Authority (CA) is reached.

This process is a foundational step in "PKI-enabled linting," as verifying the chain of trust is crucial before performing more detailed structural and content analysis of individual certificates. The example is tailored to potentially work with certificates issued by a Bangladeshi Certificate Authority (CA).

## Problem Context: PKI-Enabled Linting

Linting in PKI involves analyzing ASN.1-encoded documents like X.509 digital certificates to ensure they are valid, conform to specifications (e.g., RFC 5280), and adhere to best practices. A critical first step in this validation is verifying the certificate's issuance path – the chain of trust. If a certificate isn't issued by a trusted entity, or if the chain is broken, then further linting of its content is often moot.

This script addresses part (a) of a larger problem:
> a) Write code to use PKI-enabled lint to check digital certificate issued by Bangladeshi CA whether it is valid.

While this script doesn't perform exhaustive linting (like checking key usage, extensions, or algorithm strength), it validates the **existence and linkability of the trust chain**.

## How it Works: Traversing the Trust Chain

The script operates by iteratively stepping up the certificate chain:

1.  **Start with an End-Entity Certificate:**
    *   The process begins with a specific certificate file (e.g., `mir.pem`).
    *   This file is opened, its content is read, and `cryptography.x509.load_pem_x509_certificate()` is used to parse the PEM-encoded X.509 certificate data into a Python object.

2.  **Extract Subject and Issuer Information:**
    *   From the parsed certificate object, the script extracts:
        *   `cert.subject`: Information about the entity this certificate belongs to.
        *   `cert.issuer`: Information about the CA that issued this certificate.
    *   A helper function `get_cn(name)` is used to retrieve the Common Name (CN) from both the subject and issuer distinguished names. The CN is often used to identify CAs.

3.  **Check for Self-Signed (Root CA):**
    *   If the Subject CN is identical to the Issuer CN, the certificate is considered self-signed. This typically signifies a Root CA, which is the anchor of trust. The chain traversal stops here.

4.  **Identify the Next Certificate in the Chain:**
    *   If the certificate is not self-signed, the Issuer CN tells us who *should* have signed this certificate.
    *   The script then **formats the Issuer CN into an expected filename** (e.g., "My Intermediate CA" becomes `My_Intermediate_CA.pem`) using the `format_filename(cn)` function. This convention is key: *the script assumes the issuer's certificate file is named after the issuer's Common Name*.

5.  **Locate and Load the Issuer's Certificate:**
    *   The script attempts to find and load the file corresponding to the Issuer CN in the specified `base_path` (current directory by default).
    *   If the file exists, it's loaded, and this new certificate becomes the "current certificate" for the next iteration, repeating from step 2.

6.  **Handling Missing Certificates / End of Chain:**
    *   If the expected issuer certificate file is not found:
        *   The script has a specific fallback message: `🔐 Root CA Bangladesh 2020\n   Self-signed Root Certificate ✅ \n   Provided by Bangladesh CA ✅`. This suggests an assumption that if an intermediate CA certificate isn't found locally, the chain might terminate with this known Bangladeshi Root CA. **Note:** In a more robust system, you'd typically have a local trust store or fetch missing intermediates from AIA extensions.
        *   The chain traversal stops.
    *   If any other error occurs while loading a certificate, the process also halts.

The output clearly shows each certificate's subject and its issuer, visually representing the chain:
`Subject A`
   `issued by ➝ Issuer B`

`Subject B (was Issuer B)`
   `issued by ➝ Issuer C`

...and so on, until a root is found.

## Prerequisites

*   Python 3.x
*   The `cryptography` library:
    ```bash
    pip install cryptography
    ```
*   Certificate files:
    *   An initial certificate file (e.g., `mir.pem`).
    *   Subsequent issuer certificates, named according to their Common Name (spaces replaced with underscores, e.g., `Issuer_CN.pem`), placed in the same directory.

## File Structure Example

For the script to successfully traverse a chain, your files might look like this: