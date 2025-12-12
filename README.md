# Ransomware program
This repository contains a minimal, non-operational ransomware prototype. The code is not intended to function as a real piece of malicious software, it is intentionally simplified so that it can serve as a conceptual bridge between theory and practice.

**Disclaimer:**  
This repository is intended **for educational use only**.

The flow begins with a symmetric key, usually something like an AES key, generated locally on the victim machine. Symmetric cryptography relies on a single secret used both to encrypt and decrypt, which makes it fast and well-suited for transforming large volumes of data. The program scans the chosen directory and applies the symmetric algorithm to each target file, replacing the readable content with its encrypted form. This is the stage that illustrates the heart of ransomware logic: transforming accessible data into unreadable ciphertext.

A symmetric key alone would be trivial to misuse if it remained stored in plaintext on the machine, so real ransomware families wrap that key inside a second cryptographic layer. This is represented by taking the locally generated symmetric key and encrypting it with a public key belonging to the “attacker.” Public-key cryptography uses a keypair: the public half can lock information, while only the corresponding private key can unlock it. Because only the private key holder can reverse the operation, the encrypted symmetric key becomes inaccessible to the victim. Even if someone understands the entire structure of the prototype, the essential point remains: only the possessor of the private key could theoretically restore the original symmetric key, and consequently the files.
