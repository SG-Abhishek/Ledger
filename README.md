# Ledger — Personal Balances

A secure, private personal finance ledger for tracking money lent and borrowed between friends, family, and peers.

## Security Architecture

- **Zero Unencrypted Persistence:** No transactions, balances, or contact names are ever saved unencrypted to disk or `localStorage`.
- **AES-256-GCM Vault:** Database payloads are encrypted with authenticated AES-GCM derived from a user-selected PIN via 250,000 PBKDF2-SHA256 iterations.
- **Hardware-Backed Biometrics:** Biometric authentication uses the **WebAuthn PRF (Pseudo-Random Function) extension** to securely unwrap the master AES key without storing unencrypted cache files.
- **Background Auto-Lock:** Monitors device sleep and app switching using differential timestamp tracking, reliably locking the vault even when OS-level power saving halts JavaScript timers.
- **Integer Minor Unit Precision:** All financial calculations operate on exact integer minor units (paise/cents) to eliminate floating-point rounding drift.

## Setup & Running

1. Host over HTTPS or serve locally:
   ```bash
   npx serve .