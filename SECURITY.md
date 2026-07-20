# Security policy

Security fixes target the latest release and `main`.

Do not publish authentication bypasses, unsafe PAM behavior, privilege-boundary problems, or rollback failures in a public issue. Use GitHub private vulnerability reporting when available. Otherwise, open a minimal issue requesting a private channel without including exploit details.

Include the affected version, macOS version and architecture, the smallest safe reproduction, and the expected and observed PAM result. Remove usernames, local paths, authentication prompts, credentials, signing material, and other private data.

The project never needs a password, token, signing identity, private key, or remote access to investigate a report. The CLI does not receive authentication results or credentials; after setup, Apple’s built-in `pam_tid.so` communicates directly with `sudo`.
