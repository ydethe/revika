package main

// passphrase.go provides the process-wide passphrase for at-rest encryption of
// workspace secrets (private key files and root.json). The passphrase is
// sourced from the REVIKA_PASSPHRASE environment variable — set it in your
// shell profile or as a CI secret. When the variable is absent the workspace
// is unencrypted (legacy mode, backward-compatible with existing workspaces).
//
// All reads are lazy and cached: the first call to workspacePassphrase()
// acquires the value; subsequent calls in the same process return it
// immediately. Because revika-ctl is a short-lived process, caching the secret
// in a process-scoped variable is safe — it is never written to disk and
// disappears when the process exits.

import (
    "os"
    "sync"
)

// passphraseEnv is the environment variable name.
const passphraseEnv = "REVIKA_PASSPHRASE"

var (
    ppOnce  sync.Once
    ppValue []byte // nil = not set (plaintext mode)
)

// workspacePassphrase returns the at-rest passphrase for this process, or nil
// if REVIKA_PASSPHRASE is not set. A nil result means plaintext mode: existing
// unencrypted workspaces continue to work, and new key material is written
// without encryption.
func workspacePassphrase() []byte {
    ppOnce.Do(func() {
        if v := os.Getenv(passphraseEnv); v != "" {
            ppValue = []byte(v)
        }
    })
    return ppValue
}
