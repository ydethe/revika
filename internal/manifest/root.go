package manifest

import (
	"bytes"
	"encoding/binary"
	"fmt"

	"revika/internal/cap"
)

// RootPointer is the one mutable anchor per User (Architecture §4): a signed
// record mapping the User's Ed25519 owner identity to the cap of their current
// root directory, carrying a monotonic sequence number and a timestamp. Every
// content blob below it is immutable and content-addressed; only this pointer
// changes, and only its Seq advances. Publish it IPNS-style (DHT keyed by the
// owner pubkey, and/or on chosen nodes, §6); readers verify the signature and
// take the highest Seq, so a node cannot serve a rolled-back root.
//
// Single-writer-per-key holds by construction: only the holder of the signing
// key can advance Seq. Multi-device writes for one User reconcile in the sync
// layer via Seq + conflict copies (§3.7).
//
// Defence controls (security/Defence.md; primitive P3 in security/frameworks.md):
//
//	D3-MAN (Message Authentication) — Ed25519 binds the root cap + seq to the owner.
//	AU-10  (Non-repudiation)        — the signature proves who advanced the pointer.
//	SC-8   (Transmission Integrity)  — a lower Seq or bad signature is rejected (anti-rollback).
type RootPointer struct {
	Owner  cap.SignPubKey
	Root   ReadCap
	Seq    uint64
	TimeNS int64
	Sig    []byte
}

// signingPayload is the canonical byte string signed and verified: a domain
// separator, then owner || seq || time || the canonical cap bytes. The domain
// tag keeps a root-pointer signature from ever being mistaken for some other
// Ed25519 message the same key signs (auth tokens, repair grants).
func (r RootPointer) signingPayload() ([]byte, error) {
	capBytes, err := r.Root.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("manifest: marshal root cap: %w", err)
	}
	var b bytes.Buffer
	b.WriteString("revika/root/1.0.0\x00")
	b.Write(r.Owner[:])
	var u [8]byte
	binary.BigEndian.PutUint64(u[:], r.Seq)
	b.Write(u[:])
	binary.BigEndian.PutUint64(u[:], uint64(r.TimeNS))
	b.Write(u[:])
	b.Write(capBytes)
	return b.Bytes(), nil
}

// SignRoot builds and signs a RootPointer advancing the User's namespace to root
// at sequence seq (timeNS is a caller-supplied Unix-nanosecond timestamp; this
// package takes no clock so it stays deterministic and testable). The signer's
// public key becomes the record's Owner.
func SignRoot(k cap.SignKey, root ReadCap, seq uint64, timeNS int64) (RootPointer, error) {
	r := RootPointer{Owner: k.Public(), Root: root, Seq: seq, TimeNS: timeNS}
	payload, err := r.signingPayload()
	if err != nil {
		return RootPointer{}, err
	}
	r.Sig = k.Sign(payload)
	return r, nil
}

// Verify reports whether r carries a valid signature by its own Owner. A reader
// still compares Seq across the records it sees and keeps the highest verified
// one (anti-rollback); Verify only attests that this record is authentic.
func (r RootPointer) Verify() bool {
	payload, err := r.signingPayload()
	if err != nil {
		return false
	}
	return r.Owner.Verify(payload, r.Sig)
}
