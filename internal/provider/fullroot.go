package provider

import (
	"encoding/base64"
	"encoding/json"
	"fmt"

	"revika/internal/cap"
	"revika/internal/manifest"
)

// fullRootJSON is the on-disk / on-wire shape of a sealed self-root companion:
// the byte fields render as base64 (JSON has no byte-string type), the seq is a
// plain number. It mirrors rootPointerJSON so the DHT codec stays uniform.
type fullRootJSON struct {
	Owner  string `json:"owner"`           // base64 Ed25519 owner pubkey
	Seq    uint64 `json:"seq"`
	Sealed string `json:"sealed,omitempty"` // base64 ML-KEM-sealed full ReadCap (legacy single-owner)
	// Seals carries one base64 ML-KEM seal per authorized device for the
	// device-scoped companion (Architecture §3.7.2). omitempty keeps a legacy
	// single-owner record byte-identical to before this field existed.
	Seals []string `json:"seals,omitempty"`
	Sig   string   `json:"sig"` // base64 Ed25519 signature
}

// EncodeFullRoot renders a FullRootRecord as the JSON the DHT companion record
// carries. It mirrors EncodeRootPointer so both root records share one codec
// style; the sealed cap is opaque base64 here (only owner devices can open it).
func EncodeFullRoot(r manifest.FullRootRecord) ([]byte, error) {
	jr := fullRootJSON{
		Owner: base64.StdEncoding.EncodeToString(r.Owner[:]),
		Seq:   r.Seq,
		Sig:   base64.StdEncoding.EncodeToString(r.Sig),
	}
	if len(r.Sealed) > 0 {
		jr.Sealed = base64.StdEncoding.EncodeToString(r.Sealed)
	}
	for _, s := range r.Seals {
		jr.Seals = append(jr.Seals, base64.StdEncoding.EncodeToString(s))
	}
	return json.Marshal(jr)
}

// DecodeFullRoot reverses EncodeFullRoot. It does not verify the signature or
// open the seal; callers do (the validator and GetFullRoot).
func DecodeFullRoot(data []byte) (manifest.FullRootRecord, error) {
	var jr fullRootJSON
	if err := json.Unmarshal(data, &jr); err != nil {
		return manifest.FullRootRecord{}, fmt.Errorf("provider: parse full-root record: %w", err)
	}
	owner, err := base64.StdEncoding.DecodeString(jr.Owner)
	if err != nil || len(owner) != len(cap.SignPubKey{}) {
		return manifest.FullRootRecord{}, fmt.Errorf("provider: full-root record has a malformed owner key")
	}
	var sealed []byte
	if jr.Sealed != "" {
		sealed, err = base64.StdEncoding.DecodeString(jr.Sealed)
		if err != nil {
			return manifest.FullRootRecord{}, fmt.Errorf("provider: full-root record has a malformed sealed cap")
		}
	}
	var seals [][]byte
	for _, s := range jr.Seals {
		raw, derr := base64.StdEncoding.DecodeString(s)
		if derr != nil {
			return manifest.FullRootRecord{}, fmt.Errorf("provider: full-root record has a malformed device seal")
		}
		seals = append(seals, raw)
	}
	sig, err := base64.StdEncoding.DecodeString(jr.Sig)
	if err != nil {
		return manifest.FullRootRecord{}, fmt.Errorf("provider: full-root record has a malformed signature")
	}
	r := manifest.FullRootRecord{Seq: jr.Seq, Sealed: sealed, Seals: seals, Sig: sig}
	copy(r.Owner[:], owner)
	return r, nil
}
