package provider

import (
	"encoding/base64"
	"encoding/json"
	"fmt"

	"revika/internal/cap"
	"revika/internal/device"
)

// deviceAuthJSON is the on-disk (<workspace>/devices.json) and on-wire (DHT
// namespace revika-devices) shape of a device-authorization record. Byte fields
// render as base64 (JSON has no byte-string type); it mirrors rootPointerJSON /
// fullRootJSON so every revika record shares one codec style.
type deviceAuthJSON struct {
	Owner   string           `json:"owner"` // base64 Ed25519 owner (master) pubkey
	Seq     uint64           `json:"seq"`
	Members []deviceMemberJSON `json:"members"`
	Sig     string           `json:"sig"` // base64 Ed25519 signature
}

type deviceMemberJSON struct {
	ID    string `json:"id"`  // hex device ID (SHA-256 of pub)
	Pub   string `json:"pub"` // base64 ML-KEM public key
	Label string `json:"label,omitempty"`
	Added uint64 `json:"added,omitempty"`
}

// EncodeDeviceAuth renders a device.Auth as canonical JSON. It preserves the
// record's member order; callers that need the signable canonical form rely on
// device.Auth's own sort, not this codec.
func EncodeDeviceAuth(a device.Auth) ([]byte, error) {
	ja := deviceAuthJSON{
		Owner: base64.StdEncoding.EncodeToString(a.Owner[:]),
		Seq:   a.Seq,
		Sig:   base64.StdEncoding.EncodeToString(a.Sig),
	}
	for _, m := range a.Members {
		ja.Members = append(ja.Members, deviceMemberJSON{
			ID:    m.ID.String(),
			Pub:   base64.StdEncoding.EncodeToString(m.Pub[:]),
			Label: m.Label,
			Added: m.Added,
		})
	}
	return json.MarshalIndent(ja, "", "  ")
}

// DecodeDeviceAuth reverses EncodeDeviceAuth. It does not verify the signature;
// callers do (device.Auth.Verify, which also re-derives each member ID from its
// key, so a codec-level ID is a display convenience only).
func DecodeDeviceAuth(data []byte) (device.Auth, error) {
	var ja deviceAuthJSON
	if err := json.Unmarshal(data, &ja); err != nil {
		return device.Auth{}, fmt.Errorf("provider: parse device-auth record: %w", err)
	}
	owner, err := base64.StdEncoding.DecodeString(ja.Owner)
	if err != nil || len(owner) != len(cap.SignPubKey{}) {
		return device.Auth{}, fmt.Errorf("provider: device-auth record has a malformed owner key")
	}
	sig, err := base64.StdEncoding.DecodeString(ja.Sig)
	if err != nil {
		return device.Auth{}, fmt.Errorf("provider: device-auth record has a malformed signature")
	}
	a := device.Auth{Seq: ja.Seq, Sig: sig}
	copy(a.Owner[:], owner)
	for _, jm := range ja.Members {
		pub, perr := cap.ParsePublicKey(jm.Pub)
		if perr != nil {
			return device.Auth{}, fmt.Errorf("provider: device-auth member has a malformed key: %w", perr)
		}
		a.Members = append(a.Members, device.Member{
			ID:    device.NewID(pub), // derived, never trusted from the wire
			Pub:   pub,
			Label: jm.Label,
			Added: jm.Added,
		})
	}
	return a, nil
}
