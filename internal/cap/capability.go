package cap

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"

	"github.com/revika/revika/internal/crypto"
)

const FormatVersion uint8 = 1

var (
	ErrInvalidCapability = errors.New("capability: invalid capability")
	ErrUnauthorized      = errors.New("capability: permission denied")
	ErrExpired           = errors.New("capability: expired")
)

type Permission uint32

const (
	Read Permission = 1 << iota
	Write
	Delete
)

func (permissions Permission) Has(required Permission) bool {
	return permissions&required == required
}

type Capability struct {
	Version     uint8      `json:"version"`
	ID          string     `json:"id"`
	Scope       string     `json:"scope"`
	Permissions Permission `json:"permissions"`
	Issuer      []byte     `json:"issuer"`
	Recipient   []byte     `json:"recipient,omitempty"`
	ExpiresAt   int64      `json:"expires_at,omitempty"`
	Key         []byte     `json:"key,omitempty"`
	Signature   []byte     `json:"signature"`
}

func New(scope string, permissions Permission, recipient, key []byte, expiresAt time.Time) Capability {
	capability := Capability{
		Version:     FormatVersion,
		Scope:       scope,
		Permissions: permissions,
		Recipient:   append([]byte(nil), recipient...),
		Key:         append([]byte(nil), key...),
	}
	if !expiresAt.IsZero() {
		capability.ExpiresAt = expiresAt.UnixNano()
	}
	return capability
}

func (capability *Capability) Sign(signer crypto.Signer) error {
	capability.Version = FormatVersion
	capability.Issuer = signer.Public()
	capability.Signature = nil
	payload, err := capability.payload()
	if err != nil {
		return err
	}
	signature, err := signer.Sign(payload)
	if err != nil {
		return err
	}
	capability.Signature = signature
	capability.ID = digest(payload)
	return nil
}

func (capability Capability) Verify(now time.Time) error {
	if capability.Version != FormatVersion || capability.Scope == "" || capability.Permissions == 0 || len(capability.Issuer) == 0 || len(capability.Signature) == 0 {
		return ErrInvalidCapability
	}
	if capability.ExpiresAt != 0 && now.UnixNano() >= capability.ExpiresAt {
		return ErrExpired
	}
	payload, err := capability.payload()
	if err != nil {
		return err
	}
	if digest(payload) != capability.ID {
		return ErrInvalidCapability
	}
	return crypto.VerifyEd25519(capability.Issuer, payload, capability.Signature)
}

func (capability Capability) Authorize(scope string, permission Permission, now time.Time) error {
	if err := capability.Verify(now); err != nil {
		return err
	}
	if capability.Scope != scope || !capability.Permissions.Has(permission) {
		return ErrUnauthorized
	}
	return nil
}

func (capability Capability) MarshalBinary() ([]byte, error) {
	if err := capability.Verify(time.Now()); err != nil {
		return nil, err
	}
	return json.Marshal(capability)
}

func Unmarshal(data []byte) (Capability, error) {
	var capability Capability
	if err := json.Unmarshal(data, &capability); err != nil {
		return Capability{}, ErrInvalidCapability
	}
	if err := capability.Verify(time.Now()); err != nil {
		return Capability{}, err
	}
	return capability, nil
}

func (capability Capability) payload() ([]byte, error) {
	unsigned := capability
	unsigned.ID = ""
	unsigned.Signature = nil
	return json.Marshal(unsigned)
}

func digest(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func (capability Capability) EqualRecipient(recipient []byte) bool {
	return bytes.Equal(capability.Recipient, recipient)
}
