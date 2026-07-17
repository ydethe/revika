package cap

import (
	"bytes"
	"errors"
	"testing"
)

func TestWrapUnwrapRoundTrip(t *testing.T) {
	priv, pub, err := GenerateIdentity()
	if err != nil {
		t.Fatalf("GenerateIdentity: %v", err)
	}
	msg := []byte("a read-capability: manifest location + keys")

	sealed, err := Wrap(pub, msg)
	if err != nil {
		t.Fatalf("Wrap: %v", err)
	}
	if bytes.Equal(sealed, msg) {
		t.Fatal("sealed cap equals plaintext")
	}

	got, err := Unwrap(priv, pub, sealed)
	if err != nil {
		t.Fatalf("Unwrap: %v", err)
	}
	if !bytes.Equal(got, msg) {
		t.Fatalf("round trip = %q, want %q", got, msg)
	}
}

func TestWrapIsNondeterministic(t *testing.T) {
	_, pub, _ := GenerateIdentity()
	a, _ := Wrap(pub, []byte("same"))
	b, _ := Wrap(pub, []byte("same"))
	if bytes.Equal(a, b) {
		t.Fatal("wrapping identical plaintext twice produced identical output")
	}
}

func TestUnwrapWrongKeyFails(t *testing.T) {
	_, pub, _ := GenerateIdentity()
	wrongPriv, wrongPub, _ := GenerateIdentity()

	sealed, err := Wrap(pub, []byte("secret"))
	if err != nil {
		t.Fatal(err)
	}
	// Correct pub, wrong priv.
	if _, err := Unwrap(wrongPriv, pub, sealed); !errors.Is(err, ErrUnwrap) {
		t.Fatalf("wrong priv: err = %v, want ErrUnwrap", err)
	}
	// Entirely different recipient.
	if _, err := Unwrap(wrongPriv, wrongPub, sealed); !errors.Is(err, ErrUnwrap) {
		t.Fatalf("wrong recipient: err = %v, want ErrUnwrap", err)
	}
}

func TestUnwrapTamperedFails(t *testing.T) {
	priv, pub, _ := GenerateIdentity()
	sealed, err := Wrap(pub, []byte("integrity matters"))
	if err != nil {
		t.Fatal(err)
	}
	sealed[len(sealed)-1] ^= 0xff // flip a byte in the tag/ciphertext
	if _, err := Unwrap(priv, pub, sealed); !errors.Is(err, ErrUnwrap) {
		t.Fatalf("tampered: err = %v, want ErrUnwrap", err)
	}
}

func TestKeyTextRoundTrip(t *testing.T) {
	priv, pub, _ := GenerateIdentity()

	gotPub, err := ParsePublicKey(pub.String())
	if err != nil || gotPub != pub {
		t.Fatalf("public key round trip: %v, %v (want %v)", gotPub, err, pub)
	}
	gotPriv, err := ParsePrivateKey(priv.String())
	if err != nil || gotPriv != priv {
		t.Fatalf("private key round trip: %v, %v", gotPriv, err)
	}

	if _, err := ParsePublicKey("not base64!!!"); err == nil {
		t.Fatal("ParsePublicKey accepted invalid base64")
	}
	if _, err := ParsePublicKey("YWJj"); err == nil { // "abc" -> 3 bytes, wrong length
		t.Fatal("ParsePublicKey accepted wrong-length key")
	}
}

func TestPrivateKeyPublicDerivation(t *testing.T) {
	priv, pub, _ := GenerateIdentity()
	derived, err := priv.Public()
	if err != nil {
		t.Fatalf("Public: %v", err)
	}
	if derived != pub {
		t.Fatalf("derived public %v != generated %v", derived, pub)
	}
	// And a cap wrapped to pub unwraps using only the private key's derived pub.
	sealed, _ := Wrap(pub, []byte("derive me"))
	if _, err := Unwrap(priv, derived, sealed); err != nil {
		t.Fatalf("unwrap with derived pub: %v", err)
	}
}
