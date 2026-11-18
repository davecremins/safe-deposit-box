package keymgt

import (
	"bytes"
	"testing"
)

// fastParams keeps tests quick while staying within the validated bounds.
var fastParams = KDFParams{Time: 1, Memory: minMemory, Threads: 1}

func TestDeriveKeyIsDeterministic(t *testing.T) {
	salt, err := NewSalt()
	if err != nil {
		t.Fatal(err)
	}
	k1, err := DeriveKey([]byte("correct horse"), salt, fastParams)
	if err != nil {
		t.Fatal(err)
	}
	k2, _ := DeriveKey([]byte("correct horse"), salt, fastParams)
	if !bytes.Equal(k1, k2) {
		t.Error("same passphrase and salt produced different keys")
	}
	if len(k1) != DerivedKeySize {
		t.Errorf("expected %d byte key, got %d", DerivedKeySize, len(k1))
	}
}

func TestDeriveKeyDependsOnPassphraseAndSalt(t *testing.T) {
	salt1, _ := NewSalt()
	salt2, _ := NewSalt()
	base, _ := DeriveKey([]byte("pass"), salt1, fastParams)
	otherPass, _ := DeriveKey([]byte("pass2"), salt1, fastParams)
	otherSalt, _ := DeriveKey([]byte("pass"), salt2, fastParams)
	if bytes.Equal(base, otherPass) {
		t.Error("different passphrases produced the same key")
	}
	if bytes.Equal(base, otherSalt) {
		t.Error("different salts produced the same key")
	}
}

func TestDeriveKeyRejectsBadInput(t *testing.T) {
	salt, _ := NewSalt()
	cases := map[string]struct {
		pass []byte
		salt []byte
		p    KDFParams
	}{
		"empty passphrase": {nil, salt, fastParams},
		"short salt":       {[]byte("x"), salt[:8], fastParams},
		"zero time":        {[]byte("x"), salt, KDFParams{0, minMemory, 1}},
		"huge time":        {[]byte("x"), salt, KDFParams{maxTime + 1, minMemory, 1}},
		"tiny memory":      {[]byte("x"), salt, KDFParams{1, minMemory - 1, 1}},
		"huge memory":      {[]byte("x"), salt, KDFParams{1, maxMemory + 1, 1}},
		"zero threads":     {[]byte("x"), salt, KDFParams{1, minMemory, 0}},
		"too many threads": {[]byte("x"), salt, KDFParams{1, minMemory, maxThreads + 1}},
	}
	for name, c := range cases {
		if _, err := DeriveKey(c.pass, c.salt, c.p); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
}

func TestDefaultParamsAreValid(t *testing.T) {
	if err := DefaultKDFParams.Validate(); err != nil {
		t.Error(err)
	}
}

func TestWipe(t *testing.T) {
	b := []byte{1, 2, 3}
	Wipe(b)
	if !bytes.Equal(b, []byte{0, 0, 0}) {
		t.Error("buffer not zeroed")
	}
}
