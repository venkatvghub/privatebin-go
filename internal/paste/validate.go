package paste

import (
	"encoding/base64"
	"encoding/json"
	"errors"

	"github.com/venkatvghub/privatebin-go/internal/model"
)

// Limits mirror PrivateBin's FormatV2::isValid, so every paste PrivateBin
// accepts is accepted here. PrivateBin has no upper bound on the PBKDF2
// iteration count; maxIterations is the one deliberate deviation. It bounds
// the work a paste can demand from every browser that opens it, and sits well
// above any real client's setting.
const (
	minIterations = 10_000 // PrivateBin refuses this many or fewer
	maxIterations = 10_000_000
	maxIVChars    = 24 // base64 text, so up to a 16-byte IV
	maxSaltChars  = 14
)

var ErrInvalid = errors.New("invalid data")

var formats = map[string]bool{"plaintext": true, "syntaxhighlighting": true, "markdown": true}

// Input is the PrivateBin v2 create/comment request body. PasteID is only set
// on comment requests.
type Input struct {
	PasteID string          `json:"pasteid"`
	V       float64         `json:"v"`
	AData   json.RawMessage `json:"adata"`
	CT      string          `json:"ct"`
	Meta    struct {
		Expire string `json:"expire"`
	} `json:"meta"`
}

// b64 reports whether s is non-empty, strictly valid base64 of at most maxChars.
func b64(s string, maxChars int) bool {
	b, err := base64.StdEncoding.DecodeString(s)
	return err == nil && len(b) > 0 && len(s) <= maxChars
}

// Validate applies PrivateBin's v2 format checks and returns the burn flag.
func (in *Input) Validate() (burn bool, err error) {
	if in.V < 2 || !b64(in.CT, len(in.CT)) {
		return false, ErrInvalid
	}
	var ad []json.RawMessage
	if json.Unmarshal(in.AData, &ad) != nil || len(ad) != 4 {
		return false, ErrInvalid
	}
	var cp []json.RawMessage
	if json.Unmarshal(ad[0], &cp) != nil || len(cp) < 8 {
		return false, ErrInvalid
	}
	var iv, salt, algo, mode, comp string
	var iter, keySize, tagSize int
	if json.Unmarshal(cp[0], &iv) != nil || json.Unmarshal(cp[1], &salt) != nil ||
		json.Unmarshal(cp[2], &iter) != nil || json.Unmarshal(cp[3], &keySize) != nil ||
		json.Unmarshal(cp[4], &tagSize) != nil || json.Unmarshal(cp[5], &algo) != nil ||
		json.Unmarshal(cp[6], &mode) != nil || json.Unmarshal(cp[7], &comp) != nil {
		return false, ErrInvalid
	}
	if !b64(iv, maxIVChars) || !b64(salt, maxSaltChars) ||
		iter <= minIterations || iter > maxIterations ||
		(keySize != 128 && keySize != 192 && keySize != 256) ||
		(tagSize != 64 && tagSize != 96 && tagSize != 128) ||
		algo != "aes" || (mode != "ctr" && mode != "cbc" && mode != "gcm") ||
		(comp != "none" && comp != "zlib") {
		return false, ErrInvalid
	}
	var format string
	if json.Unmarshal(ad[1], &format) != nil || !formats[format] {
		return false, ErrInvalid
	}
	if _, ok := model.ParseFlag(ad[2]); !ok {
		return false, ErrInvalid
	}
	burn, ok := model.ParseFlag(ad[3])
	if !ok {
		return false, ErrInvalid
	}
	return burn, nil
}
