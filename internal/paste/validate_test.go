package paste

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

// adata builds the v2 header; each cipher parameter can be overridden.
func adata(iv, salt string, iter int, mode string, flags string) string {
	return fmt.Sprintf(`[[%q,%q,%d,256,128,"aes",%q,"zlib"],"markdown",%s]`, iv, salt, iter, mode, flags)
}

const (
	iv12  = "AAAAAAAAAAAAAAAA"         // 12 bytes, 16 chars
	iv16  = "AAAAAAAAAAAAAAAAAAAAAAAA" // 16 bytes, 24 chars
	salt8 = "AAAAAAAAAAA="             // 8 bytes, 12 chars
	ok    = "AAAA"
	noBrn = "0,0"
)

func in(v float64, ad, ct string) *Input {
	return &Input{V: v, CT: ct, AData: json.RawMessage(ad)}
}

func TestValidate(t *testing.T) {
	cases := []struct {
		name  string
		in    *Input
		burn  bool
		valid bool
	}{
		{"ok burn int", in(2, adata(iv12, salt8, 100000, "gcm", "0,1"), ok), true, true},
		{"ok bool flags", in(2, adata(iv12, salt8, 100000, "gcm", "false,false"), ok), false, true},
		{"v 3 accepted like PrivateBin", in(3, adata(iv12, salt8, 100000, "gcm", noBrn), ok), false, true},
		{"16 byte IV (PrivateBin JS)", in(2, adata(iv16, salt8, 100000, "gcm", noBrn), ok), false, true},
		{"short IV", in(2, adata("AAAA", salt8, 100000, "gcm", noBrn), ok), false, true},
		{"mode ctr", in(2, adata(iv12, salt8, 100000, "ctr", noBrn), ok), false, true},
		{"mode cbc", in(2, adata(iv12, salt8, 100000, "cbc", noBrn), ok), false, true},
		{"iterations just above minimum", in(2, adata(iv12, salt8, minIterations+1, "gcm", noBrn), ok), false, true},
		{"iterations at ceiling", in(2, adata(iv12, salt8, maxIterations, "gcm", noBrn), ok), false, true},
		{"extra cipher params", in(2, strings.Replace(adata(iv12, salt8, 100000, "gcm", noBrn), `"zlib"]`, `"zlib",1]`, 1), ok), false, true},

		{"v 1", in(1, adata(iv12, salt8, 100000, "gcm", noBrn), ok), false, false},
		{"empty ct", in(2, adata(iv12, salt8, 100000, "gcm", noBrn), ""), false, false},
		{"bad ct", in(2, adata(iv12, salt8, 100000, "gcm", noBrn), "!!"), false, false},
		{"IV too long", in(2, adata(iv16+"AAAA", salt8, 100000, "gcm", noBrn), ok), false, false},
		{"IV not base64", in(2, adata("!!!!", salt8, 100000, "gcm", noBrn), ok), false, false},
		{"salt too long", in(2, adata(iv12, "AAAAAAAAAAAAAAAA", 100000, "gcm", noBrn), ok), false, false},
		{"iterations at minimum", in(2, adata(iv12, salt8, minIterations, "gcm", noBrn), ok), false, false},
		{"iterations above ceiling", in(2, adata(iv12, salt8, maxIterations+1, "gcm", noBrn), ok), false, false},
		{"unknown mode", in(2, adata(iv12, salt8, 100000, "xts", noBrn), ok), false, false},
		{"bad format", in(2, strings.Replace(adata(iv12, salt8, 100000, "gcm", noBrn), "markdown", "html", 1), ok), false, false},
		{"bad burn flag", in(2, adata(iv12, salt8, 100000, "gcm", "0,2"), ok), false, false},
		{"too few cipher params", in(2, `[["AAAA","AAAA",100000,256,128,"aes","gcm"],"plaintext",0,0]`, ok), false, false},
		{"adata not array", in(2, `{}`, ok), false, false},
	}
	for _, c := range cases {
		burn, err := c.in.Validate()
		if (err == nil) != c.valid || burn != c.burn {
			t.Errorf("%s: burn=%v err=%v", c.name, burn, err)
		}
	}
}
