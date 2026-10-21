package paste

import (
	"encoding/json"
	"testing"
)

func input(t *testing.T, adata, ct string) *Input {
	t.Helper()
	in := &Input{V: 2, CT: ct, AData: json.RawMessage(adata)}
	return in
}

func TestValidate(t *testing.T) {
	cases := []struct {
		name  string
		in    *Input
		burn  bool
		valid bool
	}{
		{"ok int burn", input(t, `[["AAAAAAAAAAAAAAAA","AAAAAAAAAAA=",100000,256,128,"aes","gcm","zlib"],"markdown",0,1]`, "AAAA"), true, true},
		{"ok bool", input(t, `[["AAAAAAAAAAAAAAAA","AAAAAAAAAAA=",100000,256,128,"aes","gcm","none"],"plaintext",false,false]`, "AAAA"), false, true},
		{"bad version", &Input{V: 1, CT: "AAAA", AData: json.RawMessage(`[]`)}, false, false},
		{"empty ct", input(t, `[]`, ""), false, false},
		{"bad format", input(t, `[["AAAAAAAAAAAAAAAA","AAAAAAAAAAA=",100000,256,128,"aes","gcm","none"],"html",0,0]`, "AAAA"), false, false},
		{"bad iv len", input(t, `[["AAAA","AAAAAAAAAAA=",100000,256,128,"aes","gcm","none"],"plaintext",0,0]`, "AAAA"), false, false},
		{"bad mode", input(t, `[["AAAAAAAAAAAAAAAA","AAAAAAAAAAA=",100000,256,128,"aes","cbc","none"],"plaintext",0,0]`, "AAAA"), false, false},
		{"bad burn", input(t, `[["AAAAAAAAAAAAAAAA","AAAAAAAAAAA=",100000,256,128,"aes","gcm","none"],"plaintext",0,2]`, "AAAA"), false, false},
		{"bad ct", input(t, `[["AAAAAAAAAAAAAAAA","AAAAAAAAAAA=",100000,256,128,"aes","gcm","none"],"plaintext",0,0]`, "!!"), false, false},
	}
	for _, c := range cases {
		burn, err := c.in.Validate()
		if (err == nil) != c.valid || burn != c.burn {
			t.Errorf("%s: burn=%v err=%v", c.name, burn, err)
		}
	}
}
