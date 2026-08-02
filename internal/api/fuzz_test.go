package api

import "testing"

func FuzzDecodeRootObject(f *testing.F) {
	f.Add([]byte(`{"type":"totp","credential":"ABC"}`))
	f.Add([]byte(`{"type":"totp","type":"flysms"}`))
	f.Add([]byte(`[]`))
	f.Fuzz(func(t *testing.T, input []byte) {
		if len(input) > 128<<10 {
			t.Skip()
		}
		fields, _ := decodeRootObject(input)
		clearRawFields(fields)
	})
}
