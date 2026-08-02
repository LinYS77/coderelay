package outlook

import "testing"

func FuzzCredentialParser(f *testing.F) {
	f.Add([]byte("user@example.com----password----550e8400-e29b-41d4-a716-446655440000----" + string(testRefreshToken('x'))))
	f.Add([]byte("garbage"))
	f.Fuzz(func(t *testing.T, input []byte) {
		credential, err := ParseCredential(input)
		if err == nil {
			credential.Destroy()
		}
	})
}

func FuzzMIME(f *testing.F) {
	f.Add([]byte("Subject: code\r\nContent-Type: text/plain\r\n\r\n123456"))
	f.Add([]byte("not mime"))
	f.Fuzz(func(t *testing.T, input []byte) {
		_, _, _, _, _ = parseMIME(input)
	})
}
