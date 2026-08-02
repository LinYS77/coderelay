package outlook

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/LinYS77/coderelay/internal/domain"
)

func TestParseMIMEEnforcesNestedDepth(t *testing.T) {
	allowed := nestedMIME(10)
	_, _, text, _, err := parseMIME([]byte(allowed))
	if err != nil || !strings.Contains(text, "123456") {
		t.Fatalf("depth 10: text=%q err=%v", text, err)
	}
	_, _, _, _, err = parseMIME([]byte(nestedMIME(11)))
	if !errors.Is(err, domain.ErrUpstreamSchemaChanged) {
		t.Fatalf("depth 11 error = %v", err)
	}
}

func TestParseMIMESkipsInlineFilename(t *testing.T) {
	raw := "Content-Type: multipart/mixed; boundary=b\r\n\r\n" +
		"--b\r\nContent-Type: text/plain; name=secret.txt\r\nContent-Disposition: inline; filename=secret.txt\r\n\r\nattachment 111111\r\n" +
		"--b\r\nContent-Type: text/plain\r\n\r\nbody 222222\r\n--b--\r\n"
	_, _, text, _, err := parseMIME([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(text, "111111") || !strings.Contains(text, "222222") {
		t.Fatalf("text = %q", text)
	}
}

func TestParseMIMERejectsMoreThanPartLimit(t *testing.T) {
	var raw strings.Builder
	raw.WriteString("Content-Type: multipart/mixed; boundary=b\r\n\r\n")
	for i := 0; i <= maxMIMEParts; i++ {
		raw.WriteString("--b\r\nContent-Type: text/plain\r\n\r\npart\r\n")
	}
	raw.WriteString("--b--\r\n")
	_, _, _, _, err := parseMIME([]byte(raw.String()))
	if !errors.Is(err, domain.ErrUpstreamSchemaChanged) {
		t.Fatalf("error = %v", err)
	}
}

func nestedMIME(depth int) string {
	value := "Content-Type: text/plain\r\n\r\ncode 123456\r\n"
	for level := 0; level < depth; level++ {
		boundary := fmt.Sprintf("b%d", level)
		value = "Content-Type: multipart/mixed; boundary=" + boundary + "\r\n\r\n--" + boundary + "\r\n" + value + "--" + boundary + "--\r\n"
	}
	return value
}
