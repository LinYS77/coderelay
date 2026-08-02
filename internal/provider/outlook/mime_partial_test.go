package outlook

import (
	"strings"
	"testing"
)

func TestParseMIMEWithPartialRetainsCompletedText(t *testing.T) {
	raw := "Content-Type: multipart/alternative; boundary=b\r\n\r\n--b\r\nContent-Type: text/plain\r\n\r\nYour code is 123456\r\n--b\r\nContent-Type: text/html\r\n\r\n<p>incomplete"
	_, _, text, _, err := parseMIMEWithPartial([]byte(raw), true)
	if err != nil || !strings.Contains(text, "123456") {
		t.Fatalf("partial MIME = text %q err %v", text, err)
	}
}
