package outlook

import (
	"errors"
	"sync"
)

type xoauth2Client struct {
	email    []byte
	token    []byte
	response []byte
	started  bool
	mu       sync.Mutex
}

func newXOAUTH2Client(email, token []byte) *xoauth2Client {
	return &xoauth2Client{email: email, token: token}
}

func (c *xoauth2Client) Start() (string, []byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.started {
		return "", nil, errors.New("XOAUTH2 client already started")
	}
	c.started = true
	c.response = make([]byte, 0, len(c.email)+len(c.token)+20)
	c.response = append(c.response, "user="...)
	c.response = append(c.response, c.email...)
	c.response = append(c.response, '\x01')
	c.response = append(c.response, "auth=Bearer "...)
	c.response = append(c.response, c.token...)
	c.response = append(c.response, '\x01', '\x01')
	return "XOAUTH2", c.response, nil
}

func (c *xoauth2Client) Next(_ []byte) ([]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return []byte{}, nil
}

func (c *xoauth2Client) Destroy() {
	c.mu.Lock()
	defer c.mu.Unlock()
	clear(c.response)
	c.response = nil
	c.email = nil
	c.token = nil
}
