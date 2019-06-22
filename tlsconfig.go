package xautoserver

type TLSConfig struct {
	// path to the tls files
	Cert	string
	Key		string
}

// TODO only public fields
func (c *TLSConfig) clone() *TLSConfig {
	cc := *c
	return &cc
}