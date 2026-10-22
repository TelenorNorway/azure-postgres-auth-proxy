package main

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

const (
	sshKeepAliveInterval = 30 * time.Second
	sshKeepAliveTimeout  = 15 * time.Second
	sshKeyPassphraseEnv  = "SSH_KEY_PASSPHRASE"
)

var errSSHTunnelClosed = errors.New("ssh tunnel is closed")

type sshClientConfigFunc func(ctx context.Context) (*ssh.ClientConfig, error)

type sshTunnel struct {
	addr         string
	clientConfig sshClientConfigFunc

	mu     sync.Mutex
	client *ssh.Client
	closed bool
}

func sshKeyClientConfig(user, keyPath, passphrase string, hostKeyCallback ssh.HostKeyCallback) (sshClientConfigFunc, error) {
	key, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read SSH private key: %w", err)
	}

	var signer ssh.Signer
	if passphrase != "" {
		signer, err = ssh.ParsePrivateKeyWithPassphrase(key, []byte(passphrase))
	} else {
		signer, err = ssh.ParsePrivateKey(key)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to parse SSH private key: %w", err)
	}

	return func(context.Context) (*ssh.ClientConfig, error) {
		return &ssh.ClientConfig{
			User:            user,
			Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
			HostKeyCallback: hostKeyCallback,
		}, nil
	}, nil
}

func newSSHTunnel(addr string, clientConfig sshClientConfigFunc) *sshTunnel {
	return &sshTunnel{addr: addr, clientConfig: clientConfig}
}

func (t *sshTunnel) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	client, err := t.connect(ctx)
	if err != nil {
		return nil, err
	}

	conn, err := client.DialContext(ctx, network, addr)
	var openChannelErr *ssh.OpenChannelError
	if err == nil || errors.As(err, &openChannelErr) || ctx.Err() != nil {
		return conn, err
	}

	l.Warn("SSH connection to bastion is broken, reconnecting", "sshHost", t.addr, "error", err)
	t.discard(client)

	client, err = t.connect(ctx)
	if err != nil {
		return nil, err
	}
	return client.DialContext(ctx, network, addr)
}

func (t *sshTunnel) connect(ctx context.Context) (*ssh.Client, error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.closed {
		return nil, errSSHTunnelClosed
	}
	if t.client != nil {
		return t.client, nil
	}

	config, err := t.clientConfig(ctx)
	if err != nil {
		return nil, err
	}
	config.HostKeyAlgorithms = knownHostKeyAlgorithms(config.HostKeyCallback, t.addr)

	l.Info("connecting to SSH bastion", "sshHost", t.addr, "user", config.User)

	var dialer net.Dialer
	conn, err := dialer.DialContext(ctx, "tcp", t.addr)
	if err != nil {
		return nil, fmt.Errorf("failed to dial SSH bastion: %w", err)
	}

	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	sshConn, chans, reqs, err := ssh.NewClientConn(conn, t.addr, config)
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("failed to establish SSH connection to bastion: %w", err)
	}
	_ = conn.SetDeadline(time.Time{})

	t.client = ssh.NewClient(sshConn, chans, reqs)
	go t.keepAlive(t.client)

	l.Info("connected to SSH bastion", "sshHost", t.addr)
	return t.client, nil
}

func (t *sshTunnel) keepAlive(client *ssh.Client) {
	done := make(chan struct{})
	go func() {
		_ = client.Wait()
		close(done)
	}()

	ticker := time.NewTicker(sshKeepAliveInterval)
	defer ticker.Stop()

	for {
		select {
		case <-done:
			t.discard(client)
			return
		case <-ticker.C:
			if err := sendKeepAlive(client); err != nil {
				l.Warn("SSH keepalive to bastion failed", "sshHost", t.addr, "error", err)
				t.discard(client)
			}
		}
	}
}

func sendKeepAlive(client *ssh.Client) error {
	errc := make(chan error, 1)
	go func() {
		_, _, err := client.SendRequest("keepalive@openssh.com", true, nil)
		errc <- err
	}()

	select {
	case err := <-errc:
		return err
	case <-time.After(sshKeepAliveTimeout):
		return errors.New("timed out waiting for keepalive reply")
	}
}

func (t *sshTunnel) discard(client *ssh.Client) {
	t.mu.Lock()
	if t.client == client {
		t.client = nil
	}
	t.mu.Unlock()

	_ = client.Close()
}

func (t *sshTunnel) Close() error {
	t.mu.Lock()
	defer t.mu.Unlock()

	t.closed = true
	if t.client == nil {
		return nil
	}
	err := t.client.Close()
	t.client = nil
	return err
}

// Go prefers RSA host keys while OpenSSH prefers ED25519, so without this the bastion may present
// a key type that is missing from known_hosts and fail verification even though another type is known.
func knownHostKeyAlgorithms(hostKeyCallback ssh.HostKeyCallback, addr string) []string {
	err := hostKeyCallback(addr, &net.TCPAddr{IP: net.IPv4zero}, unknownHostKey)
	keyErr, ok := errors.AsType[*knownhosts.KeyError](err)
	if !ok {
		return nil
	}

	var algorithms []string
	for _, known := range keyErr.Want {
		keyAlgorithms := []string{known.Key.Type()}
		if known.Key.Type() == ssh.KeyAlgoRSA {
			keyAlgorithms = []string{ssh.KeyAlgoRSASHA512, ssh.KeyAlgoRSASHA256}
		}
		for _, algorithm := range keyAlgorithms {
			if !slices.Contains(algorithms, algorithm) {
				algorithms = append(algorithms, algorithm)
			}
		}
	}
	return algorithms
}

var unknownHostKey = func() ssh.PublicKey {
	key, err := ssh.NewPublicKey(ed25519.PublicKey(make([]byte, ed25519.PublicKeySize)))
	if err != nil {
		panic(err)
	}
	return key
}()

func defaultKnownHostsPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".ssh", "known_hosts")
}

func connectSSHTunnel(ctx context.Context, addr, user, keyPath, knownHostsPath string) (*sshTunnel, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	hostKeyCallback, err := knownhosts.New(knownHostsPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read SSH known hosts: %w", err)
	}

	var clientConfig sshClientConfigFunc
	if keyPath != "" {
		clientConfig, err = sshKeyClientConfig(user, keyPath, os.Getenv(sshKeyPassphraseEnv), hostKeyCallback)
	} else {
		clientConfig, err = entraSSHClientConfig(ctx, hostKeyCallback)
	}
	if err != nil {
		return nil, err
	}

	tunnel := newSSHTunnel(addr, clientConfig)
	if _, err := tunnel.connect(ctx); err != nil {
		return nil, err
	}
	return tunnel, nil
}
