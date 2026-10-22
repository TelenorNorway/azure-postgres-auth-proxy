package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/cache"
	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/public"
	"golang.org/x/crypto/ssh"
)

// The Azure CLI client and the Entra application behind "az ssh", see
// https://github.com/Azure/azure-cli-extensions/blob/main/src/ssh/azext_ssh/custom.py.
const (
	azureCLIClientID          = "04b07795-8ddb-461a-bbee-02f9e1bf7b46"
	entraSSHLoginScope        = "ce6ff14a-7fdc-4685-bbe0-f6afdfcfa8e0/.default"
	entraSSHCertRenewalMargin = 5 * time.Minute
)

type entraSSHCertificates struct {
	key     ssh.Signer
	scheme  sshCertAuthScheme
	client  public.Client
	account public.Account

	mu   sync.Mutex
	cert *ssh.Certificate
}

func entraSSHClientConfig(ctx context.Context, hostKeyCallback ssh.HostKeyCallback) (sshClientConfigFunc, error) {
	client, account, err := azureCLIClient(ctx)
	if err != nil {
		return nil, err
	}

	privateKey, err := rsa.GenerateKey(rand.Reader, 3072)
	if err != nil {
		return nil, fmt.Errorf("failed to generate SSH key: %w", err)
	}
	key, err := ssh.NewSignerFromKey(privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create SSH signer: %w", err)
	}
	scheme, err := newSSHCertAuthScheme(key.PublicKey())
	if err != nil {
		return nil, err
	}

	certs := &entraSSHCertificates{key: key, scheme: scheme, client: client, account: account}
	return func(ctx context.Context) (*ssh.ClientConfig, error) {
		cert, err := certs.certificate(ctx)
		if err != nil {
			return nil, err
		}
		signer, err := ssh.NewCertSigner(cert, certs.key)
		if err != nil {
			return nil, fmt.Errorf("failed to create SSH certificate signer: %w", err)
		}
		return &ssh.ClientConfig{
			User:            strings.ToLower(cert.ValidPrincipals[0]),
			Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
			HostKeyCallback: hostKeyCallback,
		}, nil
	}, nil
}

func (c *entraSSHCertificates) certificate(ctx context.Context) (*ssh.Certificate, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.cert != nil && time.Until(time.Unix(int64(c.cert.ValidBefore), 0)) > entraSSHCertRenewalMargin {
		return c.cert, nil
	}

	l.Info("fetching an entra SSH certificate")
	result, err := c.client.AcquireTokenSilent(ctx, []string{entraSSHLoginScope},
		public.WithSilentAccount(c.account),
		public.WithAuthenticationScheme(c.scheme),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to obtain Entra SSH certificate: %w", err)
	}

	pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(ssh.CertAlgoRSAv01 + " " + result.AccessToken))
	if err != nil {
		return nil, fmt.Errorf("failed to parse Entra SSH certificate: %w", err)
	}
	cert, ok := pub.(*ssh.Certificate)
	if !ok || len(cert.ValidPrincipals) == 0 {
		return nil, errors.New("entra SSH certificate has no principals")
	}

	l.Info("obtained Entra SSH certificate", "principal", cert.ValidPrincipals[0], "expiresAt", time.Unix(int64(cert.ValidBefore), 0))
	c.cert = cert
	return cert, nil
}

func azureCLIClient(ctx context.Context) (public.Client, public.Account, error) {
	out, err := exec.CommandContext(ctx, "az", "account", "show", "--query", "{tenantId: tenantId, user: user.name}", "--output", "json").Output()
	if err != nil {
		return public.Client{}, public.Account{}, fmt.Errorf("failed to get the Azure CLI account, run 'az login': %w", err)
	}
	var cliAccount struct {
		TenantID string `json:"tenantId"`
		User     string `json:"user"`
	}
	if err := json.Unmarshal(out, &cliAccount); err != nil {
		return public.Client{}, public.Account{}, fmt.Errorf("failed to parse the Azure CLI account: %w", err)
	}

	client, err := public.New(azureCLIClientID,
		public.WithAuthority("https://login.microsoftonline.com/"+cliAccount.TenantID),
		public.WithCache(azureCLITokenCache{}),
	)
	if err != nil {
		return public.Client{}, public.Account{}, err
	}

	accounts, err := client.Accounts(ctx)
	if err != nil {
		return public.Client{}, public.Account{}, err
	}
	i := slices.IndexFunc(accounts, func(a public.Account) bool {
		return strings.EqualFold(a.PreferredUsername, cliAccount.User)
	})
	if i < 0 {
		return public.Client{}, public.Account{}, fmt.Errorf("no cached Azure CLI login for %s, run 'az login'", cliAccount.User)
	}
	return client, accounts[i], nil
}

type azureCLITokenCache struct{}

func (azureCLITokenCache) Replace(_ context.Context, c cache.Unmarshaler, _ cache.ReplaceHints) error {
	dir := os.Getenv("AZURE_CONFIG_DIR")
	if dir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return err
		}
		dir = filepath.Join(home, ".azure")
	}
	data, err := os.ReadFile(filepath.Join(dir, "msal_token_cache.json"))
	if err != nil {
		return fmt.Errorf("failed to read the Azure CLI token cache: %w", err)
	}
	return c.Unmarshal(data)
}

func (azureCLITokenCache) Export(context.Context, cache.Marshaler, cache.ExportHints) error {
	return nil
}

type sshCertAuthScheme struct {
	jwk   string
	keyID string
}

func newSSHCertAuthScheme(pub ssh.PublicKey) (sshCertAuthScheme, error) {
	var wire struct {
		Algorithm string
		Exponent  []byte
		Modulus   []byte
	}
	if err := ssh.Unmarshal(pub.Marshal(), &wire); err != nil {
		return sshCertAuthScheme{}, fmt.Errorf("failed to decode SSH public key: %w", err)
	}

	e := base64.URLEncoding.EncodeToString(wire.Exponent)
	n := base64.URLEncoding.EncodeToString(wire.Modulus)
	hash := sha256.Sum256([]byte(n + e))
	keyID := hex.EncodeToString(hash[:])

	jwk, err := json.Marshal(struct {
		Kty string `json:"kty"`
		N   string `json:"n"`
		E   string `json:"e"`
		Kid string `json:"kid"`
	}{"RSA", n, e, keyID})
	if err != nil {
		return sshCertAuthScheme{}, err
	}
	return sshCertAuthScheme{jwk: string(jwk), keyID: keyID}, nil
}

func (s sshCertAuthScheme) TokenRequestParams() map[string]string {
	return map[string]string{
		"token_type": "ssh-cert",
		"req_cnf":    s.jwk,
		"key_id":     s.keyID,
	}
}

func (s sshCertAuthScheme) KeyID() string {
	return s.keyID
}

func (s sshCertAuthScheme) FormatAccessToken(accessToken string) (string, error) {
	return accessToken, nil
}

func (s sshCertAuthScheme) AccessTokenType() string {
	return "ssh-cert"
}
