package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/jackc/pgx/v5"
	"github.com/mdelapenya/tlscert"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"
)

// fakeAzureCredential implements the azcore.TokenCredential interface.
// Its GetToken method always returns a fixed token. In this test, we return
// the token "test" which will match the PostgreSQL container’s password.
type fakeAzureCredential struct {
	token azcore.AccessToken
}

func (f *fakeAzureCredential) GetToken(ctx context.Context, opts policy.TokenRequestOptions) (azcore.AccessToken, error) {
	return f.token, nil
}

func TestRun(t *testing.T) {
	t.Parallel()
	tests := []struct {
		postgresVersion string
	}{
		{postgresVersion: "postgres:17-alpine"},
		{postgresVersion: "postgres:16-alpine"},
		{postgresVersion: "postgres:15-alpine"},
		{postgresVersion: "postgres:14-alpine"},
		{postgresVersion: "postgres:13-alpine"},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.postgresVersion, func(t *testing.T) {
			t.Parallel()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			caCert, serverCerts, err := createSSLCerts(t)
			require.NoError(t, err)

			dbUser, dbPassword, dbName := "postgres", "fakepass", "mydatabase"
			pgContainer, err := postgres.Run(ctx,
				tt.postgresVersion,
				postgres.WithDatabase(dbName),
				postgres.WithUsername(dbUser),
				postgres.WithPassword(dbPassword),
				postgres.WithConfigFile(filepath.Join("testdata", "postgres-ssl.conf")),
				postgres.WithSSLCert(caCert.CertPath, serverCerts.CertPath, serverCerts.KeyPath),
				testcontainers.WithWaitStrategy(
					wait.ForLog("database system is ready to accept connections").
						WithOccurrence(2).
						WithStartupTimeout(5*time.Second)),
			)

			t.Cleanup(func() {
				if err := testcontainers.TerminateContainer(pgContainer); err != nil {
					log.Printf("failed to terminate container: %s", err)
				}
			})

			require.NoError(t, err)

			require.NoError(t, pgContainer.Start(ctx))

			host, err := pgContainer.Host(ctx)
			require.NoError(t, err)
			mappedPort, err := pgContainer.MappedPort(ctx, "5432")
			require.NoError(t, err)
			dbHost := fmt.Sprintf("%s:%s", host, mappedPort.Port())

			fakeAzCreds := &fakeAzureCredential{token: azcore.AccessToken{Token: dbPassword, ExpiresOn: time.Now().Add(1 * time.Hour)}}

			// get a random available port
			proxyPort, err := getFreePort()
			require.NoError(t, err)
			proxyHost := fmt.Sprintf("127.0.0.1:%d", proxyPort)
			go func() {
				err := run(ctx, dbHost, proxyHost, fakeAzCreds)
				require.NoError(t, err)
			}()

			// Connect to the database through the proxy.
			timeout, retry := 10*time.Second, 1*time.Second
			var conn *pgx.Conn
			assert.Eventually(t, func() bool {
				var err error
				connString := fmt.Sprintf("postgresql://%s:%s@%s/%s?sslmode=disable", dbUser, "this-password-should-be-overwritten-by-the-proxy", proxyHost, dbName)
				l.Info("connecting to database", "connString", connString)
				conn, err = pgx.Connect(ctx, connString)
				return err == nil
			}, timeout, retry)

			require.NotNil(t, conn)
			defer func() {
				if err := conn.Close(ctx); err != nil {
					t.Logf("failed to close connection: %v", err)
				}
			}()

			var result int
			require.NoError(t, conn.QueryRow(ctx, "SELECT 1").Scan(&result))
			require.Equal(t, 1, result)
		})
	}
}

func createSSLCerts(t *testing.T) (*tlscert.Certificate, *tlscert.Certificate, error) {
	t.Helper()
	tmpDir := t.TempDir()
	certsDir := tmpDir + "/certs"

	require.NoError(t, os.MkdirAll(certsDir, 0o755))

	t.Cleanup(func() {
		require.NoError(t, os.RemoveAll(tmpDir))
	})

	caCert := tlscert.SelfSignedFromRequest(tlscert.Request{
		Host:      "localhost",
		Name:      "ca-cert",
		ParentDir: certsDir,
	})

	if caCert == nil {
		return caCert, nil, errors.New("unable to create CA Authority")
	}

	cert := tlscert.SelfSignedFromRequest(tlscert.Request{
		Host:      "localhost",
		Name:      "client-cert",
		Parent:    caCert,
		ParentDir: certsDir,
	})
	if cert == nil {
		return caCert, cert, errors.New("unable to create Server Certificates")
	}

	return caCert, cert, nil
}

// getFreePort asks the kernel for a free open port that is ready to use.
func getFreePort() (port int, err error) {
	var a *net.TCPAddr
	if a, err = net.ResolveTCPAddr("tcp", "localhost:0"); err == nil {
		var l *net.TCPListener
		if l, err = net.ListenTCP("tcp", a); err == nil {
			defer func() { _ = l.Close() }()
			return l.Addr().(*net.TCPAddr).Port, nil
		}
	}
	return
}
