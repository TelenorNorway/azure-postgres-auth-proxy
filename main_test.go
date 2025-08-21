package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"runtime"
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

var (
	proxyShutdownTimeout = 5 * time.Second
)

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
		t.Run(tt.postgresVersion, func(t *testing.T) {
			t.Parallel()
			ctx := t.Context()

			cfg := pgContainerConfig{
				postgresVersion: tt.postgresVersion,
				dbName:          "mydatabase",
				username:        "postgres",
				password:        "fakepass",
			}

			dbHost := createPostgresContainer(t, cfg)
			conn := startProxyAndConnect(t, ctx, dbHost, cfg, &fakeAzureCredential{
				token: azcore.AccessToken{Token: cfg.password, ExpiresOn: time.Now().Add(1 * time.Hour)},
			})

			var result int
			require.NoError(t, conn.QueryRow(ctx, "SELECT 1").Scan(&result))
			require.Equal(t, 1, result)
		})
	}
}

// TestPanicRecovery verifies that a panic in handleConnection doesn't propagate
func TestPanicRecovery(t *testing.T) {
	// Create a mock connection that panics on Read
	mockConn := &panicConn{}

	// Create valid credentials
	creds := &fakeAzureCredential{
		token: azcore.AccessToken{
			Token:     "test",
			ExpiresOn: time.Now().Add(1 * time.Hour),
		},
	}

	// This should not panic despite mockConn.Read() panicking
	// The panic should be recovered in handleConnection
	handleConnection(context.Background(), mockConn, "test:5432", creds)

	// If we got here, the panic was recovered successfully
	t.Log("Panic was recovered successfully")
}

// panicConn is a mock connection that panics on Read
type panicConn struct {
	net.Conn
}

func (p *panicConn) Read(b []byte) (n int, err error) {
	panic("simulated panic in Read")
}

func (p *panicConn) Write(b []byte) (n int, err error) {
	return len(b), nil
}

func (p *panicConn) Close() error {
	return nil
}

func (p *panicConn) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 12345}
}

func (p *panicConn) SetReadDeadline(t time.Time) error {
	return nil
}

func TestGracefulShutdown(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	cfg := pgContainerConfig{
		postgresVersion: "postgres:17-alpine",
		dbName:          "mydatabase",
		username:        "postgres",
		password:        "fakepass",
	}

	dbHost := createPostgresContainer(t, cfg)

	// Create a cancelable context for the proxy
	ctxProxy, cancelProxy := context.WithCancel(ctx)
	conn := startProxyAndConnect(t, ctxProxy, dbHost, cfg, &fakeAzureCredential{
		token: azcore.AccessToken{Token: cfg.password, ExpiresOn: time.Now().Add(1 * time.Hour)},
	})

	// Start a long-running query to simulate active work
	queryDone := make(chan error, 1)
	go func() {
		// This query will sleep for 2 seconds to simulate a long-running operation
		_, err := conn.Exec(ctx, "SELECT pg_sleep(2)")
		queryDone <- err
	}()

	// Record the time when we initiate shutdown
	shutdownStart := time.Now()
	cancelProxy()

	select {
	case err := <-queryDone:
		require.NoError(t, err, "long-running query should complete during graceful shutdown")
		shutdownDuration := time.Since(shutdownStart)
		assert.GreaterOrEqual(t, shutdownDuration, 1500*time.Millisecond,
			"shutdown should have waited for active connection to complete")

	case <-time.After(10 * time.Second):
		t.Fatal("graceful shutdown test timed out - query did not complete")
	}
}

func TestGracefulShutdownTimeout(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	cfg := pgContainerConfig{
		postgresVersion: "postgres:17-alpine",
		dbName:          "mydatabase",
		username:        "postgres",
		password:        "fakepass",
	}

	dbHost := createPostgresContainer(t, cfg)

	// Create a cancelable context for the proxy
	ctxProxy, cancelProxy := context.WithCancel(ctx)
	conn := startProxyAndConnect(t, ctxProxy, dbHost, cfg, &fakeAzureCredential{
		token: azcore.AccessToken{Token: cfg.password, ExpiresOn: time.Now().Add(1 * time.Hour)},
	})

	// Start a long-running query that exceeds shutdown timeout
	queryDone := make(chan error, 1)
	queryResult := make(chan int, 1)
	go func() {
		// This query will sleep for 10 seconds which exceeds the 5s shutdown timeout
		// We expect this to return 42 if it completes, but it should be interrupted
		var result int
		err := conn.QueryRow(ctx, "SELECT pg_sleep(10), 42").Scan(&result, &result)
		if err == nil {
			queryResult <- result
		}
		queryDone <- err
	}()

	// Give the query a moment to start
	time.Sleep(100 * time.Millisecond)

	// Record when shutdown starts
	shutdownStart := time.Now()
	cancelProxy()

	// Wait for either the query to fail or timeout
	select {
	case err := <-queryDone:
		shutdownDuration := time.Since(shutdownStart)

		// The query should fail due to connection being closed during shutdown timeout
		require.Error(t, err, "long-running query should have been interrupted by shutdown timeout")

		// The query should fail due to connection being forcefully closed after timeout
		// The actual duration may be longer than the timeout because the PostgreSQL query
		// continues running until the connection is actually closed
		assert.GreaterOrEqual(t, shutdownDuration, proxyShutdownTimeout-500*time.Millisecond,
			"shutdown should have taken at least the timeout duration")

		// The important thing is that it didn't wait for the full 10 seconds
		assert.Less(t, shutdownDuration, 10*time.Second,
			"shutdown should not have waited for the full query duration")

		// Verify the query didn't complete successfully
		select {
		case result := <-queryResult:
			t.Errorf("query should not have completed successfully, but got result: %d", result)
		default:
			// Expected: no result because query was interrupted
		}

	case <-time.After(15 * time.Second):
		t.Fatal("test timed out - shutdown should have completed within timeout period")
	}
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

// fakeAzureCredential implements the azcore.TokenCredential interface.
// Its GetToken method always returns a fixed token. In this test, we return
// the token "test" which will match the PostgreSQL container’s password.
type fakeAzureCredential struct {
	token azcore.AccessToken
}

func (f *fakeAzureCredential) GetToken(ctx context.Context, opts policy.TokenRequestOptions) (azcore.AccessToken, error) {
	return f.token, nil
}

type pgContainerConfig struct {
	postgresVersion string
	dbName          string
	username        string
	password        string
}

func createPostgresContainer(t *testing.T, cfg pgContainerConfig) string {
	if runtime.GOOS == "darwin" {
		if err := os.Setenv("TESTCONTAINERS_RYUK_DISABLED", "true"); err != nil {
			require.NoError(t, err, "failed to set environment variable")
			return ""
		}
	}

	caCert, serverCerts, err := createSSLCerts(t)
	require.NoError(t, err)

	pgContainer, err := postgres.Run(t.Context(),
		cfg.postgresVersion,
		postgres.WithDatabase(cfg.dbName),
		postgres.WithUsername(cfg.username),
		postgres.WithPassword(cfg.password),
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
	require.NoError(t, pgContainer.Start(t.Context()))

	host, err := pgContainer.Host(t.Context())
	require.NoError(t, err)
	mappedPort, err := pgContainer.MappedPort(t.Context(), "5432")
	require.NoError(t, err)
	dbHost := fmt.Sprintf("%s:%s", host, mappedPort.Port())

	return dbHost
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

// startProxyAndConnect starts the proxy and establishes a connection to the database through the proxy
func startProxyAndConnect(t *testing.T, ctx context.Context, dbHost string, cfg pgContainerConfig, azCreds azcore.TokenCredential) *pgx.Conn {
	// get a random available port
	proxyPort, err := getFreePort()
	require.NoError(t, err)
	proxyHost := fmt.Sprintf("127.0.0.1:%d", proxyPort)
	go func() {
		err := run(ctx, dbHost, proxyHost, proxyShutdownTimeout, azCreds)
		require.NoError(t, err)
	}()

	// Connect to the database through the proxy.
	timeout, retry := 10*time.Second, 1*time.Second
	var conn *pgx.Conn
	assert.Eventually(t, func() bool {
		var err error
		connString := fmt.Sprintf("postgresql://%s:%s@%s/%s?sslmode=disable", cfg.username, "this-password-should-be-overwritten-by-the-proxy", proxyHost, cfg.dbName)
		l.Info("connecting to database", "connString", connString)
		conn, err = pgx.Connect(t.Context(), connString)
		return err == nil
	}, timeout, retry)
	require.NotNil(t, conn)

	t.Cleanup(func() {
		if err := conn.Close(ctx); err != nil {
			t.Logf("failed to close connection: %v", err)
		}
	})

	return conn
}
