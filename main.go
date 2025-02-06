package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgproto3"
)

const azureDatabaseScope = "https://ossrdbms-aad.database.windows.net/.default"

var l = slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{}))

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	const help = `The azure-postgres-auth-proxy proxies PostgreSQL connections to a backend PostgreSQL server using Entra for authentication.
	Usage:
		`

	listenAddr := flag.String("listen-addr", "127.0.0.1:5432", "Address the proxy listens on. Binding to the loopback interface protects it from external access outside the pod network namespace.")
	dbHost := flag.String("db-host", "", "Host of the PostgreSQL server to proxy traffic to. For example 'mydb.postgres.database.azure.com:5432'.")
	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), help+"\n")
		flag.PrintDefaults()
	}

	flag.Parse()

	if *dbHost == "" {
		fmt.Println("missing required flag: -db-host")
		os.Exit(1)
	}

	*dbHost = strings.Trim(strings.TrimSpace(*dbHost), `"`) // passing the arg db-host in k8s yaml can add quotes, so we remove them
	if _, _, err := net.SplitHostPort(*dbHost); err != nil {
		fmt.Println("invalid -db-host value:", err)
		os.Exit(1)
	}

	// Create an Azure credential for token retrieval.
	azureCred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		fmt.Println("failed to create Azure credential:", err)
		os.Exit(1)
	}

	ctxToken, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err = azureCred.GetToken(ctxToken, policy.TokenRequestOptions{Scopes: []string{azureDatabaseScope}}); err != nil {
		fmt.Println("failed to obtain Azure Entra token:", err)
		os.Exit(1)
	}

	l.Info("successfully obtained an entra token")

	if err := run(ctx, *dbHost, *listenAddr, azureCred); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, dbHost, listenAddr string, azureCred azcore.TokenCredential) error {
	ln, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return fmt.Errorf("failed to listen: %w", err)
	}
	defer ln.Close()

	l.Info("proxy is listening", "listenAddr", listenAddr, "dbHost", dbHost)

	go func() {
		<-ctx.Done()
		l.Info("shutting down listener due to cancellation")
		ln.Close()
	}()

	for {
		clientConn, err := ln.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				l.Info("listener closed due to cancellation")
				return nil
			default:
			}
			l.Error("error accepting client connection", "error", err)
			continue
		}

		go handleConnection(ctx, clientConn, dbHost, azureCred)
	}
}

func handleConnection(ctx context.Context, clientConn net.Conn, dbHost string, azureCred azcore.TokenCredential) {
	defer clientConn.Close()

	startupMsg, err := readStartupMessage(clientConn)
	if err != nil {
		l.Error("failed to read startup message", "error", err)
		return
	}

	l.Info("client startup parameters", "parameters", startupMsg.Parameters)

	clientUser, ok := startupMsg.Parameters["user"]
	if !ok {
		l.Error("no user provided in startup message")
		return
	}
	clientDatabase, ok := startupMsg.Parameters["database"]
	if !ok {
		l.Error("no database provided in startup message")
		return
	}

	l.Info("fetching an entra token for authentication to backend")

	ctxToken, cancelToken := context.WithTimeout(ctx, 5*time.Second)
	defer cancelToken()
	token, err := azureCred.GetToken(ctxToken, policy.TokenRequestOptions{Scopes: []string{azureDatabaseScope}})
	if err != nil {
		l.Error("error obtaining Azure Entra token", "error", err)
		return
	}

	l.Info("obtained Azure Entra token", "expiresAt", token.ExpiresOn)

	connStr := fmt.Sprintf("postgres://%s:%s@%s/%s?sslmode=require", clientUser, token.Token, dbHost, clientDatabase)
	config, err := pgconn.ParseConfig(connStr)
	if err != nil {
		l.Error("failed to parse connection string", "error", err)
		return
	}

	for k, v := range startupMsg.Parameters {
		if k != "user" && k != "database" {
			config.RuntimeParams[k] = v
		}
	}

	ctxConn, cancelConn := context.WithTimeout(ctx, 5*time.Second)
	defer cancelConn()
	backendConn, err := pgconn.ConnectConfig(ctxConn, config)
	if err != nil {
		l.Error("failed to connect to backend", "error", err)
		return
	}
	defer backendConn.Close(ctx)

	l.Info("successfully connected to the database", "addr", dbHost)

	if err := backendConn.SyncConn(ctxConn); err != nil {
		l.Error("failed to sync backend connection", "error", err)
		return
	}

	// Get the underlying net.Conn from the backend connection.
	hijackedBackend, err := backendConn.Hijack()
	if err != nil {
		l.Error("failed to hijack backend connection", "error", err)
		return
	}
	defer hijackedBackend.Conn.Close()

	l.Info("simulating client handshake")
	if err := simulateClientHandshake(clientConn, hijackedBackend); err != nil {
		l.Error("failed to simulate client handshake", "error", err)
		return
	}

	backendNetConn := hijackedBackend.Conn

	l.Info("proxy connection successful", "clientAddr", clientConn.RemoteAddr(), "backendAddr", backendNetConn.RemoteAddr())

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		if _, err := io.Copy(backendNetConn, clientConn); err != nil {
			l.Error("failed to copy data from client to backend", "error", err)
		}
	}()
	go func() {
		defer wg.Done()
		if _, err := io.Copy(clientConn, backendNetConn); err != nil {
			l.Error("failed to copy data from backend to client", "error", err)
		}
	}()

	wg.Wait()

	l.Info("proxy connection closed", "clientAddr", clientConn.RemoteAddr(), "backendAddr", backendNetConn.RemoteAddr())
}

// simulateClientHandshake simulates the PostgreSQL handshake between the client and the backend.
// It sends the authentication messages and the runtime parameters to the client.
func simulateClientHandshake(clientConn net.Conn, hijackedBackend *pgconn.HijackedConn) error {
	handshakeMessages := []pgproto3.BackendMessage{
		&pgproto3.AuthenticationOk{},
	}
	for k, v := range hijackedBackend.Config.RuntimeParams {
		handshakeMessages = append(handshakeMessages, &pgproto3.ParameterStatus{
			Name:  k,
			Value: v,
		})
	}
	handshakeMessages = append(handshakeMessages, &pgproto3.BackendKeyData{
		ProcessID: uint32(hijackedBackend.PID),
		SecretKey: uint32(hijackedBackend.SecretKey),
	})
	handshakeMessages = append(handshakeMessages, &pgproto3.ReadyForQuery{
		TxStatus: 'I',
	})

	for _, msg := range handshakeMessages {
		buf, err := msg.Encode(nil)
		if err != nil {
			return fmt.Errorf("failed to encode handshake message: %w", err)
		}

		if _, err := clientConn.Write(buf); err != nil {
			return fmt.Errorf("failed to send handshake message to client: %w", err)
		}
	}

	return nil
}

// readStartupMessage reads the PostgreSQL startup message from the client.
func readStartupMessage(clientConn net.Conn) (*pgproto3.StartupMessage, error) {
	frontend := pgproto3.NewBackend(clientConn, clientConn)
	msg, err := frontend.ReceiveStartupMessage()
	if err != nil {
		return nil, err
	}
	startupMsg, ok := msg.(*pgproto3.StartupMessage)
	if !ok {
		return nil, fmt.Errorf("unexpected message type: %T", msg)
	}
	return startupMsg, nil
}
