# azure-postgres-auth-proxy

A proxy that uses Microsoft Entra authentication for Azure PostgreSQL.

It was created to solve the following problems:

- Your third-party Postgres client or program does not support Microsoft Entra authentication.
- You do not want to add `azidentity` to your application code.
- You want to connect to an Azure PostgreSQL database from your IDE without having to fetch a new token all the time.

The proxy uses `azidentity.NewDefaultAzureCredential` so any of the methods described
in the [Azure SDK for Go documentation](https://pkg.go.dev/github.com/Azure/azure-sdk-for-go/sdk/azidentity#readme-credential-types) can be used to authenticate.

## Installation

Download the latest release from the [releases page](https://github.com/TelenorNorway/azure-postgres-auth-proxy/releases).

## Usage

You can run the proxy locally or as a sidecar in your Kubernetes cluster.

### Local

```bash
./azure-postgres-auth-proxy -db-addr your-database.postgres.database.azure.com:5432
```

Connect to the proxy using your favorite Postgres client.

With `psql`:

```bash
psql "host=127.0.0.1 port=5432 sslmode=disable user=<username> dbname=<database>"
```

### Kubernetes

Create a `ServiceAccount` and `Deployment` with [Azure Workload Identity](https://azure.github.io/azure-workload-identity/docs/) configured.

The example below runs a container with `psql` and connects to the database using the proxy.
Workload Identity is used to authenticate the proxy with the database.

```bash
# Update the following environment variables with your values
export CLIENT_ID="your-client-id"
export DATABASE_HOST="your-database.postgres.database.azure.com:5432"
export DATABASE_NAME="mydatabase"
export DATABASE_USERNAME="your-username"

# Create the service account and deployment
kubectl apply -f - <<EOF
apiVersion: v1
kind: ServiceAccount
metadata:
  name: my-db-client
  annotations:
    azure.workload.identity/client-id: "${CLIENT_ID}"
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: my-db-client
spec:
  replicas: 1
  selector:
    matchLabels:
      app: my-db-client
  template:
    metadata:
      labels:
        app: my-db-client
        azure.workload.identity/use: "true"
      annotations:
        azure.workload.identity/skip-containers: "my-db-client-container"
    spec:
      serviceAccountName: my-db-client
      containers:
      - name: my-db-client-container
        image: alpine/psql
        args: ["host=127.0.0.1 port=5432 sslmode=disable user=${DATABASE_USERNAME} dbname=${DATABASE_NAME}", "-c", '\l']
      initContainers:
      - name: azure-postgres-auth-proxy
        image: ghcr.io/telenornorway/azure-postgres-auth-proxy:0.1.2
        restartPolicy: Always
        args:
        - -db-host=${DATABASE_HOST}
EOF
```

The `my-db-client-container` should now log the databases in the `mydatabase` database.
