# vault-init

The `vault-init` service automates the process of [initializing](https://www.vaultproject.io/docs/commands/operator/init.html) and [unsealing](https://www.vaultproject.io/docs/concepts/seal.html#unsealing) HashiCorp Vault instances running on [Google Cloud Platform](https://cloud.google.com).

This is a fork of of sethvargo/vault-init, adding support for multiple backends for storing recovery keys and the root token. Support for Google Secrets Manager is first.

After `vault-init` initializes a Vault server it stores master keys and root tokens, encrypted using [Google Cloud KMS](https://cloud.google.com/kms), to a user defined [Google Cloud Storage](https://cloud.google.com/storage) bucket.

## Security
It should be stated up front that right now, storing of the root token, rather than the instant revocation once initial provisioning has been performed, is against best practices. The work contained in the auth.go file is some work to have the init container provision an admin group on initialisation.

## Deploying to a cluster
### Using Google Secrets Manager

```
apiVersion: v1
kind: Pod
metadata:
  name: vault-init
  labels:
    role: vault-init
spec:
  containers:
    - name: vault-init
      image: glennadjrussell/vault-init:0.1.14
      imagePullPolicy: Always
      env:
        - name: VAULT_ADDR
          value: "http://vault-0.vault-internal:8200"
        - name: VAULT_KEY_ENGINE
          value: SSM
        - name: GCP_PROJECT
          value: "my-project-id"
        - name: GCS_BUCKET_NAME
          value: dummy-for-now
        - name: KMS_KEY_ID
          value: dummy-for-now
```

Secrets will appear in the secret manager console as 'root_token_enc' (root token) and 'unseal_keys_enc' (recovery keys).

### Using KMS

```
apiVersion: v1
kind: Pod
metadata:
  name: vault-init
  labels:
    role: vault-init
spec:
  containers:
    - name: vault-init
      image: glennadjrussell/vault-init:0.1.14
      imagePullPolicy: Always
      env:
        - name: VAULT_ADDR
          value: "http://vault-0.vault-internal:8200"
        - name: VAULT_KEY_ENGINE
          value: KMS
        - name: GCS_BUCKET_NAME
          value: my-gcs-bucket
        - name: KMS_KEY_ID
          value: projects/my-project/locations/my-location/cryptoKeys/my-key
```

Secrets will appear in GCS as 'root_token_enc' (root token) and 'unseal_keys_enc' (recovery keys).

## Usage

The `vault-init` service is designed to be run alongside a Vault server and
communicate over local host.

You can download the code and compile the binary with Go. Alternatively, a
Docker container is available via the Docker Hub:

```text
$ docker pull glennadjrussell/vault-init:0.1.11
```

To use this as part of a Kubernetes Vault Deployment:

```yaml
containers:
- name: vault-init
  image: glennadjrussell/vault-init:0.1.14
  imagePullPolicy: Always
  env:
  - name: GCS_BUCKET_NAME
    value: my-gcs-bucket
  - name: KMS_KEY_ID
    value: projects/my-project/locations/my-location/cryptoKeys/my-key
```

## Configuration

The vault-init service supports the following environment variables for configuration:

- `CHECK_INTERVAL` ("10s") - The time duration between Vault health checks. Set
  this to a negative number to unseal once and exit.

- `GCS_BUCKET_NAME` - The Google Cloud Storage Bucket where the vault master key
  and root token is stored.

- `KMS_KEY_ID` - The Google Cloud KMS key ID used to encrypt and decrypt the
  vault master key and root token.

- `VAULT_SECRET_SHARES` (5) - The number of human shares to create.

- `VAULT_SECRET_THRESHOLD` (3) - The number of human shares required to unseal.

- `VAULT_AUTO_UNSEAL` - Use Vault 1.0 native auto-unsealing directly. You must
  set the seal configuration in Vault's configuration.

- `VAULT_STORED_SHARES` (1) - Number of shares to store on KMS. Only applies to
  Vault 1.0 native auto-unseal.

- `VAULT_RECOVERY_SHARES` (1) - Number of recovery shares to generate. Only
  applies to Vault 1.0 native auto-unseal.

- `VAULT_RECOVERY_THRESHOLD` (1) - Number of recovery shares needed to unseal.
  Only applies to Vault 1.0 native auto-unseal.

- `VAULT_SKIP_VERIFY` (false) - Disable TLS validation when connecting. Setting
  to true is highly discouraged.

- `VAULT_CACERT` ("") - Path on disk to the CA _file_ to use for verifying TLS
  connections to Vault.

- `VAULT_CAPATH` ("") - Path on disk to a directory containing the CAs to use
  for verifying TLS connections to Vault. `VAULT_CACERT` takes precedence.

- `VAULT_TLS_SERVER_NAME` ("") - Custom SNI hostname to use when validating TLS
  connections to Vault.

### Example Values

```
CHECK_INTERVAL="30s"
GCS_BUCKET_NAME="vault-storage"
KMS_KEY_ID="projects/my-project/locations/global/keyRings/my-keyring/cryptoKeys/key"
```

### IAM &amp; Permissions

The `vault-init` service uses the official Google Cloud Golang SDK. This means
it supports the common ways of [providing credentials to GCP][cloud-creds].

To use this service, the service account must have the following minimum
scope(s):

```text
https://www.googleapis.com/auth/cloudkms
https://www.googleapis.com/auth/devstorage.read_write
```

Additionally, the service account must have the following minimum role(s):

```text
roles/cloudkms.cryptoKeyEncrypterDecrypter
roles/storage.objectAdmin OR roles/storage.legacyBucketWriter
```

For more information on service accounts, please see the
[Google Cloud Service Accounts documentation][service-accounts].

[cloud-creds]: https://cloud.google.com/docs/authentication/production#providing_credentials_to_your_application
[service-accounts]: https://cloud.google.com/compute/docs/access/service-accounts
