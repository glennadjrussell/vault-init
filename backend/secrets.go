package backend

import (
	"context"
	"fmt"
	"io/ioutil"
	"log"
	"encoding/base64"
	"runtime"

	option "google.golang.org/api/option"
	storage "cloud.google.com/go/storage"
	cloudkms "google.golang.org/api/cloudkms/v1"
	secretmanager "cloud.google.com/go/secretmanager/apiv1"
	secretmanagerpb "google.golang.org/genproto/googleapis/cloud/secretmanager/v1"
)

var (
	userAgent = fmt.Sprintf("vault-init/1.0.0 (%s)", runtime.Version())
)

type KeyBackend interface {
	Store(key string, payload []byte) (bool, error)
	Read(key string) ([]byte, error)
}

type SecretsManagerBackend struct {
	Context *context.Context
	ProjectId string
	Client *secretmanager.Client
}

func NewSecretsManagerBackend(projectid string) (*SecretsManagerBackend, error) {
	ctx := context.Background()
	client, err := secretmanager.NewClient(ctx)
	if err != nil {
		log.Fatalf("failed to configure secrets manager client: %v", err)
		return nil, err
	}

	smb := SecretsManagerBackend{
		Context: &ctx,
		ProjectId: fmt.Sprintf("projects/%s", projectid),
		Client: client,
	}

	return &smb, nil
}

func (s *SecretsManagerBackend) Store(key string, payload []byte) (bool, error) {
	secretReq := &secretmanagerpb.CreateSecretRequest{
		Parent: s.ProjectId,
		SecretId: key,
		Secret: &secretmanagerpb.Secret{
			Replication: &secretmanagerpb.Replication{
				Replication: &secretmanagerpb.Replication_Automatic_{
					Automatic: &secretmanagerpb.Replication_Automatic{},
				},
			},
		},
	}

	secret, err := s.Client.CreateSecret(*s.Context, secretReq)
	if err != nil {
		log.Printf("failed to create secret: %v. falling back to reading secret", err)

		getSecretReq := &secretmanagerpb.GetSecretRequest{
			Name: fmt.Sprintf("%s/secrets/%s", s.ProjectId, key),
		}

		secret, err = s.Client.GetSecret(*s.Context, getSecretReq)
		if err != nil {
		log.Fatalf("failed to read secret (%s): %v", fmt.Sprintf("%s/secrets/%s", s.ProjectId, key), err)
			return false, err
		}
	}

	log.Printf("Writing secret to %s", key)

	addSecretReq := &secretmanagerpb.AddSecretVersionRequest{
		Parent: secret.Name,
		Payload: &secretmanagerpb.SecretPayload{
			Data: payload,
		},
	}

	version, err := s.Client.AddSecretVersion(*s.Context, addSecretReq)
	if err != nil {
		log.Fatalf("unable to add secret version: %v", err)
		return false, err
	}

	log.Printf("Secret version %s", version)

	return true, nil
}

func (s *SecretsManagerBackend) Read(key string) ([]byte, error) {
	accessRequest := &secretmanagerpb.AccessSecretVersionRequest{
		Name: fmt.Sprintf("%s/secrets/%s/versions/latest", s.ProjectId, key),
	}

	result, err := s.Client.AccessSecretVersion(*s.Context, accessRequest)
	if err != nil {
		log.Fatalf("failed to read vault key: %v", err)
		return nil, err
	}

	return result.Payload.Data, nil
}

//
// KMS/GCP Backend
//

type KmsBackend struct {
	KmsKeyId string
	GcsBucketName string
	KmsService *cloudkms.Service
	StorageClient *storage.Client
}

func NewKmsBackend(kmsKey string, gcsBucketName string) (*KmsBackend, error) {
	kmsCtx, kmsCtxCancel := context.WithCancel(context.Background())
        defer kmsCtxCancel()
	kmsService, err := cloudkms.NewService(kmsCtx)
        if err != nil {
                log.Println(err)
                return nil, err
        }
        kmsService.UserAgent = userAgent

        storageCtx, storageCtxCancel := context.WithCancel(context.Background())
        defer storageCtxCancel()
	storageClient, err := storage.NewClient(storageCtx,
                option.WithUserAgent(userAgent),
                option.WithScopes(storage.ScopeReadWrite))
        if err != nil {
                log.Fatal(err)
        }

	kmsBackend := KmsBackend{
		KmsKeyId: kmsKey,
		GcsBucketName: gcsBucketName,
		KmsService: kmsService,
		StorageClient: storageClient,
	}

	return &kmsBackend, err
}

func (k *KmsBackend) Store(key string, payload []byte) (bool, error) {
	encryptRequest := &cloudkms.EncryptRequest{
                Plaintext: base64.StdEncoding.EncodeToString(payload),
        }

        encryptResponse, err := k.KmsService.Projects.Locations.KeyRings.CryptoKeys.Encrypt(k.KmsKeyId, encryptRequest).Do()
        if err != nil {
                log.Println(err)
                return false, err
        }

        bucket := k.StorageClient.Bucket(k.GcsBucketName)

        ctx := context.Background()
        keyObject := bucket.Object(key).NewWriter(ctx)
        defer keyObject.Close()

        _, err = keyObject.Write([]byte(encryptResponse.Ciphertext))
        if err != nil {
                log.Println(err)
		return false, err
        }

        log.Printf("KMS encrypted payload written to gs://%s/%s", k.GcsBucketName, key)

	return true, nil
}

func (k *KmsBackend) Read(key string) ([]byte, error) {
        bucket := k.StorageClient.Bucket(k.GcsBucketName)

        ctx := context.Background()
        keyObject, err := bucket.Object(key).NewReader(ctx)
        if err != nil {
                log.Println(err)
                return nil, err
        }

        defer keyObject.Close()

        keyData, err := ioutil.ReadAll(keyObject)
        if err != nil {
                log.Println(err)
                return nil, err
        }

        keyDecryptRequest := &cloudkms.DecryptRequest{
                Ciphertext: string(keyData),
        }

        keyDecryptResponse, err := k.KmsService.Projects.Locations.KeyRings.CryptoKeys.Decrypt(k.KmsKeyId, keyDecryptRequest).Do()
        if err != nil {
                log.Println(err)
                return nil, err
        }

        keyPlaintext, err := base64.StdEncoding.DecodeString(keyDecryptResponse.Plaintext)
        if err != nil {
                log.Println(err)
                return nil, err
        }

	return keyPlaintext, nil
}

