package backend

import (
	"context"
	"fmt"
	"log"

	secretmanager "cloud.google.com/go/secretmanager/apiv1"
	secretmanagerpb "google.golang.org/genproto/googleapis/cloud/secretmanager/v1"
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
		return false, err
	}

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

