// GET /v1/sys/storage/raft/snapshot HTTP/1.1
package main

import (
	"context"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"sync"
	"time"

	storage "cloud.google.com/go/storage"
	option "google.golang.org/api/option"
)

var (
	backupTicker   *time.Ticker
	backupInterval time.Duration
)

func backup(ch <-chan struct{}, wg *sync.WaitGroup) {
	backupInterval = durFromEnv("VAULT_BACKUP_INTERVAL", 60*time.Second)
	backupTicker = time.NewTicker(backupInterval)

	log.Println("Backups initialised")
	defer wg.Done()

	for {
		select {
		case <-ch:
			backupTicker.Stop()
			return
		case t := <-backupTicker.C:
			log.Printf("Backup running at %s", t.String())

			req, err := http.NewRequest("GET", vaultAddr+"/v1/sys/storage/raft/snapshot", nil)
			if err != nil {
				log.Printf("error occurred during backup %v", err)
				continue
			}

			token, err := keyBackend.Read(rootTokenFd)
			if err != nil {
				log.Printf("error occurred reading token %v", err)
				continue
			}

			req.Header.Set("X-Vault-Token", string(token))
			response, err := httpClient.Do(req)
			if response != nil && response.Body != nil {
				//response.Body.Close()
			}

			if err != nil || response.StatusCode != 200 {
				log.Printf("error occurred during backup %d, %v", response.StatusCode, err)
			}

			bodyBuffer, _ := ioutil.ReadAll(response.Body)
			fileName := fmt.Sprintf("vault_backup_%d_%02d_%02dT%02d_%02d_%02d.snap",
				t.Year(), t.Month(), t.Day(), t.Hour(), t.Minute(), t.Second())
			upload(fileName, bodyBuffer)
		}
	}

}

func upload(file string, backupData []byte) (bool, error) {
	log.Printf("Writing backup to %s/%s", gcsBucketName, file)

	storageCtx, storageCtxCancel := context.WithCancel(context.Background())
	defer storageCtxCancel()

	storageClient, err := storage.NewClient(storageCtx,
		option.WithUserAgent(userAgent),
		option.WithScopes(storage.ScopeReadWrite))
	if err != nil {
		log.Fatal(err)
	}

	ctx := context.Background()
	bucket := storageClient.Bucket(gcsBucketName)
	dataObject := bucket.Object(file).NewWriter(ctx)
	defer dataObject.Close()

	_, err = dataObject.Write(backupData)
	if err != nil {
		log.Println("failed to write backup file")
		return false, err
	}

	return true, nil
}
