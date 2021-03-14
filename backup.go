// GET /v1/sys/storage/raft/snapshot HTTP/1.1
package main

import (
	"fmt"
	"context"
	"net/http"
	"io/ioutil"
	"log"
	"time"

	option "google.golang.org/api/option"
	storage "cloud.google.com/go/storage"
)

var (
	backupTicker time.Ticker
)

func Backup(ch <-chan bool) (bool, error) {
	backupTicker := time.NewTicker(1 * time.Minute)

	go func() {
		for {
			select {
			case <- ch:
				backupTicker.Stop()
				return
			case t := <-backupTicker.C:
				log.Printf("Backup running at %t", t.String())

				req, err :=  http.NewRequest("GET", vaultAddr+"/v1/sys/storage/raft/snapshot", nil)
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
				Upload(fileName, bodyBuffer)
			}
		}
	}()

	log.Println("Backups initialised")
	return true, nil
}

func Upload(file string, backupData []byte) (bool, error) {
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

