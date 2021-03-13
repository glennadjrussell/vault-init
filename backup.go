// GET /v1/sys/storage/raft/snapshot HTTP/1.1
package main

import (
	//"net/http"
	"log"
	"time"
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
				return
			case t := <-backupTicker.C:
				log.Printf("Backup running at %d", t)
				response, err := httpClient.Get(vaultAddr+"/v1/sys/storage/raft/snapshot")
				if response != nil && response.Body != nil {
					response.Body.Close()
				}

				if err != nil {
					log.Println(err)
				}

				log.Println(response.Body)
			}
		}
	}()

	backupTicker.Stop()

	return true, nil
}

func Upload() (bool, error) {
	return false, nil
}

