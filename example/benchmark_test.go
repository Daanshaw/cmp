package main

import (
	"fmt"
	"github.com/taurusgroup/multi-party-sig/internal/test"
	"github.com/taurusgroup/multi-party-sig/pkg/party"
	"github.com/taurusgroup/multi-party-sig/pkg/pool"
	"sync"
	"testing"
)

func BenchmarkProtocol(b *testing.B) {
	numParties := 3 // Set the number of parties
	threshold := 2  // Set the threshold

	// Create a slice of party IDs with the specified number of parties
	ids := make(party.IDSlice, numParties)
	for i := 0; i < numParties; i++ {
		ids[i] = party.ID(fmt.Sprintf("p%d", i+1))
	}

	messageToSign := []byte("hello") // Define the message to be signed
	net := test.NewNetwork(ids)      // Create a new test network with the given party IDs

	var wg sync.WaitGroup // Create a WaitGroup to synchronize the goroutines

	b.ResetTimer() // Reset the benchmark timer to ignore setup time
	for n := 0; n < b.N; n++ {

		// Iterate through the party IDs and start a new goroutine for each party
		for _, id := range ids {
			wg.Add(1) // Increment the WaitGroup counter
			go func(id party.ID) {
				pl := pool.NewPool(0) // Create a new memory pool
				defer pl.TearDown()   // Ensure that the memory pool is cleaned up after the function returns
				if err := All(id, ids, threshold, messageToSign, net, &wg, pl); err != nil {
					b.Error(err) // Report any errors that occur during the benchmark
				}
			}(id)
		}
		wg.Wait() // Wait for all goroutines to complete

	}

}
