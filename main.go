// Making Proof of Work solution discovery more predictable
//
// One of the problems with PoW is that the solution time is pretty
// unpredictable. This is because solution times are distributed
// exponentially. If a target solution time over a population is 10 minutes
// (like Bitcoin), then solutions might be found in seconds, and at other
// times in hours.
//
// What may be preferred are solutions that only vary by some smaller
// percentage.  While it might be possible for a participant to find a
// solution quickly, we would rather that be far, far more rare than
// simple PoW provides, a.k.a simply finding a hash solution.
//
// This code demonstrates that if what is required is not just finding a
// solution, but several solutions, then the difference between the outliers
// (the minimum time and the maximum time required to find a solution) can
// be narrowed, and the reporting of solutions can be more in line with
// the hash power represented by an individual solution.

package main

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"time"

	humanize "github.com/dustin/go-humanize"
)

func main() {
	numSamples := 1000 // How many samples are required

	fmt.Printf("%11s %18s %15s %15s %15s %10s %10s\n", "#solutions", "samples", "min(ns)", "max(ns)", "avg(ns)", "min", "max")
	fmt.Printf("%11s %18s %15s %15s %15s %10s %10s\n\n", "", "", "", "", "", "% of avg", "% of avg")
	var hashOfData [32]byte = [32]byte{1, 2, 3}     // Start with any random seed

	for i := 1; i <= 512; i *= 2 { //
		var min, max, sum time.Duration                 // Keep min, max and sum all the times required
		diff := uint64(0x003FFFFFFFFFFFFF * float64(i)) // Adjust difficulty for solutions required
		for j := 0; j < numSamples; j++ {
			hashOfData = sha256.Sum256(hashOfData[:]) // Get a new hash

			start := time.Now()              // time how long it takes to get a solution
			solution(hashOfData[:], diff, i) // get a solution (validation not required for a test)
			t := time.Since(start)

			if min == 0 || min > t { // Get the block time, and collect min, max, and sum values
				min = t
			}
			if max == 0 || max < t {
				max = t
			}
			sum += t

		}

		// Print each entry in the table for this number of solutions
		avg := sum / time.Duration(numSamples)
		fmt.Printf("%11d %18s %15s %15s %15s %9.2f%% %9.2f%%\n",
			i,
			humanize.Comma(int64(numSamples)),
			humanize.Comma(int64(min)),
			humanize.Comma(int64(max)),
			humanize.Comma(int64(avg)),
			float64(min)/float64(avg)*100,
			float64(max)/float64(avg)*100)
	}
}

// Returns a nonce that meets the proof of work requirement
// for the given difficulty and number of salts
func solution(data []byte, difficulty uint64, numSolutions int) (nonces []uint64) {
	var buff [40]byte    // Buffer for combining the data hash and nonce
	copy(buff[8:], data) // Put data hash into the buffer.  All calculations use the data
	var nonce uint64     // The nonce will be walked upward from zero

	for {
		binary.BigEndian.PutUint64(buff[:], nonce) // Add the current nonce
		v := sha256.Sum256(buff[:])                // Hash the buffer (data + nonce)
		d := binary.BigEndian.Uint64(v[:])         // d = difficulty of this hash
		if d < difficulty {                        // look for d below the difficulty target
			nonces = append(nonces, nonce)   // If lower, add the nonce to solution list
			if len(nonces) >= numSolutions { // If numSolutions are found, submit
				break
			}
		}
		nonce++ // Keep looking through the nonces
	}
	return nonces
}
