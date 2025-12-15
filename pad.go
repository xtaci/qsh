package main

import (
	"crypto/rand"
	"errors"
	"math/big"
)

const (
	minPadCount = 1024
	maxPadCount = 2048
)

var primePadCounts = generatePrimePadCounts()

func generatePrimePadCounts() []uint16 {
	var primes []uint16
	for n := minPadCount; n <= maxPadCount; n++ {
		if isPrime(n) {
			primes = append(primes, uint16(n))
		}
	}
	return primes
}

func isPrime(n int) bool {
	if n < 2 {
		return false
	}
	for i := 2; i*i <= n; i++ {
		if n%i == 0 {
			return false
		}
	}
	return true
}

func randomPrimePadCount() (uint16, error) {
	if len(primePadCounts) == 0 {
		return 0, errors.New("no prime pad counts available")
	}
	max := big.NewInt(int64(len(primePadCounts)))
	idx, err := rand.Int(rand.Reader, max)
	if err != nil {
		return 0, err
	}
	return primePadCounts[idx.Int64()], nil
}

func validatePadCount(p uint16) bool {
	return int(p) >= minPadCount && int(p) <= maxPadCount && isPrime(int(p))
}
