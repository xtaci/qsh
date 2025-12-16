package crypto

import (
	"crypto/rand"
	"errors"
	"math/big"
)

const (
	MinPadCount = 1024
	MaxPadCount = 2048
)

var primePadCounts = generatePrimePadCounts()

// generatePrimePadCounts generates a slice of prime numbers between MinPadCount and MaxPadCount.
func generatePrimePadCounts() []uint16 {
	var primes []uint16
	for n := MinPadCount; n <= MaxPadCount; n++ {
		if isPrime(n) {
			primes = append(primes, uint16(n))
		}
	}
	return primes
}

// isPrime checks if a number is prime.
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

// RandomPrimePadCount returns a random prime number between MinPadCount and MaxPadCount.
func RandomPrimePadCount() (uint16, error) {
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

// ValidatePadCount checks if the given pad count is a prime number within the valid range.
func ValidatePadCount(p uint16) bool {
	return int(p) >= MinPadCount && int(p) <= MaxPadCount && isPrime(int(p))
}
