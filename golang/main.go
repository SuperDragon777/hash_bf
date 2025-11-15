package main

import (
	"bufio"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"hash"
	"os"
	"strings"
)

const (
	MAX_LEN     = 6
	CHARSET     = "abcdefghijklmnopqrstuvwxyz0123456789"
	CHARSET_LEN = 36
)

type Algorithm struct {
	Name string
	Hash func() hash.Hash
}

func bytesToHex(data []byte) string {
	return fmt.Sprintf("%x", data)
}

func calculateTotal(maxLen int) int64 {
	var total int64 = 0
	power := 1
	for i := 1; i <= maxLen; i++ {
		power *= CHARSET_LEN
		total += int64(power)
	}
	return total
}

func generateCombinations(length int, targetHash string, algorithms []Algorithm) {
	pwd := make([]byte, length)
	for i := 0; i < length; i++ {
		pwd[i] = CHARSET[0]
	}

	total := calculateTotal(MAX_LEN)
	var attempt int64 = 0

	for {
		attempt++

		if attempt%10000 == 0 {
			percent := (float64(attempt) / float64(total)) * 100
			fmt.Printf("    [%d] %.1f%%\r", attempt, percent)
		}

		pwd_str := string(pwd)
		for _, algo := range algorithms {
			h := algo.Hash()
			h.Write([]byte(pwd_str))
			hashHex := bytesToHex(h.Sum(nil))

			if hashHex == targetHash {
				fmt.Printf("\n[+] FOUND!\n")
				fmt.Printf("    Password: %s\n", pwd_str)
				fmt.Printf("    Algorithm: %s\n", algo.Name)
				fmt.Printf("    Attempts: %d\n", attempt)
				return
			}
		}

		pos := length - 1
		for pos >= 0 {
			charIdx := strings.Index(CHARSET, string(pwd[pos]))
			if charIdx < CHARSET_LEN-1 {
				pwd[pos] = CHARSET[charIdx+1]
				break
			} else {
				pwd[pos] = CHARSET[0]
				pos--
			}
		}

		if pos < 0 {
			break
		}
	}

	fmt.Printf("\n[-] Not found (checked: %d)\n", attempt)
}

func main() {
	fmt.Println("HASH BRUTE FORCER")

	reader := bufio.NewReader(os.Stdin)
	fmt.Print("\nEnter hash to crack: ")
	userHash, _ := reader.ReadString('\n')
	userHash = strings.TrimSpace(userHash)

	if userHash == "" {
		fmt.Println("[!] No hash entered")
		return
	}

	algorithms := []Algorithm{
		{"MD5", md5.New},
		{"SHA1", sha1.New},
		{"SHA256", sha256.New},
		{"SHA512", sha512.New},
	}

	fmt.Println("\n[*] Checking all algorithms...")

	for length := 1; length <= MAX_LEN; length++ {
		fmt.Printf("\n[*] Checking passwords of length %d...\n", length)
		generateCombinations(length, userHash, algorithms)
	}
}
