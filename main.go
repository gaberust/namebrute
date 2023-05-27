package main

import (
	"bufio"
	"flag"
	"fmt"
	"log"
	"math/rand"
	"net"
	"os"
	"strings"
	"sync"
	"time"
)

var wordlist []string
var autoconfirm bool

func usage() {
	fmt.Printf("Usage: %s [OPTION]... [DOMAIN]...\n", os.Args[0])
	flag.PrintDefaults()
}

func randomName(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyz0123456789"
	prng := rand.New(rand.NewSource(time.Now().UnixNano()))
	b := make([]byte, length)
	for i := range b {
		b[i] = charset[prng.Intn(len(charset))]
	}
	return string(b)
}

func confirm(prompt string) bool {
	reader := bufio.NewReader(os.Stdin)
	for {
		fmt.Println(prompt, "(y/n)")
		if autoconfirm {
			return true
		}
		line, err := reader.ReadString('\n')
		if err != nil {
			log.Fatal(err)
		}
		if strings.EqualFold(strings.TrimSpace(line), "y") {
			return true
		}
		if strings.EqualFold(strings.TrimSpace(line), "n") {
			return false
		}
	}
}

func ipInResult(ip net.IP, result []net.IP) bool {
	for _, r := range result {
		if string(ip) == string(r) {
			return true
		}
	}
	return false
}

func loadWords(path string) {
	wordlistContent, err := os.ReadFile(path)
	if err != nil {
		fmt.Printf("Could not read %s.", path)
		os.Exit(1)
	}
	wordlist = strings.Fields(string(wordlistContent))
}

func brute(domain string, words chan string, wildcardIP []net.IP, logger *log.Logger, waitGroup *sync.WaitGroup) {
	defer waitGroup.Done()
	for word := range words {
		result, _ := net.LookupIP(fmt.Sprintf("%s.%s", word, domain))
		if len(wildcardIP) != 0 {
			if !ipInResult(wildcardIP[0], result) {
				logger.Println(fmt.Sprintf("%s.%s", word, domain), result)
			}
			continue
		}
		if len(result) != 0 {
			logger.Println(fmt.Sprintf("%s.%s", word, domain), result)
		}
	}
}

func main() {
	//var recurse bool
	//flag.BoolVar(&recurse, "r", false, "Automatically start new scan on identified subdomains.")
	var threads int
	flag.IntVar(&threads, "t", 1024, "Maximum number of concurrent DNS queries.")
	var wordlistFilePath string
	flag.StringVar(&wordlistFilePath, "w", "", "Wordlist of subdomains to attempt.")
	flag.BoolVar(&autoconfirm, "y", false, "Automatically answer yes to prompts (wildcard bypass, unresolved domain bypass).")
	flag.Usage = usage
	flag.Parse()
	domains := flag.Args()

	loadWords(wordlistFilePath)

	logger := log.New(os.Stdout, "", 0)

	for _, domain := range domains {
		domainIP, _ := net.LookupIP(domain)
		if len(domainIP) == 0 {
			if !confirm(fmt.Sprintf("Failed to resolve %s. Continue brute force on this domain?", domain)) {
				continue
			}
		}

		wildcardTest := fmt.Sprintf("%s.%s", randomName(32), domain)
		wildcardIP, _ := net.LookupIP(wildcardTest)
		if len(wildcardIP) != 0 {
			if !confirm(fmt.Sprintf("Detected wildcard at *.%s %s. Continue brute force on this domain?", domain, wildcardIP)) {
				continue
			}
		}

		var waitGroup sync.WaitGroup
		waitGroup.Add(threads)
		words := make(chan string)
		go func() {
			for _, word := range wordlist {
				words <- word
			}
			close(words)
		}()
		for i := 0; i < threads; i++ {
			go brute(domain, words, wildcardIP, logger, &waitGroup)
		}
		waitGroup.Wait()
	}
}
