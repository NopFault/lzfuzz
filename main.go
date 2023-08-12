package main

import (
	"bufio"
	"crypto/md5"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
)

type Fuzzer struct {
	link      string
	wordlist  string
	ua        string
	status    string
	method    string
	redirects bool
}

func (f *Fuzzer) contentsOf(url string) (int, string) {

	req, _ := http.NewRequest(f.method, url, nil)

	// to prevent EOF
	req.Close = true

	req.Header.Set("User-Agent", f.ua)

	client := &http.Client{}

	if f.redirects == false {

		client = &http.Client{
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			}}
	}

	resp, err := client.Do(req)

	if err != nil {
		panic(err)
	}

	defer resp.Body.Close()

	b, _ := io.ReadAll(resp.Body)

	var hash string = ""
	if f.method != "HEAD" {
		hasher := md5.New()
		hasher.Write([]byte(b))
		hash = hex.EncodeToString(hasher.Sum(nil))
	}

	return resp.StatusCode, hash

}

func (f *Fuzzer) Fuzz() {

	wordlist, err := os.Open(f.wordlist)
	if err != nil {
		panic("[ error ] Cant read a file")
	}

	wordScanner := bufio.NewScanner(wordlist)
	wordScanner.Split(bufio.ScanLines)

	var wg = &sync.WaitGroup{}
	for wordScanner.Scan() {

		wg.Add(1)

		go func(word string) {
			status, hash := f.contentsOf(strings.Replace(f.link, "[LZF]", word, -1))
			if len(f.status) > 0 {
				if len(strings.Split(f.status, strconv.Itoa(status))) >= 2 {
					fmt.Println("[ " + strconv.Itoa(status) + " ]: " + word + "\t | " + hash)
				}
			} else {
				fmt.Println("[ " + strconv.Itoa(status) + " ]: " + word + "\t | " + hash)
			}
			wg.Done()
		}(wordScanner.Text())
	}
	wg.Wait()

}

func main() {
	var fuzzlink string
	var wordfile string
	var useragent string
	var status string
	var method string
	var follow_redirects bool

	flag.StringVar(&fuzzlink, "h", "", "Provide a fuzzing link: (https://www.example.com/{LZF})")
	flag.StringVar(&wordfile, "wf", "", "Provide a wordlist for a fuzzer")
	flag.StringVar(&useragent, "ua", "Mozilla/5.0 (iPhone; CPU iPhone OS 13_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) FxiOS/116.0 Mobile/15E148 Safari/605.1.15", "Set custom user-agent")
	flag.StringVar(&status, "s", "", "Set status to be shown for e.x.: 200,301... or leave empty for all")
	flag.StringVar(&method, "m", "GET", "You can change HTTP method ")
	flag.BoolVar(&follow_redirects, "f", false, "Follow the redirects")

	flag.Parse()

	if len(fuzzlink) > 10 && len(wordfile) > 0 {

		fmt.Println("Fuzzing link: " + fuzzlink)
		fmt.Println("with wordlist: " + wordfile)

		var fuzzer Fuzzer = Fuzzer{
			link:      fuzzlink,
			wordlist:  wordfile,
			ua:        useragent,
			status:    status,
			method:    method,
			redirects: follow_redirects,
		}

		fuzzer.Fuzz()

	} else {

		fmt.Println("Wrong parameters passed:\n ")
		flag.PrintDefaults()
	}

}
