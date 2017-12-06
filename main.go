// slurp s3 bucket enumerator
// Copyright (C) 2017 8c30ff1057d69a6a6f6dc2212d8ec25196c542acb8620eb4148318a4b10dd131
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.
//

package main

import (
	"bufio"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/CaliDog/certstream-go"
	"github.com/jmoiron/jsonq"
	"github.com/joeguo/tldextract"

	log "github.com/Sirupsen/logrus"
	"github.com/Workiva/go-datastructures/queue"
)

var exit bool
var dQ *queue.Queue
var dbQ *queue.Queue
var permutatedQ *queue.Queue
var extract *tldextract.TLDExtract
var checked int64
var sem chan int
var action string
var extension string

type Domain struct {
	CN     string
	Domain string
	Suffix string
}

type PermutatedDomain struct {
	Permutation string
	Domain      Domain
}

// JSONBucket for interesting JSON data, send to Elasticsearch
type JSONBucket struct {
	URL      string
	Name     string
	FileName string
	FileExt  string
}

// S3BucketXML struct defines all contents
type S3BucketXML struct {
	XMLName  xml.Name   `xml:"ListBucketResult"`
	Name     string     `xml:"Name"`
	Contents []Contents `xml:"Contents"`
}

// Contents looks for the Key value which is the file name
type Contents struct {
	XMLName xml.Name `xml:"Contents"`
	File    string   `xml:"Key"`
}

var rootCmd = &cobra.Command{
	Use:   "slurp",
	Short: "slurp",
	Long:  `slurp`,
	Run: func(cmd *cobra.Command, args []string) {
		action = "NADA"
	},
}

var certstreamCmd = &cobra.Command{
	Use:   "certstream",
	Short: "Uses certstream to find s3 buckets in real-time",
	Long:  "Uses certstream to find s3 buckets in real-time",
	Run: func(cmd *cobra.Command, args []string) {
		action = "CERTSTREAM"
	},
}

var manualCmd = &cobra.Command{
	Use:   "domain",
	Short: "Takes a domain as input and attempts to find its s3 buckets",
	Long:  "Takes a domain as input and attempts to find its s3 buckets",
	Run: func(cmd *cobra.Command, args []string) {
		action = "MANUAL"
	},
}

var (
	cfgDomain string
)

func getFlagBool(cmd *cobra.Command, flag string) bool {
	f := cmd.Flags().Lookup(flag)
	if f == nil {
		log.Fatal("Error with flag")
	}
	// Caseless compare.
	if strings.ToLower(f.Value.String()) == "true" {
		return true
	}
	return false
}

func setFlags() {
	manualCmd.PersistentFlags().StringVar(&cfgDomain, "domain", "", "Domain to enumerate s3 bucks with")
	rootCmd.PersistentFlags().Bool("ext", false, "Uses the interestingext.txt to search s3 buckets for extenion matches")
}

// PreInit initializes goroutine concurrency and initializes cobra
func PreInit() {
	setFlags()

	helpCmd := rootCmd.HelpFunc()

	var helpFlag bool

	newHelpCmd := func(c *cobra.Command, args []string) {
		helpFlag = true
		helpCmd(c, args)
	}
	rootCmd.SetHelpFunc(newHelpCmd)

	// certstreamCmd command help
	helpCertstreamCmd := certstreamCmd.HelpFunc()
	newCertstreamHelpCmd := func(c *cobra.Command, args []string) {
		helpFlag = true
		helpCertstreamCmd(c, args)
	}
	certstreamCmd.SetHelpFunc(newCertstreamHelpCmd)

	// manualCmd command help
	helpManualCmd := manualCmd.HelpFunc()
	newManualHelpCmd := func(c *cobra.Command, args []string) {
		helpFlag = true
		helpManualCmd(c, args)
	}
	manualCmd.SetHelpFunc(newManualHelpCmd)

	// Add subcommands
	rootCmd.AddCommand(certstreamCmd)
	rootCmd.AddCommand(manualCmd)

	err := rootCmd.Execute()

	if err != nil {
		log.Fatal(err)
	}

	if helpFlag {
		os.Exit(0)
	}
}

// GetXML reads the s3 bucket page:
// https://stackoverflow.com/a/42718113
func GetXML(url string) ([]byte, error) {
	resp, err := http.Get(url)
	if err != nil {
		return []byte{}, fmt.Errorf("GET error: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return []byte{}, fmt.Errorf("Status error: %v", resp.StatusCode)
	}

	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return []byte{}, fmt.Errorf("Read body: %v", err)
	}

	return data, nil
}

// StreamCerts takes input from certstream and stores it in the queue
func StreamCerts() {
	// The false flag specifies that we don't want heartbeat messages.
	stream, errStream := certstream.CertStreamEventStream(false)

	for {
		select {
		case jq := <-stream:
			domain, err2 := jq.String("data", "leaf_cert", "subject", "CN")

			if err2 != nil {
				if !strings.Contains(err2.Error(), "Error decoding jq string") {
					continue
				}
				log.Error(err2)
			}

			//log.Infof("Domain: %s", domain)
			//log.Info(jq)

			dQ.Put(domain)

		case err := <-errStream:
			log.Error(err)
		}
	}
}

// ProcessQueue processes data stored in the queue
func ProcessQueue() {
	for {
		cn, err := dQ.Get(1)

		if err != nil {
			log.Error(err)
			continue
		}

		//log.Infof("Domain: %s", cn[0].(string))

		if !strings.Contains(cn[0].(string), "cloudflaressl") && !strings.Contains(cn[0].(string), "xn--") && len(cn[0].(string)) > 0 && !strings.HasPrefix(cn[0].(string), "*.") && !strings.HasPrefix(cn[0].(string), ".") {
			result := extract.Extract(cn[0].(string))
			//domain := fmt.Sprintf("%s.%s", result.Root, result.Tld)

			d := Domain{
				CN:     cn[0].(string),
				Domain: result.Root,
				Suffix: result.Tld,
			}

			dbQ.Put(d)
		}

		//log.Infof("CN: %s\tDomain: %s", cn[0].(string), domain)
	}
}

// StoreInDB stores the dbQ results into the database
func StoreInDB() {
	for {
		dstruct, err := dbQ.Get(1)

		if err != nil {
			log.Error(err)
			continue
		}

		var d Domain = dstruct[0].(Domain)

		//log.Infof("CN: %s\tDomain: %s.%s", d.CN, d.Domain, d.Suffix)

		pd := PermutateDomain(d.Domain, d.Suffix)

		for p := range pd {
			permutatedQ.Put(PermutatedDomain{
				Permutation: pd[p],
				Domain:      d,
			})
		}
	}
}

// ReadExt reads the file interestingext.txt for interesting extensions
// into an array
func ReadExt(path string) ([]string, error) {
	// Open File
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	// Read lines and append to results
	scanner := bufio.NewScanner(file)
	scanner.Split(bufio.ScanWords)
	var result []string
	for scanner.Scan() {
		x := scanner.Text()
		result = append(result, x)
	}
	return result, scanner.Err()
}

// CheckPermutations runs through all permutations checking them for PUBLIC/FORBIDDEN buckets
func CheckPermutations() {
	var max = runtime.NumCPU() * 10
	sem = make(chan int, max)

	// Checking for interesting file extensions?
	extension_check := getFlagBool(rootCmd, "ext")

	// Get array of interesting file extensions (interestingext.txt)
	// Create map (all true)
	extensions, err := ReadExt("interestingext.txt")
	if err != nil {
		log.Error(err)
	}
	set := make(map[string]bool)
	for _, v := range extensions {
		set[v] = true
	}

	for {
		sem <- 1
		dom, err := permutatedQ.Get(1)

		if err != nil {
			log.Error(err)
		}

		tr := &http.Transport{
			IdleConnTimeout:       3 * time.Second,
			ResponseHeaderTimeout: 3 * time.Second,
			MaxIdleConnsPerHost:   max,
			ExpectContinueTimeout: 1 * time.Second,
		}
		client := &http.Client{
			Transport: tr,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}

		go func(pd PermutatedDomain) {

			req, err := http.NewRequest("GET", "http://s3-1-w.amazonaws.com", nil)

			if err != nil {
				if !strings.Contains(err.Error(), "time") {
					log.Error(err)
				}

				permutatedQ.Put(pd)
				<-sem
				return
			}

			req.Host = pd.Permutation
			//req.Header.Add("Host", host)

			resp, err1 := client.Do(req)

			if err1 != nil {
				if strings.Contains(err1.Error(), "time") {
					permutatedQ.Put(pd)
					<-sem
					return
				}

				log.Error(err1)
				permutatedQ.Put(pd)
				<-sem
				return
			}

			defer resp.Body.Close()

			//log.Infof("%s (%d)", host, resp.StatusCode)

			if resp.StatusCode == 307 {
				loc := resp.Header.Get("Location")

				req, err := http.NewRequest("GET", loc, nil)

				if err != nil {
					log.Error(err)
				}

				resp, err1 := client.Do(req)

				if err1 != nil {
					if strings.Contains(err1.Error(), "time") {
						permutatedQ.Put(pd)
						<-sem
						return
					}

					log.Error(err1)
					permutatedQ.Put(pd)
					<-sem
					return
				}

				defer resp.Body.Close()

				if resp.StatusCode == 200 {
					log.Infof("\033[32m\033[1mPUBLIC\033[39m\033[0m %s (\033[33mhttp://%s.%s\033[39m)", loc, pd.Domain.Domain, pd.Domain.Suffix)

					// Fetch bucket as XML
					if xmlBytes, err := GetXML(loc); err != nil {
						log.Infof("\033[31m\033[1mFAILED\033[39m\033[0 to view S3 bucket: %v", err)
					} else {
						log.Infof("\033[32m\033[1mPARSING\033[39m\033[0m S3 Bucket: %s", loc)

						// Parse XML file using struct -> result
						var result S3BucketXML
						xml.Unmarshal(xmlBytes, &result)
						// If there is files in Contents
						if len(result.Contents) > 0 {
							// Loop over Contents for each file name and file extension
							for i := 0; i < len(result.Contents); i++ {
								basename := result.Contents[i].File
								ext := string(filepath.Ext(basename))
								// Debug
								//fmt.Println("Filename: " + basename)
								//fmt.Println("Extension: " + ext)
								if extension_check {
									if ext != "" {
										if set[ext] {
											log.Infof("Interesting file ext (%s) found @ \033[33mhttp://%s.%s%s\033[39m", ext, pd.Domain.Domain, pd.Domain.Suffix, basename)
										}
									}
								}
							}
						}
					}
				} else if resp.StatusCode == 403 {
					log.Infof("\033[31m\033[1mFORBIDDEN\033[39m\033[0m http://%s (\033[33mhttp://%s.%s\033[39m)", pd.Permutation, pd.Domain.Domain, pd.Domain.Suffix)
				}
			} else if resp.StatusCode == 403 {
				log.Infof("\033[31m\033[1mFORBIDDEN\033[39m\033[0m http://%s (\033[33mhttp://%s.%s\033[39m)", pd.Permutation, pd.Domain.Domain, pd.Domain.Suffix)
			} else if resp.StatusCode == 503 {
				log.Info("too fast")
				permutatedQ.Put(pd)
			}

			checked = checked + 1

			<-sem
		}(dom[0].(PermutatedDomain))
	}
}

// PermutateDomain returns all possible domain permutations
func PermutateDomain(domain, suffix string) []string {
	jsondata, err := ioutil.ReadFile("./permutations.json")

	if err != nil {
		log.Fatal(err)
	}

	data := map[string]interface{}{}
	dec := json.NewDecoder(strings.NewReader(string(jsondata)))
	dec.Decode(&data)
	jq := jsonq.NewQuery(data)

	s3url, err := jq.String("s3_url")

	if err != nil {
		log.Fatal(err)
	}

	var permutations []string

	perms, err := jq.Array("permutations")

	if err != nil {
		log.Fatal(err)
	}

	// Our list of permutations
	for i := range perms {
		permutations = append(permutations, fmt.Sprintf(perms[i].(string), domain, s3url))
	}

	// Permutations that are not easily put into the list
	permutations = append(permutations, fmt.Sprintf("%s.%s.%s", domain, suffix, s3url))
	permutations = append(permutations, fmt.Sprintf("%s.%s", strings.Replace(fmt.Sprintf("%s.%s", domain, suffix), ".", "", -1), s3url))

	return permutations
}

// Init does low level initialization before we can run
func Init() {
	var err error

	dQ = queue.New(1000)

	dbQ = queue.New(1000)

	permutatedQ = queue.New(1000)

	extract, err = tldextract.New("./tld.cache", false)

	if err != nil {
		log.Fatal(err)
	}
}

// PrintJob prints the queue sizes
func PrintJob() {
	for {
		log.Infof("dQ size: %d", dQ.Len())
		log.Infof("dbQ size: %d", dbQ.Len())
		log.Infof("permutatedQ size: %d", permutatedQ.Len())
		log.Infof("Checked: %d", checked)

		time.Sleep(10 * time.Second)
	}
}

func main() {
	PreInit()

	switch action {
	case "CERTSTREAM":
		log.Info("Initializing....")
		Init()

		//go PrintJob()

		log.Info("Starting to stream certs....")
		go StreamCerts()

		log.Info("Starting to process queue....")
		go ProcessQueue()

		//log.Info("Starting to stream certs....")
		go StoreInDB()

		log.Info("Starting to process permutations....")
		go CheckPermutations()

		for {
			if exit {
				break
			}

			time.Sleep(1 * time.Second)
		}
	case "MANUAL":
		if cfgDomain == "" {
			log.Fatal("You must specify a domain to enumerate")
		}

		Init()

		result := extract.Extract(cfgDomain)

		if result.Root == "" || result.Tld == "" {
			log.Fatal("Is the domain even valid bruh?")
		}

		d := Domain{
			CN:     cfgDomain,
			Domain: result.Root,
			Suffix: result.Tld,
		}

		dbQ.Put(d)

		//log.Info("Starting to process queue....")
		//go ProcessQueue()

		//log.Info("Starting to stream certs....")
		go StoreInDB()

		log.Info("Starting to process permutations....")
		go CheckPermutations()

		for {
			// 3 second hard sleep; added because sometimes it's possible to switch exit = true
			// in the time it takes to get from dbQ.Put(d); we can't have that...
			// So, a 3 sec sleep will prevent an pre-mature exit; but in most cases shouldn't really be noticable
			time.Sleep(3 * time.Second)

			if exit {
				break
			}

			if permutatedQ.Len() != 0 || dbQ.Len() > 0 || len(sem) > 0 {
				if len(sem) == 1 {
					<-sem
				}
			} else {
				exit = true
			}
		}

	case "NADA":
		log.Info("Check help")
		os.Exit(0)
	}
}
