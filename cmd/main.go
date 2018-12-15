package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/filipovi/simpleca/pkg/ca"
)

func split(s string) (results []string) {
	if len(s) > 0 {
		return strings.Split(s, ",")
	}
	return nil
}

func main() {
	dns := flag.String("dns", "", "Comma separated domain names")
	ips := flag.String("ips", "", "Comma separated IP addresses")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage of %s:\n", os.Args[0])
		fmt.Fprintf(os.Stderr, `
SimpleCA is useful in case you need to generate valid certificates for local development.
As soon as you can use a valid and routable domain name it is advisable to use a service
such as "Let’s Encrypt". At its first execution, it will generate the root keys and
certificate. The keys and certificates used by your web server will be created in a folder
based on the first domain name or IP address provided to the command.

`)
		flag.PrintDefaults()
	}
	flag.Parse()
	if *dns == "" && *ips == "" {
		flag.Usage()
		os.Exit(1)
	}

	simpleCA, err := ca.New()
	if err != nil {
		log.Fatal(err)
	}
	err = simpleCA.GenerateSignedKeyAndCertificat(split(*ips), split(*dns))
	if err != nil {
		log.Fatal(err)
	}
}
