package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"

	"github.com/jasonhancock/go-nagios"
	"github.com/matryer/m"
	"github.com/pkg/errors"
)

var errNotFound = errors.New("version not found")
var errNotString = errors.New("endpoint-path wasn't a string")

func main() {
	p := nagios.NewPlugin("elk-message", flag.CommandLine)
	p.StringFlag("endpoint", "", "The page to check for your application's Go version. The page must output JSON.")
	p.StringFlag("endpoint-path", "", "The path to the JSON key containing your application's Go version specified in JavaScript notation")
	p.StringFlag("version", "latest", "The expected version. If set to `latest`, the latest-version-url will be consulted")
	p.StringFlag("latest-version-filter", "go1.10", "A prefix filter for the version.  Example `go1.10`")
	p.StringFlag("latest-version-url", "https://golang.org/dl/?mode=json", "The url where one can retrieve the latest version of Go")
	p.StringFlag("tls-client-cert", "", "path to certificate file used to connect to endpoint")
	p.StringFlag("tls-client-key", "", "path to private key file used to connect to endpoint")
	p.StringFlag("tls-client-root-ca-file", "", "path to private certificate authority certificate used to connect to endpoint")
	flag.Parse()

	endpoint := p.OptRequiredString("endpoint")
	endpointPath := p.OptRequiredString("endpoint-path")
	version := p.OptRequiredString("version")

	tlsCert, _ := p.OptString("tls-client-cert")
	tlsKey, _ := p.OptString("tls-client-key")
	tlsCaCert, _ := p.OptString("tls-client-root-ca-file")
	tlsConfig, err := buildTLSConfig(tlsCert, tlsKey, tlsCaCert)
	if err != nil {
		p.Fatal(errors.Wrap(err, "constructing TLS client config"))
	}

	pageData, err := fetchPage(endpoint, tlsConfig)
	if err != nil {
		p.Fatal(errors.Wrap(err, "fetching page"))
	}

	appVersion, err := extractPageVersion(pageData, endpointPath)
	if err != nil {
		p.Fatal(errors.Wrap(err, "extracting version from application page"))
	}

	if version == "latest" {
		latestVersionURL, _ := p.OptString("latest-version-url")
		filterVersion, _ := p.OptString("latest-version-filter")
		version, err = fetchGoVersion(latestVersionURL, filterVersion)
		if err != nil {
			p.Fatal(errors.Wrap(err, "fetching latest go version"))
		}
	}

	code := nagios.OK
	label := "OK"
	if appVersion != version {
		code = nagios.WARNING
		label = "WARNING"
	}

	p.Exit(code, fmt.Sprintf("%s - application_version=%q expected_version=%q", label, appVersion, version))
}

func buildTLSConfig(tlsClientCert, tlsClientKey, tlsClientRootCaFile string) (*tls.Config, error) {
	if tlsClientCert == "" || tlsClientKey == "" || tlsClientRootCaFile == "" {
		return nil, nil
	}

	// Load client cert
	cert, err := tls.LoadX509KeyPair(tlsClientCert, tlsClientKey)
	if err != nil {
		return nil, errors.Wrap(err, "loading keypair")
	}

	// Load CA cert
	caCert, err := ioutil.ReadFile(tlsClientRootCaFile)
	if err != nil {
		return nil, errors.Wrap(err, "reading CA cert")
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	// Setup HTTPS client
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      caCertPool,
	}
	tlsConfig.BuildNameToCertificate()

	return tlsConfig, nil
}

type goDownloadInfo []struct {
	Version string `json:"version"`
	Stable  bool   `json:"stable"`
	Files   []struct {
		Filename string `json:"filename"`
		Os       string `json:"os"`
		Arch     string `json:"arch"`
		Version  string `json:"version"`
		Sha256   string `json:"sha256"`
		Size     int    `json:"size"`
		Kind     string `json:"kind"`
	} `json:"files"`
}

func fetchGoVersion(url, filter string) (string, error) {
	client := &http.Client{}
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return "", errors.Wrap(err, "constructing request")
	}

	resp, err := client.Do(req)
	if err != nil {
		return "", errors.Wrap(err, "executing request")
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", errors.New("non-200 response received")
	}

	var results goDownloadInfo
	if decodeErr := json.NewDecoder(resp.Body).Decode(&results); decodeErr != nil {
		return "", decodeErr
	}

	for _, ver := range results {
		if strings.HasPrefix(ver.Version, filter) && ver.Stable {
			return ver.Version, nil
		}
	}

	return "", errors.New(fmt.Sprintf("version not fould that starts with %s", filter))
}

func fetchPage(url string, tlsConfig *tls.Config) (map[string]interface{}, error) {
	client := &http.Client{}
	if tlsConfig != nil {
		client.Transport = &http.Transport{TLSClientConfig: tlsConfig}
	}

	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, errors.Wrap(err, "constructing request")
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, errors.Wrap(err, "executing request")
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, errors.New("non-200 response received")
	}

	data := make(map[string]interface{})
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return nil, errors.Wrap(err, "decoding response")
	}

	return data, nil
}

func extractPageVersion(data map[string]interface{}, path string) (string, error) {
	version, ok := m.GetOK(data, path)
	if !ok {
		return "", errNotFound
	}

	vStr, ok := version.(string)
	if !ok {
		return "", errNotString
	}

	return vStr, nil
}
