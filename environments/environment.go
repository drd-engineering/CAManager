package environments

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"math/big"
	"os"
	"time"

	"github.com/joho/godotenv"
)

// LoadEnvironmentVariableFile should be run once before you use the environment variable
func LoadEnvironmentVariableFile() {
	releaseType := os.Getenv("RELEASE_TYPE")
	fileEnvLocation := "./environments/.env." + releaseType
	err := godotenv.Load(fileEnvLocation)
	if err != nil {
		fmt.Println("Error loading " + fileEnvLocation + " file")
	}
}

// Get environment variable from environments file loaded
func Get(key string) string {
	return os.Getenv(key)
}

// Set additional environment variable needed
func Set(key string, value string) {
	os.Setenv(key, value)
}

// CreateRootCA is environment creator for making a new root CA certificate file
func CreateRootCA() {
	var rootTemplate = x509.Certificate{
		Version:      1,
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Country:      []string{"INA"},
			Organization: []string{"PT. Artha Amita Sempurna", "DRD"},
			CommonName:   "Root CA",
		},
		SignatureAlgorithm:    x509.SHA512WithRSA,
		NotBefore:             time.Now().Add(-10 * time.Second),
		NotAfter:              time.Now().AddDate(15, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	privateKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		panic(err)
	}
	certBytes, err := x509.CreateCertificate(rand.Reader, &rootTemplate, &rootTemplate, privateKey.PublicKey, privateKey)
	if err != nil {
		panic("Failed to create certificate:" + err.Error())
	}
	b := pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBytes,
	}
	fileLocation := "./RootCAStorage/"
	fileName := "validRootCA.crt"
	certificateFile, err := os.Create(fileLocation + fileName)
	if err != nil {
		panic(err)
	}
	err = pem.Encode(certificateFile, &b)
	if err != nil {
		panic(err)
	}
}

// LoadRootCA is environment tools that will help to get The ROOT CA in the environments
func LoadRootCA() (*x509.Certificate, error) {
	fileLocation := "./RootCAStorage/"
	fileName := "validRootCA.crt"
	r, err := ioutil.ReadFile(fileLocation + fileName)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(r)
	cert, err := x509.ParseCertificate(block.Bytes)
	return cert, err
}
