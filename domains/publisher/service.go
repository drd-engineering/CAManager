package publisher

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"github.com/jinzhu/gorm"
	"math/big"
	"net/http"
	"time"

	"github.com/drd-engineering/CAManager/db"
	"github.com/drd-engineering/CAManager/environments"
	"github.com/gin-gonic/gin"
)

// PublishNewCertificate is service that serving to publish new certificate for new user along with key pairs
func PublishNewCertificate(c *gin.Context) {
	var input RequesterNewCertificate
	c.ShouldBindJSON(&input)

	if len(input.UserID) == 0 {
		c.Abort()
		c.JSON(http.StatusBadRequest,
			gin.H{"message": "target user id needed"})
		return
	}
	dbInstance := db.GetDb()
	newUser := db.User{ID: input.UserID}
	go dbInstance.Create(&newUser)

	certificate, privateKey, err := createCertificateForUser(dbInstance, &newUser)
	if err != nil {
		c.Abort()
		c.JSON(http.StatusInternalServerError,
			gin.H{"message": err.Error()})
		return
	}
	var pemPrivateBlock = pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PublicKey(&privateKey.PublicKey),
	}
	privateKeyEncoded := pem.EncodeToMemory(&pemPrivateBlock)

	responseReturn := ResponseCertificateCreation{
		PrivateKey:  string(privateKeyEncoded),
		Certificate: string(certificate),
	}

	c.JSON(http.StatusOK, responseReturn)
}

func generateNewKey(bitSize int) (*rsa.PrivateKey, error) {
	var privateKey *rsa.PrivateKey
	var err error
	if privateKey, err = rsa.GenerateKey(rand.Reader, 4096); err != nil {
		return nil, err
	}
	// Validate Private Key -- Sanity checks on the key
	if err = privateKey.Validate(); err != nil {
		return nil, err
	}
	// Precompute some calculations speeds up private key operations in the future
	privateKey.Precompute()

	return privateKey, nil
}

func createUniqueCertificate(dbInstance *gorm.DB) (certificate *x509.Certificate) {
	var countCertificate int
	var certificateID *big.Int
	for i := 0; i < 3; i++ {
		certificateID = big.NewInt(1)
		dbInstance.Where("id = ?", *certificateID).Count(&countCertificate)
		if countCertificate < 1 {
			break
		}
	}
	if certificateID == nil {
		return nil
	}
	certificate = &x509.Certificate{
		SerialNumber:       certificateID,
		SignatureAlgorithm: x509.SHA512WithRSA,
		NotBefore:          time.Now().Add(-10 * time.Second),
		NotAfter:           time.Now().AddDate(1, 0, 0),
		KeyUsage:           x509.KeyUsageDigitalSignature,
		ExtKeyUsage:        []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
		IsCA:               false,
	}
	return certificate
}
func createCertificateForUser(dbInstance *gorm.DB, userDB *db.User) (certificate []byte, privateKey *rsa.PrivateKey, err error) {
	privateKey, err = generateNewKey(2048)
	if err != nil {
		return nil, nil, err
	}
	rootCA, err := environments.LoadRootCA()
	if err != nil {
		return nil, nil, err
	}

	userCertificate := createUniqueCertificate(dbInstance)
	certificate, err = x509.CreateCertificate(rand.Reader, rootCA, userCertificate, &privateKey.PublicKey, &privateKey)
	if err != nil {
		return nil, nil, err
	}
	b := pem.Block{Type: "CERTIFICATE", Bytes: certificate}
	certificateEncoded := pem.EncodeToMemory(&b)
	certificateDb := db.Certificate{ID: *userCertificate.SerialNumber, Instance: string(certificateEncoded)}
	go dbInstance.Create(certificateDb)

	var pemPublicBlock = pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: x509.MarshalPKCS1PublicKey(&privateKey.PublicKey),
	}
	publicKeyEncoded := pem.EncodeToMemory(&pemPublicBlock)

	userDB.CertificateID = certificateDb.ID
	userDB.Certificate = certificateDb
	userDB.PublicKey = string(publicKeyEncoded)
	go dbInstance.Update(userDB)

	return certificate, privateKey, err
}

// RenewUserCertificate is service for requesting to publish new CA for the user exist
func RenewUserCertificate(c *gin.Context) {
	var input RequesterRenewing
	c.ShouldBindJSON(&input)

	if len(input.UserID) == 0 {
		c.Abort()
		c.JSON(http.StatusBadRequest,
			gin.H{"message": "target user id needed"})
		return
	}

	dbInstance := db.GetDb()
	var userDb db.User
	var oldCertificate db.Certificate

	dbInstance.Where("id = ?", input.UserID).First(&userDb)
	if len(userDb.ID) == 0 {
		c.Abort()
		c.JSON(http.StatusBadRequest,
			gin.H{"message": "target user id needed"})
		return
	}
	oldCertificate = userDb.Certificate

	newCertificate, newPrivateKey, err := createCertificateForUser(dbInstance, &userDb)
	if err != nil {
		c.Abort()
		c.JSON(http.StatusInternalServerError,
			gin.H{"message": err.Error()})
		return
	}
	dbInstance.Delete(oldCertificate)

	var pemPrivateBlock = pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PublicKey(&newPrivateKey.PublicKey),
	}
	privateKeyEncoded := pem.EncodeToMemory(&pemPrivateBlock)

	responseReturn := ResponseCertificateCreation{
		PrivateKey:  string(privateKeyEncoded),
		Certificate: string(newCertificate),
	}

	c.JSON(http.StatusOK, responseReturn)
}
