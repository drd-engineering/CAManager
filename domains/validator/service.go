package validator

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"time"

	"github.com/drd-engineering/CAManager/db"
	"github.com/drd-engineering/CAManager/environments"
	"github.com/gin-gonic/gin"
)

// ValidateTheOwner is service for checking the given certificate is owned by given user or not
func ValidateTheOwner(c *gin.Context) {
	var input ValidateOwnerRequest
	c.ShouldBindJSON(&input)

	if len(input.UserID) == 0 || len(input.Certificate) == 0 {
		c.Abort()
		c.JSON(http.StatusBadRequest,
			gin.H{"message": "please provide complete input"})
		return
	}

	certificate, err := certificateFromString(input.Certificate)
	if err != nil {
		c.Abort()
		c.JSON(http.StatusBadRequest,
			gin.H{"message": "please provide valid input"})
		return
	}

	var userDB db.User
	dbInstance := db.GetDb()
	dbInstance.Where("id = ?", input.UserID).First(userDB)

	if len(userDB.ID) == 0 {
		c.Abort()
		c.JSON(http.StatusBadRequest,
			gin.H{"message": "please provide valid input"})
		return
	}

	valid, err := validateCertificateIsPublishByUs(certificate)
	if err != nil {
		c.Abort()
		c.JSON(http.StatusInternalServerError,
			gin.H{"message": err.Error()})
		return
	}
	if !valid {
		c.Abort()
		c.JSON(http.StatusBadRequest,
			gin.H{"message": "The certificate is not Published by DRD"})
		return
	}

	dbPublicKey, err := publicKeyFromString(userDB.PublicKey)
	if err != nil {
		c.Abort()
		c.JSON(http.StatusInternalServerError,
			gin.H{"message": err.Error()})
		return
	}

	if certificate.PublicKey.(*rsa.PublicKey).N.Cmp(dbPublicKey.N) == 0 && dbPublicKey.E == certificate.PublicKey.(*rsa.PublicKey).E {
		c.JSON(http.StatusOK, gin.H{"valid": true})
	}
	c.JSON(http.StatusOK, gin.H{"valid": false})
}

// ValidateCertificateStillValid is service for checking the given certificate still valid (not expired)
func ValidateCertificateStillValid(c *gin.Context) {
	var input ValidateCertificateDate
	c.ShouldBindJSON(&input)

	if len(input.Certificate) == 0 {
		c.Abort()
		c.JSON(http.StatusBadRequest,
			gin.H{"message": "please provide complete input"})
		return
	}

	certificate, err := certificateFromString(input.Certificate)
	if err != nil {
		c.Abort()
		c.JSON(http.StatusBadRequest,
			gin.H{"message": "please provide valid input"})
		return
	}

	valid, err := validateCertificateIsPublishByUs(certificate)
	if err != nil {
		c.Abort()
		c.JSON(http.StatusInternalServerError,
			gin.H{"message": err.Error()})
		return
	}
	if !valid {
		c.Abort()
		c.JSON(http.StatusBadRequest,
			gin.H{"message": "The certificate is not Published by DRD"})
		return
	}

	valid = validateCertificateIsNotExpired(certificate)
	if !valid {
		c.JSON(http.StatusOK, gin.H{"valid": false})
	}
	c.JSON(http.StatusOK, gin.H{"valid": true})
}

func certificateFromString(input string) (*x509.Certificate, error) {
	block, _ := pem.Decode([]byte(input))
	certificate, err := x509.ParseCertificate(block.Bytes)
	return certificate, err
}

func publicKeyFromString(input string) (*rsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(input))
	publicKey, err := x509.ParsePKCS1PublicKey(block.Bytes)
	return publicKey, err
}

func validateCertificateIsPublishByUs(certificate *x509.Certificate) (bool, error) {
	rootCA, err := environments.LoadRootCA()
	if err != nil {
		return false, err
	}
	roots := x509.NewCertPool()
	roots.AddCert(rootCA)
	verifyRoot := x509.VerifyOptions{
		Roots: roots,
	}
	if _, err := certificate.Verify(verifyRoot); err != nil {
		return false, nil
	}
	return true, nil
}

func validateCertificateIsNotExpired(certificate *x509.Certificate) bool {
	verifyRoot := x509.VerifyOptions{
		CurrentTime: time.Now(),
	}
	if _, err := certificate.Verify(verifyRoot); err != nil {
		return false
	}
	return true
}
