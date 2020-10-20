package publisher

import ()

// RequesterNewCertificate is input definition from json body PublishNewCertificate request
type RequesterNewCertificate struct {
	UserID string `json:"userID"`
}

// ResponseCertificateCreation is response json data after publish new certificate
type ResponseCertificateCreation struct {
	PrivateKey  string `json:"privateKey"`
	Certificate string `json:"certificate"`
}

// RequesterRenewing is input definition from json body RenewUserCertificate request
type RequesterRenewing struct {
	UserID string `json:"userID"`
}
