package validator

import ()

// ValidateOwnerRequest is input definition from json body ValidateTheOwner request
type ValidateOwnerRequest struct {
	UserID      string `json:"userID"`
	Certificate string `json:"certificate"`
}

// ValidateCertificateDate is input definition from json body ValidateCertificateStillValid request
type ValidateCertificateDate struct {
	Certificate string `json:"certificate"`
}
