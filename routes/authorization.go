package routes

import (
	// "bytes"
	// "encoding/json"
	// "net/http"
	// "strings"
	// "time"

	"github.com/drd-engineering/CAManager/environments"
	"github.com/gin-gonic/gin"
)

// DRDApplicationIdentification is authorization for identify the request is from drd app
func DRDApplicationIdentification(auths ...string) gin.HandlerFunc {
	return func(c *gin.Context) {
		apiKey := c.GetHeader("Drd-Identification")
		if len(apiKey) < 1 {
			c.AbortWithStatus(401)
			return
		}
		if apiKey != environments.Get("DRD_IDENTIFICATION") {
			c.AbortWithStatus(401)
			return
		}
		c.Next()
	}
}

// // AuthorizationBearer is authorization middleware for identify the request client logged in or not
// func AuthorizationBearer(auths ...string) gin.HandlerFunc {
// 	return func(c *gin.Context) {
// 		bearerToken := c.GetHeader("Authorization")
// 		strArr := strings.Split(bearerToken, " ")
// 		if len(strArr) < 2 {
// 			c.Abort()
// 			c.JSON(http.StatusUnauthorized,
// 				gin.H{"message": "Please provide authorization token"})
// 			return
// 		}
// 		timeout := time.Duration(5 * time.Second)
// 		client := http.Client{Timeout: timeout}
// 		request, err := http.NewRequest("POST", "http://drdaccess.com/api/v1/sso/check-token", bytes.NewBuffer([]byte{}))
// 		request.Header.Set("Authorization", bearerToken)
// 		if err != nil {
// 			c.Abort()
// 			c.JSON(http.StatusInternalServerError,
// 				gin.H{"message": "There is some error"})
// 			return
// 		}
// 		response, err := client.Do(request)
// 		if err != nil {
// 			c.Abort()
// 			c.JSON(http.StatusInternalServerError,
// 				gin.H{"message": "There is some error"})
// 			return
// 		}
// 		if response.StatusCode != http.StatusOK {
// 			c.Abort()
// 			c.JSON(http.StatusUnauthorized,
// 				gin.H{"message": "Access Denied"})
// 			return
// 		}
// 		defer response.Body.Close()
// 		var jsonBody map[string]string
// 		json.NewDecoder(response.Body).Decode(&jsonBody)
// 		c.Set("userID", jsonBody["userID"])
// 		c.Next()
// 	}
// }
