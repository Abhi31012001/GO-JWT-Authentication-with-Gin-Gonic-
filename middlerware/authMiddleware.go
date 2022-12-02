package middlerware

import (
	helper "GOLANG-JWT/helpers"
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
)

func Authenticate() gin.HandlerFunc {
	return func(c *gin.Context) {
		clientToken := c.Request.Header.Get("token")
		if clientToken == "" {
			c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("No token as provided")})
			c.Abort()
			return
		}
		cliams, err := helper.ValidateToken(clientToken)
		if err != "" {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err})
			c.Abort()
			return
		}
		c.Set("email", cliams.Email)
		c.Set("first_name", cliams.First_name)
		c.Set("last_name", cliams.Last_name)
		c.Set("uid", cliams.Uid)
		c.Set("user_type", cliams.User_type)
		c.Next()
	}
}
