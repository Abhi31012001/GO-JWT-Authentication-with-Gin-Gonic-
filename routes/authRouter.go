package routes

import (
	controller "GOLANG-JWT/controllers"

	"github.com/gin-gonic/gin"
)

func AuthRoutes(incomingRoutes *gin.Engine) {
	incomingRoutes.POST("non/signup", controller.Signup())
	incomingRoutes.POST("non/login", controller.Login())
}
