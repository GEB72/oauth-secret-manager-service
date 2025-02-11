package rest

import (
	"app/api"
	"app/internal/token"
	"github.com/gin-gonic/gin"
	"log/slog"
	"net/http"
)

// RetrieveTokenHandler is the handler for endpoint /token/get. It has the token.Retriever
// interface as a dependency, which it will call to invoke the correct business logic
// to retrieve a token for a given user. It uses the token.Retriever interface to fetch
// the token based on the UserID provided in the request body. If the retrieval is
// successful, it returns the access token, refresh token, and expiry date. In case
// of an error or invalid token, the handler responds with a http.StatusInternalServerError
// status. Note that it will still return the token if it is expired
func RetrieveTokenHandler(r token.Retriever) gin.HandlerFunc {
	errorBody := gin.H{"Error": "Could not retrieve token"}

	return func(c *gin.Context) {
		// You know the middleware has already run, so userID must exist if authorized.
		userID, ok := c.Get("user_id")
		if !ok || userID == "" {
			c.JSON(http.StatusUnauthorized, errorBody)
			return
		}

		tk, err := r.RetrieveToken(&api.RetrieveTokenRequest{UserID: userID.(string)})
		if err != nil || tk == nil || tk.AccessToken == "" {
			c.JSON(http.StatusInternalServerError, errorBody)
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"access_token":  tk.AccessToken,
			"refresh_token": tk.RefreshToken,
			"expiry":        tk.Expiry.String()})
	}
}

// SaveTokenHandler is the handler for endpoint /token/save. It has the token.Saver
// interface as a dependency, which it will call to invoke the correct business
// logic to save a token given the request is correctly structured. On success,
// the handler will return a basic success message with status code http.StatusOK
func SaveTokenHandler(s token.Saver) gin.HandlerFunc {
	errorBody := gin.H{"Error": "Could not save token"}

	return func(c *gin.Context) {
		var req api.SaveTokenRequest
		if err := c.ShouldBindBodyWithJSON(&req); err != nil {
			slog.Error(err.Error())
			c.JSON(http.StatusBadRequest, errorBody)
			return
		}

		err := s.SaveToken(&api.SaveTokenRequest{
			UserID:       req.UserID,
			AccessToken:  req.AccessToken,
			RefreshToken: req.RefreshToken,
			Expiry:       req.Expiry})
		if err != nil {
			c.JSON(http.StatusInternalServerError, errorBody)
			return
		}

		c.JSON(http.StatusOK, gin.H{"Message": "Token saved successfully"})
	}
}
