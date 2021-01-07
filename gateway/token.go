package gateway

import (
	"fmt"
	"github.com/dgrijalva/jwt-go"
	jwtReq "github.com/dgrijalva/jwt-go/request"
	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"
	"net/http"
)

const (
	SigningAlgoRSA = "rsa"
	SigningAlgoHMAC = "hmac"
)

// Given request with JWT in Bearer token, tenant container and JWT secret value,
// fill tenant container with JWT claim data and validate JWT signature.
func jwtToTenant(r *http.Request, te *tenant, logger log.Logger, algo string, jwtSecretValue interface{}) error {

	unexpectedSigningMethod := func(algUsed interface{}) error {
		level.Info(logger).Log("msg", "unexpected signing method",
			"used_method", algUsed)
		return fmt.Errorf("Unexpected signing method: %v", algUsed)
	}

	var validator func(token *jwt.Token)(interface{}, error)

	// Validate JWT
	switch algo {
		case SigningAlgoHMAC:
			validator = func(token *jwt.Token) (interface{}, error) {
				// HS* family
				if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
					return nil, unexpectedSigningMethod(token.Header["alg"])
				}

				return jwtSecretValue, nil
			}
		case SigningAlgoRSA:
			validator = func(token *jwt.Token) (interface{}, error) {
				// RS* family
				if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
					return nil, unexpectedSigningMethod(token.Header["alg"])
				}

				return jwtSecretValue, nil
			}
		default:
			validator =  func(token *jwt.Token)(interface{}, error) {
				return nil, fmt.Errorf("Unknown signing method: %v", jwtValidationAlgo)
			}
	}

	_, err := jwtReq.ParseFromRequest(
		r,
		jwtReq.AuthorizationHeaderExtractor,
		validator,
		jwtReq.WithClaims(te))

	return err

}
