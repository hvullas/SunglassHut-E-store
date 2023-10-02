package token

import (
	"fmt"
	"time"

	"github.com/golang-jwt/jwt"
)

type JwtClaims struct {
	Username string  `json:"username,omitempty"`
	Roles    []int64 `json:"roles,omitempty"`
	jwt.StandardClaims
}

const JWTPrivateToken = "GenerateToken"

func (claims JwtClaims) Valid() error {
	var now = time.Now().UTC().Unix()
	if claims.VerifyExpiresAt(now, true) {
		return nil
	}
	return fmt.Errorf("Token is invalid")
}

func GenrateToken(claims *JwtClaims, expirationTime time.Time) (string, error) {

	claims.ExpiresAt = expirationTime.Unix()
	claims.IssuedAt = time.Now().UTC().Unix()

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	// Sign and get the complete encoded token as a string using the secret
	tokenString, err := token.SignedString([]byte(JWTPrivateToken))
	if err != nil {
		return "", err
	}
	return tokenString, nil
}//UPDATE cart SET items=jsonb_set(items,'{$1}','$2'::jsonb) WHERE cart_id=$3 RETURNING cart_id", fmt.Sprint(body.ProductId), string(jsonItems), body.UserId).Scan(body.UserId)
