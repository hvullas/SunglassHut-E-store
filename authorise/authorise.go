package authorise

import (
	"backend/db"
	"backend/token"
	"fmt"

	"github.com/golang-jwt/jwt"
)

func CheckRolePerm(role, perm int64) (error, bool) {
	var authorised bool
	err := db.DB.QueryRow("SELECT EXISTS(SELECT 1 FROM roles WHERE $1 = ANY(permissions) AND role_id=$2)", perm, role).Scan(&authorised)
	if err != nil {
		return err, false
	}
	if !authorised {
		return fmt.Errorf("permission doesn't exists for the role"), false
	}
	return nil, true
}


//to get roles from token
func GetRoles(tokenStr string) ([]int64, error) {
	claims := &token.JwtClaims{}

	tkn, err := jwt.ParseWithClaims(tokenStr, claims,
		func(t *jwt.Token) (interface{}, error) {
			return []byte(token.JWTPrivateToken), nil
		})

	if err != nil {
		if err == jwt.ErrSignatureInvalid {
			return nil, fmt.Errorf("Invalid signature")
		}
		return nil, fmt.Errorf("Invalid token")
	}

	if !tkn.Valid {
		return nil, fmt.Errorf("UnAuthorized")
	}

	return claims.Roles, nil
}
func CheckPerm(tokenStr string, perm int64) (bool, error) {
	roles, err := GetRoles(tokenStr)
	if err != nil {
		return false, fmt.Errorf("Unauthorised")
	}

	for _, val := range roles {
		err, authorised := CheckRolePerm(val, perm)
		if err != nil {
			return false, err
		}
		if authorised {
			return authorised, nil
		}
	}
	return false, fmt.Errorf("Unauthorised")
}
