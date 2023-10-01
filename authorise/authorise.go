package authorise

import (
	"backend/db"
	"backend/token"
	"fmt"

	"github.com/golang-jwt/jwt"
)

func CheckRolePerm(role, perm int64) (error, bool) {
	var authorised bool

	exists, err := db.RedisClient.SIsMember(fmt.Sprint(role), perm).Result()
	if err != nil {
		panic(err)
	}
	if exists {
		fmt.Println("Authorised using redis")
		return nil, true
	}
	if !exists {

		fmt.Println("Querying postgres db")

		err = db.DB.QueryRow("SELECT EXISTS(SELECT 1 FROM role_perm WHERE role_id=$1 AND perm_id=$2)", role, perm).Scan(&authorised)
		if err != nil {
			return err, false
		}
		if !authorised {
			return fmt.Errorf("permission doesn't exists for the role"), false
		}

	}
	go InsertToRedis(role)
	return nil, true
}

// to get roles from token
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

func InsertToRedis(role int64) {
	row, err := db.DB.Query("SELECT perm_id FROM role_perm WHERE role_id=$1", role)
	if err != nil {
		panic(err)
	}
	for row.Next() {
		var perm int64
		row.Scan(&perm)
		if err = db.RedisClient.SAdd(fmt.Sprint(role), perm).Err(); err != nil {
			panic(err)
		}
	}

}
