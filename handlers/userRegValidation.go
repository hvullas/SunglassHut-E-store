package handlers

import (
	"fmt"
	"net"
	"regexp"
	"strings"
)

func ValidatePassword(password string) error {
	// user password validation
	if len(password) == 0 {
		return fmt.Errorf("Enter password")
	}

	match, _ := regexp.MatchString("[0-9]+?", password)
	if !match {
		return fmt.Errorf("Password must contain atleast one number")
	}
	match, _ = regexp.MatchString("[A-Z]+?", password)
	if !match {
		return fmt.Errorf("Password must contain atleast upper case letter")
	}
	match, _ = regexp.MatchString("[a-z]+?", password)
	if !match {
		return fmt.Errorf("Password must contain atleast lower case letter")
	}
	match, _ = regexp.MatchString("[!@#$%^&*_]+?", password)
	if !match {
		return fmt.Errorf("Password must contain atleast special character")
	}
	match, _ = regexp.MatchString(".{8,30}", password)
	if !match {
		return fmt.Errorf("Password length must be atleast 8 character long")
	}
	return nil
}

func ValidateEmail(email string) error {
	//validate email using net/mail
	emailregex := regexp.MustCompile("^[A-Za-za0-9.!#$%&'*+\\/=?^_`{|}~-]+@[A-Za-z](?:[A-Za-z0-9-]{0,61}[A-Za-z])?(?:\\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$")
	match := emailregex.MatchString(email)
	if !match {
		return fmt.Errorf("invalid mail")
	}
	if len(email) < 3 && len(email) > 254 {
		return fmt.Errorf("Invalid mail")
	}

	i := strings.Index(email, "@")
	host := email[i+1:]

	_, err := net.LookupMX(host)
	if err != nil {
		return fmt.Errorf("invalid mail")
	}
	return nil
}

func ValidatePhone(number string) error {
	//phone number validation
	match, _ := regexp.MatchString("^[+]{1}[0-9]{0,3}\\s?[0-9]{10}$", number)
	if !match {
		return fmt.Errorf("invalid number")
	}
	return nil
}
