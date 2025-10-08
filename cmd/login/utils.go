package main

import (
	"crypto/rand"
	"encoding/base64"
	"log"

	"golang.org/x/crypto/bcrypt"
)

/*
hashPassword wraps bcrypt.GenerateFromPassword.
Use a cost appropriate for your environment (10 is moderate).
*/
func hashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 10)
	return string(bytes), err
}

/*
checkPasswordHash compares a plaintext password with the stored bcrypt hash.
Returns true only when the password matches.
*/
func checkPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

/*
generateToken returns a URL-safe base64 encoded random string of roughly
length*4/3 bytes. It uses crypto/rand for cryptographic randomness.
*/
func generateToken(length int) string {
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		// We choose to fatal here because token generation failure is a
		// critical condition for authentication flows.
		log.Fatalf("Failed to generate token: %v", err)
	}
	return base64.URLEncoding.EncodeToString(bytes)
}
