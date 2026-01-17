package jwt
import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"strings"
	"time"
)

//go:embed public.pem
var publicPem []byte 

type Payload struct {
	Issuer string `json:"iss"`
	Role string `json:"rol"`
	Expiration int64 `json:"exp"`
}

func ValidateJWT(token string) error{
	parts := strings.Split(string(token), ".")
	if len(parts) != 3 {
		return errors.New("El token no tiene 3 partes.")
	}

	headerB64 := parts[0]
	payloadB64 := parts[1]
	signatureB64 := parts[2]

	payloadJSON, err := base64.RawURLEncoding.DecodeString(payloadB64)
	if err != nil {
		return err		
	}

	signature, err := base64.RawURLEncoding.DecodeString(signatureB64)
	if err != nil {
		return err
	}

	publicBlock, _ :=  pem.Decode(publicPem)
	if publicBlock == nil {
		return err
	}
	
	publicBytes, err := x509.ParsePKIXPublicKey(publicBlock.Bytes)
	if err != nil {
		return err
	}

	pubKey, ok := publicBytes.(*rsa.PublicKey) 
	if !ok {
		return err
	}

	signedInput := headerB64 + "." + payloadB64
	hash := sha256.Sum256([]byte(signedInput))

	err = rsa.VerifyPKCS1v15(pubKey, crypto.SHA256, hashed, signature)
	if err != nil {
		return err
	}
	
	var payload Payload 
	if json.Unmarshal(payloadJSON, &payload); err != nil {
		return err
	}

	if payload.Expiration < time.Now().Unix()	{
		return errors.New("Token expirado.")
	}
	/* Más lógica de validacion */

	return nil
}
