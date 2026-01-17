package jwt 

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"log"
	"os"
	"time"
)

//go:embed private.pem
var privPem []byte

func base64urlEncode(data []byte) string {
	return base64.RawURLEncoding.EncodeToString(data)
}

func CrearJWT() {
	encabezado := map[string]string{
		"alg": "RS256", 
		"typ": "JWT",
	}

	headerJSON, err := json.Marshal(encabezado)
	if err != nil {
		log.Fatal("Error convirtiendo el encabezado: ", err)
	}

	headerB64 := base64urlEncode(headerJSON)

	payload := map[string]any{
		"iss": "fundasoft",
		"rol": "pasante",
		"exp": time.Now().Add(90 * 24 * time.Hour).Unix(),
	}

	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		log.Fatal("Error convirtiendo el payload: ", err)
	}

	payloadB64 := base64urlEncode(payloadJSON)

	unsignedToken := headerB64 + "." + payloadB64

	privBlock, _ := pem.Decode(privPem)
	if privBlock == nil {
		log.Fatal("Error decodificando la clave privada.")
	}

	priv, err := x509.ParsePKCS8PrivateKey(privBlock.Bytes)
	if err != nil {
		log.Fatal("Error parseando la clave privada: ", err)
	}

	unsignedBytes := []byte(unsignedToken)
	hash := sha256.Sum256(unsignedBytes)

	rsaPrivKey, ok := priv.(*rsa.PrivateKey)
	if !ok {
		log.Fatal("La clave privada no es RSA.")
	}

	signature, err := rsa.SignPKCS1v15(rand.Reader, rsaPrivKey, crypto.SHA256, hash[:])
	if err != nil {
		log.Fatal("Error firmando: ", err)
	}

	signatureB64 := base64urlEncode(signature)

	jwt := unsignedToken + "." + signatureB64
	os.WriteFile("token.jwt", []byte(jwt), 0444)
}
