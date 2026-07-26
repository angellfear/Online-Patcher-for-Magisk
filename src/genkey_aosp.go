package main

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
)

func cArray(name string, data []byte) string {
	s := fmt.Sprintf("static const unsigned char %s[] = {\n", name)
	for i, b := range data {
		if i%16 == 0 {
			s += "  "
		}
		s += fmt.Sprintf("0x%02x,", b)
		if i%16 == 15 {
			s += "\n"
		} else {
			s += " "
		}
	}
	s += "\n};\n"
	s += fmt.Sprintf("static const unsigned int %s_len = %d;\n\n", name, len(data))
	return s
}

func main() {
	pk8Der, err := os.ReadFile("platform_raw.pk8")
	if err != nil {
		panic(err)
	}
	keyIface, err := x509.ParsePKCS8PrivateKey(pk8Der)
	if err != nil {
		panic(err)
	}
	priv, ok := keyIface.(*rsa.PrivateKey)
	if !ok {
		panic("not an RSA key")
	}

	pemData, err := os.ReadFile("platform_raw.x509.pem")
	if err != nil {
		panic(err)
	}
	block, _ := pem.Decode(pemData)
	if block == nil {
		panic("failed to decode PEM")
	}
	certDER := block.Bytes
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		panic(err)
	}

	out, err := os.Create("signing_identity.h")
	if err != nil {
		panic(err)
	}
	defer out.Close()

	fmt.Fprintln(out, "// Auto-generated. Well-known AOSP 'platform' test signing identity")
	fmt.Fprintln(out, "// (build/target/product/security/platform.{pk8,x509.pem}) - matches the")
	fmt.Fprintln(out, "// dev-keys this ROM was built with, so signature-protected permissions")
	fmt.Fprintln(out, "// granted to platform-signed apps keep working after re-signing.")
	fmt.Fprintln(out, "#pragma once")
	fmt.Fprintln(out)

	nBytes := priv.N.Bytes()
	dBytes := priv.D.Bytes()

	fmt.Fprint(out, cArray("RSA_MODULUS_N", nBytes))
	fmt.Fprint(out, cArray("RSA_PRIVATE_D", dBytes))
	fmt.Fprint(out, cArray("CERT_DER", certDER))
	fmt.Fprint(out, cArray("CERT_RAW_ISSUER", cert.RawIssuer))

	serialBytes := cert.SerialNumber.Bytes()
	fmt.Fprint(out, cArray("CERT_SERIAL", serialBytes))

	fmt.Println("signing_identity.h generated from AOSP platform key")
	fmt.Println("N bits:", priv.N.BitLen())
	fmt.Println("Subject:", cert.Subject)
}
