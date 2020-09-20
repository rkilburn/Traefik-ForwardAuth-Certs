package main

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net/http"
	"os"
	"regexp"
	"strings"

	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	_ "github.com/rkilburn/Traefik-ForwardAuth-Certs/docs"
	echoSwagger "github.com/swaggo/echo-swagger" // echo-swagger middleware
	"go.elastic.co/apm/module/apmechov4"
)

// @title Traefik-ForwardAuth-Certs
// @version 1.0
// @description Parses certificate information from cert in Headers

func main() {

	requestHeader, requestHeaderFound := os.LookupEnv("REQUEST_HEADER")
	if !requestHeaderFound {
		panic("ERROR - No Request Header Provided")
	}
	fmt.Println("Request Header: " + requestHeader)

	responseHeader, responseHeaderFound := os.LookupEnv("RESPONSE_HEADER")
	if !responseHeaderFound {
		panic("ERROR - No Response Header Provided")
	}
	fmt.Println("Response Header: " + responseHeader)

	e := echo.New()
	e.Use(apmechov4.Middleware())
	e.Use(middleware.CORS())
	e.GET("/swagger/*", echoSwagger.WrapHandler)

	e.GET("/status", status)
	e.Any("/v1/certificate/cn", handleCNFromCertificate)
	e.Any("/v1/certificate/cn-regex", handleRegexCNFromCertificate)
	e.Any("/v1/certificate/dn", handleDNFromCertificate)

	e.Logger.Fatal(e.StartTLS(":8443", "./certs/cert.pem", "./certs/key.pem"))
}

// @Summary Status
// @ID status
// @Success 200 {string} string	"OK"
// @Router /status [get]
func status(c echo.Context) error {
	return c.String(http.StatusOK, "OK")
}

// @Summary Regex'ed Common Name from Certificate
// @ID get-cn-from-certificate-regex
// @Success 200 {string} string	"Client CN"
// @Param X-Forwarded-Tls-Client-Cert header string true "PEM Encoded Certificate"
// @Router /v1/certificate/cn-regex [get]
func handleRegexCNFromCertificate(c echo.Context) error {
	return getPropertyFromCertificate(c, "cn-regex")
}

// @Summary Common Name from Certificate
// @ID get-cn-from-certificate
// @Success 200 {string} string	"Client CN"
// @Param X-Forwarded-Tls-Client-Cert header string true "PEM Encoded Certificate"
// @Router /v1/certificate/cn [get]
func handleCNFromCertificate(c echo.Context) error {
	return getPropertyFromCertificate(c, "cn")
}

// @Summary Distinguished Name from Certificate
// @ID get-dn-from-certificate
// @Success 200 {string} string	"Client DN"
// @Param X-Forwarded-Tls-Client-Cert header string true "PEM Encoded Certificate"
// @Router /v1/certificate/dn [get]
func handleDNFromCertificate(c echo.Context) error {
	return getPropertyFromCertificate(c, "dn")
}

func getPropertyFromCertificate(c echo.Context, property string) error {

	requestHeader, _ := os.LookupEnv("REQUEST_HEADER")
	responseHeader, _ := os.LookupEnv("RESPONSE_HEADER")

	certificate := parseCertificateFromHeader(c, requestHeader)
	if certificate == nil {
		return c.String(http.StatusOK, "")
	}

	if property == "cn" {
		c.Response().Header().Set(responseHeader, certificate.Subject.CommonName)
		return c.String(http.StatusOK, certificate.Subject.CommonName)
	} else if property == "dn" {
		c.Response().Header().Set(responseHeader, certificate.Subject.ToRDNSequence().String())
		return c.String(http.StatusOK, certificate.Subject.ToRDNSequence().String())
	} else if property == "cn-regex" {
		shortCN := regexCN(certificate.Subject.CommonName)
		c.Response().Header().Set(responseHeader, shortCN)
		return c.String(http.StatusOK, shortCN)
	}

	return c.String(http.StatusOK, "")
}

func parseCertificateFromHeader(c echo.Context, requestHeader string) *x509.Certificate {

	certPEM := c.Request().Header.Get(requestHeader)

	if certPEM == "" {
		return nil
	}

	certPEM = strings.Replace(certPEM, "BEGIN CERTIFICATE", "BEGINCERTIFICATE", 1)
	certPEM = strings.Replace(certPEM, "END CERTIFICATE", "ENDCERTIFICATE", 1)
	certPEM = strings.ReplaceAll(certPEM, " ", "\n")
	certPEM = strings.Replace(certPEM, "BEGINCERTIFICATE", "BEGIN CERTIFICATE", 1)
	certPEM = strings.Replace(certPEM, "ENDCERTIFICATE", "END CERTIFICATE", 1)

	certPEMBytes := []byte(certPEM)

	block, _ := pem.Decode(certPEMBytes)
	if block == nil {
		panic("failed to parse certificate PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		panic("failed to parse certificate: " + err.Error())
	}

	return cert
}

func regexCN(cn string) string {

	regex, regexFound := os.LookupEnv("CN_REGEX")
	if !regexFound {
		panic("ERROR - No Regex Provided")
	}
	re := regexp.MustCompile(regex)

	matches := re.FindStringSubmatch(cn)

	if len(matches) < 2 {
		return ""
	}

	shortCN := matches[1]
	return shortCN
}
