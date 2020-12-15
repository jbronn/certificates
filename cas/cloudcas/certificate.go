package cloudcas

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"

	"github.com/pkg/errors"
	pb "google.golang.org/genproto/googleapis/cloud/security/privateca/v1beta1"
	wrapperspb "google.golang.org/protobuf/types/known/wrapperspb"
)

var (
	oidExtensionSubjectKeyID          = []int{2, 5, 29, 14}
	oidExtensionKeyUsage              = []int{2, 5, 29, 15}
	oidExtensionExtendedKeyUsage      = []int{2, 5, 29, 37}
	oidExtensionAuthorityKeyID        = []int{2, 5, 29, 35}
	oidExtensionBasicConstraints      = []int{2, 5, 29, 19}
	oidExtensionSubjectAltName        = []int{2, 5, 29, 17}
	oidExtensionCRLDistributionPoints = []int{2, 5, 29, 31}
	oidExtensionCertificatePolicies   = []int{2, 5, 29, 32}
	oidExtensionAuthorityInfoAccess   = []int{1, 3, 6, 1, 5, 5, 7, 1, 1}
)

var extraExtensions = [...]asn1.ObjectIdentifier{
	oidExtensionSubjectKeyID,          // Added by CAS
	oidExtensionKeyUsage,              // Added in CertificateConfig.ReusableConfig
	oidExtensionExtendedKeyUsage,      // Added in CertificateConfig.ReusableConfig
	oidExtensionAuthorityKeyID,        // Added by CAS
	oidExtensionBasicConstraints,      // Added in CertificateConfig.ReusableConfig
	oidExtensionSubjectAltName,        // Added in CertificateConfig.SubjectConfig.SubjectAltName
	oidExtensionCRLDistributionPoints, // Added by CAS
	oidExtensionCertificatePolicies,   // Added in CertificateConfig.ReusableConfig
	oidExtensionAuthorityInfoAccess,   // Added in CertificateConfig.ReusableConfig and by CAS
}

var (
	oidExtKeyUsageAny                            = asn1.ObjectIdentifier{2, 5, 29, 37, 0}
	oidExtKeyUsageIPSECEndSystem                 = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 5}
	oidExtKeyUsageIPSECTunnel                    = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 6}
	oidExtKeyUsageIPSECUser                      = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 7}
	oidExtKeyUsageMicrosoftServerGatedCrypto     = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 10, 3, 3}
	oidExtKeyUsageNetscapeServerGatedCrypto      = asn1.ObjectIdentifier{2, 16, 840, 1, 113730, 4, 1}
	oidExtKeyUsageMicrosoftCommercialCodeSigning = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 2, 1, 22}
	oidExtKeyUsageMicrosoftKernelCodeSigning     = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 61, 1, 1}
)

const (
	nameTypeEmail = 1
	nameTypeDNS   = 2
	nameTypeURI   = 6
	nameTypeIP    = 7
)

func createCertificateConfig(tpl *x509.Certificate) (*pb.Certificate_Config, error) {
	pk, err := createPublicKey(tpl.PublicKey)
	if err != nil {
		return nil, err
	}

	config := &pb.CertificateConfig{
		SubjectConfig: &pb.CertificateConfig_SubjectConfig{
			Subject:        createSubject(tpl),
			CommonName:     tpl.Subject.CommonName,
			SubjectAltName: createSubjectAlternativeNames(tpl),
		},
		ReusableConfig: createReusableConfig(tpl),
		PublicKey:      pk,
	}
	return &pb.Certificate_Config{
		Config: config,
	}, nil
}

func createPublicKey(key crypto.PublicKey) (*pb.PublicKey, error) {
	switch key := key.(type) {
	case *ecdsa.PublicKey:
		asn1Bytes, err := x509.MarshalPKIXPublicKey(key)
		if err != nil {
			return nil, errors.Wrap(err, "error marshaling public key")
		}
		return &pb.PublicKey{
			Type: pb.PublicKey_PEM_EC_KEY,
			Key: pem.EncodeToMemory(&pem.Block{
				Type:  "PUBLIC KEY",
				Bytes: asn1Bytes,
			}),
		}, nil
	case *rsa.PublicKey:
		return &pb.PublicKey{
			Type: pb.PublicKey_PEM_RSA_KEY,
			Key: pem.EncodeToMemory(&pem.Block{
				Type:  "RSA PUBLIC KEY",
				Bytes: x509.MarshalPKCS1PublicKey(key),
			}),
		}, nil
	default:
		return nil, errors.Errorf("unsupported public key type: %T", key)
	}
}

func createSubject(cert *x509.Certificate) *pb.Subject {
	sub := cert.Subject
	ret := new(pb.Subject)
	if len(sub.Country) > 0 {
		ret.CountryCode = sub.Country[0]
	}
	if len(sub.Organization) > 0 {
		ret.Organization = sub.Organization[0]
	}
	if len(sub.OrganizationalUnit) > 0 {
		ret.OrganizationalUnit = sub.OrganizationalUnit[0]
	}
	if len(sub.Locality) > 0 {
		ret.Locality = sub.Locality[0]
	}
	if len(sub.Province) > 0 {
		ret.Province = sub.Province[0]
	}
	if len(sub.StreetAddress) > 0 {
		ret.StreetAddress = sub.StreetAddress[0]
	}
	if len(sub.PostalCode) > 0 {
		ret.PostalCode = sub.PostalCode[0]
	}
	return ret
}

func createSubjectAlternativeNames(cert *x509.Certificate) *pb.SubjectAltNames {
	ret := new(pb.SubjectAltNames)
	ret.DnsNames = cert.DNSNames
	ret.EmailAddresses = cert.EmailAddresses
	if n := len(cert.IPAddresses); n > 0 {
		ret.IpAddresses = make([]string, n)
		for i, ip := range cert.IPAddresses {
			ret.IpAddresses[i] = ip.String()
		}
	}
	if n := len(cert.URIs); n > 0 {
		ret.Uris = make([]string, n)
		for i, u := range cert.URIs {
			ret.Uris[i] = u.String()
		}
	}

	// Add extra SANs coming from the extensions
	if ext, ok := findExtraExtension(cert, oidExtensionSubjectAltName); ok {
		var rawValues []asn1.RawValue
		if _, err := asn1.Unmarshal(ext.Value, &rawValues); err == nil {
			var newValues []asn1.RawValue

			for _, v := range rawValues {
				if v.Class == asn1.ClassContextSpecific {
					switch v.Tag {
					case nameTypeDNS:
						if len(ret.DnsNames) == 0 {
							newValues = append(newValues, v)
						}
					case nameTypeEmail:
						if len(ret.EmailAddresses) == 0 {
							newValues = append(newValues, v)
						}
					case nameTypeIP:
						if len(ret.IpAddresses) == 0 {
							newValues = append(newValues, v)
						}
					case nameTypeURI:
						if len(ret.Uris) == 0 {
							newValues = append(newValues, v)
						}
					default:
						newValues = append(newValues, v)
					}
				} else {
					newValues = append(newValues, v)
				}
			}
			if len(newValues) > 0 {
				if b, err := asn1.Marshal(newValues); err == nil {
					ret.CustomSans = []*pb.X509Extension{{
						ObjectId: createObjectID(ext.Id),
						Critical: ext.Critical,
						Value:    b,
					}}
				}
			}
		}
	}

	return ret
}

func createReusableConfig(cert *x509.Certificate) *pb.ReusableConfigWrapper {
	var unknownEKUs []*pb.ObjectId
	var ekuOptions = &pb.KeyUsage_ExtendedKeyUsageOptions{}
	for _, eku := range cert.ExtKeyUsage {
		switch eku {
		case x509.ExtKeyUsageAny:
			unknownEKUs = append(unknownEKUs, createObjectID(oidExtKeyUsageAny))
		case x509.ExtKeyUsageServerAuth:
			ekuOptions.ServerAuth = true
		case x509.ExtKeyUsageClientAuth:
			ekuOptions.ClientAuth = true
		case x509.ExtKeyUsageCodeSigning:
			ekuOptions.CodeSigning = true
		case x509.ExtKeyUsageEmailProtection:
			ekuOptions.EmailProtection = true
		case x509.ExtKeyUsageIPSECEndSystem:
			unknownEKUs = append(unknownEKUs, createObjectID(oidExtKeyUsageIPSECEndSystem))
		case x509.ExtKeyUsageIPSECTunnel:
			unknownEKUs = append(unknownEKUs, createObjectID(oidExtKeyUsageIPSECTunnel))
		case x509.ExtKeyUsageIPSECUser:
			unknownEKUs = append(unknownEKUs, createObjectID(oidExtKeyUsageIPSECUser))
		case x509.ExtKeyUsageTimeStamping:
			ekuOptions.TimeStamping = true
		case x509.ExtKeyUsageOCSPSigning:
			ekuOptions.OcspSigning = true
		case x509.ExtKeyUsageMicrosoftServerGatedCrypto:
			unknownEKUs = append(unknownEKUs, createObjectID(oidExtKeyUsageMicrosoftServerGatedCrypto))
		case x509.ExtKeyUsageNetscapeServerGatedCrypto:
			unknownEKUs = append(unknownEKUs, createObjectID(oidExtKeyUsageNetscapeServerGatedCrypto))
		case x509.ExtKeyUsageMicrosoftCommercialCodeSigning:
			unknownEKUs = append(unknownEKUs, createObjectID(oidExtKeyUsageMicrosoftCommercialCodeSigning))
		case x509.ExtKeyUsageMicrosoftKernelCodeSigning:
			unknownEKUs = append(unknownEKUs, createObjectID(oidExtKeyUsageMicrosoftKernelCodeSigning))
		}
	}

	for _, oid := range cert.UnknownExtKeyUsage {
		unknownEKUs = append(unknownEKUs, createObjectID(oid))
	}

	var policyIDs []*pb.ObjectId
	for _, oid := range cert.PolicyIdentifiers {
		policyIDs = append(policyIDs, createObjectID(oid))
	}

	var caOptions *pb.ReusableConfigValues_CaOptions
	if cert.BasicConstraintsValid {
		var maxPathLength *wrapperspb.Int32Value
		switch {
		case cert.MaxPathLenZero:
			maxPathLength = wrapperspb.Int32(0)
		case cert.MaxPathLen > 0:
			maxPathLength = wrapperspb.Int32(int32(cert.MaxPathLen))
		default:
			maxPathLength = nil
		}

		caOptions = &pb.ReusableConfigValues_CaOptions{
			IsCa:                wrapperspb.Bool(cert.IsCA),
			MaxIssuerPathLength: maxPathLength,
		}
	}

	var extraExtensions []*pb.X509Extension
	for _, ext := range cert.ExtraExtensions {
		if isExtraExtension(ext.Id) {
			extraExtensions = append(extraExtensions, &pb.X509Extension{
				ObjectId: createObjectID(ext.Id),
				Critical: ext.Critical,
				Value:    ext.Value,
			})
		}
	}

	values := &pb.ReusableConfigValues{
		KeyUsage: &pb.KeyUsage{
			BaseKeyUsage: &pb.KeyUsage_KeyUsageOptions{
				DigitalSignature:  cert.KeyUsage&x509.KeyUsageDigitalSignature > 0,
				ContentCommitment: cert.KeyUsage&x509.KeyUsageContentCommitment > 0,
				KeyEncipherment:   cert.KeyUsage&x509.KeyUsageKeyEncipherment > 0,
				DataEncipherment:  cert.KeyUsage&x509.KeyUsageDataEncipherment > 0,
				KeyAgreement:      cert.KeyUsage&x509.KeyUsageKeyAgreement > 0,
				CertSign:          cert.KeyUsage&x509.KeyUsageCertSign > 0,
				CrlSign:           cert.KeyUsage&x509.KeyUsageCRLSign > 0,
				EncipherOnly:      cert.KeyUsage&x509.KeyUsageEncipherOnly > 0,
				DecipherOnly:      cert.KeyUsage&x509.KeyUsageDecipherOnly > 0,
			},
			ExtendedKeyUsage:         ekuOptions,
			UnknownExtendedKeyUsages: unknownEKUs,
		},
		CaOptions:            caOptions,
		PolicyIds:            policyIDs,
		AiaOcspServers:       cert.OCSPServer,
		AdditionalExtensions: extraExtensions,
	}

	return &pb.ReusableConfigWrapper{
		ConfigValues: &pb.ReusableConfigWrapper_ReusableConfigValues{
			ReusableConfigValues: values,
		},
	}
}

// isExtraExtension returns true if the extension oid is not managed in a
// different way.
func isExtraExtension(oid asn1.ObjectIdentifier) bool {
	for _, id := range extraExtensions {
		if id.Equal(oid) {
			return false
		}
	}
	return true
}

func createObjectID(oid asn1.ObjectIdentifier) *pb.ObjectId {
	ret := make([]int32, len(oid))
	for i, v := range oid {
		ret[i] = int32(v)
	}
	return &pb.ObjectId{
		ObjectIdPath: ret,
	}
}

func findExtraExtension(cert *x509.Certificate, oid asn1.ObjectIdentifier) (pkix.Extension, bool) {
	for _, ext := range cert.ExtraExtensions {
		if ext.Id.Equal(oid) {
			return ext, true
		}
	}
	return pkix.Extension{}, false
}
