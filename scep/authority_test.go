package scep

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"net/url"
	"testing"

	"github.com/smallstep/certificates/authority/config"
	"github.com/smallstep/certificates/authority/provisioner"
	"github.com/smallstep/linkedca"
	"github.com/smallstep/pkcs7"
	"github.com/smallstep/scep"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.step.sm/crypto/keyutil"
	"go.step.sm/crypto/minica"
	"go.step.sm/crypto/randutil"
	"go.step.sm/crypto/x509util"
)

func generateContent(t *testing.T, size int) []byte {
	t.Helper()
	b, err := randutil.Bytes(size)
	require.NoError(t, err)
	return b
}

func generateRecipients(t *testing.T) []*x509.Certificate {
	ca, err := minica.New()
	require.NoError(t, err)
	s, err := keyutil.GenerateSigner("RSA", "", 2048)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		PublicKey: s.Public(),
		Subject:   pkix.Name{CommonName: "Test PKCS#7 Encryption"},
	}
	cert, err := ca.Sign(tmpl)
	require.NoError(t, err)
	return []*x509.Certificate{cert}
}

func TestAuthority_encrypt(t *testing.T) {
	t.Parallel()
	a := &Authority{}
	recipients := generateRecipients(t)
	type args struct {
		content    []byte
		recipients []*x509.Certificate
		algorithm  int
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{"alg-0", args{generateContent(t, 32), recipients, pkcs7.EncryptionAlgorithmDESCBC}, false},
		{"alg-1", args{generateContent(t, 32), recipients, pkcs7.EncryptionAlgorithmAES128CBC}, false},
		{"alg-2", args{generateContent(t, 32), recipients, pkcs7.EncryptionAlgorithmAES256CBC}, false},
		{"alg-3", args{generateContent(t, 32), recipients, pkcs7.EncryptionAlgorithmAES128GCM}, false},
		{"alg-4", args{generateContent(t, 32), recipients, pkcs7.EncryptionAlgorithmAES256GCM}, false},
		{"alg-unknown", args{generateContent(t, 32), recipients, 42}, true},
	}
	for _, tt := range tests {
		tc := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := a.encrypt(tc.args.content, tc.args.recipients, tc.args.algorithm)
			if tc.wantErr {
				assert.Error(t, err)
				assert.Nil(t, got)
				return
			}

			assert.NoError(t, err)
			assert.NotEmpty(t, got)
		})
	}
}

type signAuthority struct {
	ca       *minica.CA
	webhooks []*provisioner.Webhook
	template string
	// optional separate signer for the provisioner
	signerCertificate []byte
	signerKeyPEM      []byte
}

func (s *signAuthority) SignWithContext(ctx context.Context, cr *x509.CertificateRequest, opts provisioner.SignOptions, signOpts ...provisioner.SignOption) ([]*x509.Certificate, error) {
	var certOptions []x509util.Option
	for _, so := range signOpts {
		if co, ok := so.(provisioner.CertificateOptions); ok {
			certOptions = append(certOptions, co.Options(opts)...)
		}
	}
	c, err := x509util.NewCertificate(cr, certOptions...)
	if err != nil {
		return nil, err
	}
	crt, err := s.ca.Sign(c.GetCertificate())
	if err != nil {
		return nil, err
	}
	return []*x509.Certificate{crt, s.ca.Intermediate}, nil
}

func (s *signAuthority) LoadProvisionerByName(string) (provisioner.Interface, error) {
	p := &provisioner.SCEP{
		Name:              "scep",
		Type:              "SCEP",
		ChallengePassword: "password",
		DecrypterCertificate: pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: s.ca.Intermediate.Raw,
		}),
		DecrypterKeyPEM: pem.EncodeToMemory(&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(s.ca.Signer.(*rsa.PrivateKey)),
		}),
		SignerCertificate: s.signerCertificate,
		SignerKeyPEM:      s.signerKeyPEM,
		Options: &provisioner.Options{
			Webhooks: s.webhooks,
			X509: &provisioner.X509Options{
				Template: s.template,
			},
		},
	}
	if err := p.Init(provisioner.Config{
		Claims: config.GlobalProvisionerClaims,
	}); err != nil {
		return nil, err
	}
	return p, nil
}

func TestAuthority_SignCSR(t *testing.T) {
	ca, err := minica.New(minica.WithGetSignerFunc(func() (crypto.Signer, error) {
		return rsa.GenerateKey(rand.Reader, 2048)
	}))
	require.NoError(t, err)

	sa := &signAuthority{
		ca: ca,
		webhooks: []*provisioner.Webhook{{
			ID:       "1f81b7ed-62c4-4dd5-b63a-348e92b2e25d",
			Name:     "ScepChallenge",
			Kind:     linkedca.Webhook_SCEPCHALLENGE.String(),
			CertType: linkedca.Webhook_X509.String(),
			URL:      "https://not.used",
			Secret:   "MTIzNAo=",
		}},
		template: `{
{{- with .Webhooks.ScepChallenge.CommonName }}
	"subject": {"commonName" : {{ . | toJson }}},
{{- else }}
	"subject": {{ toJson .Subject }},
{{- end }}
{{- with .Webhooks.ScepChallenge.Email }}
	"emailAddresses" : [ {{ . | toJson }} ],
{{- else }}
	"sans": {{ toJson .SANs }},
{{- end }}
{{- if typeIs "*rsa.PublicKey" .Insecure.CR.PublicKey }}
	"keyUsage": ["keyEncipherment", "digitalSignature"],
{{- else }}
	"keyUsage": ["digitalSignature"],
{{- end }}
	"extKeyUsage": ["serverAuth", "clientAuth"]
}`,
	}

	a1, err := New(sa, Options{
		Roots:                []*x509.Certificate{ca.Root},
		Intermediates:        []*x509.Certificate{ca.Intermediate},
		SignerCert:           ca.Intermediate,
		Signer:               ca.Signer,
		Decrypter:            ca.Signer.(*rsa.PrivateKey),
		DecrypterCert:        ca.Intermediate,
		SCEPProvisionerNames: []string{"scep"},
	})
	require.NoError(t, err)

	p1, err := a1.LoadProvisionerByName("scep")
	require.NoError(t, err)

	ctx := NewProvisionerContext(context.Background(), p1.(*provisioner.SCEP))

	signer, err := keyutil.GenerateDefaultSigner()
	require.NoError(t, err)
	csr, err := x509util.CreateCertificateRequest("jane@example.com", []string{"urn:uuid:81d19787-cfe8-4a04-82b2-8827f3727235"}, signer)
	require.NoError(t, err)

	type args struct {
		ctx         context.Context
		csr         *x509.CertificateRequest
		msg         *PKIMessage
		signCSROpts []provisioner.SignCSROption
	}
	tests := []struct {
		name      string
		authority *Authority
		args      args
		validate  func(*testing.T, *PKIMessage)
		assertion assert.ErrorAssertionFunc
	}{
		{"ok", a1, args{ctx, csr, &PKIMessage{
			CSRReqMessage: &scep.CSRReqMessage{CSR: csr},
			P7: &pkcs7.PKCS7{
				Certificates: []*x509.Certificate{ca.Intermediate},
			},
		}, []provisioner.SignCSROption{
			provisioner.TemplateDataModifierFunc(func(data x509util.TemplateData) {
				data.SetWebhook("ScepChallenge", map[string]any{
					"CommonName": "Jane C.",
					"Email":      "jane@example.com",
				})
			}),
		}}, func(t *testing.T, p *PKIMessage) {
			require.NotNil(t, p.CertRepMessage)
			cert, err := x509.ParseCertificate(p.Certificate.Raw)
			require.NoError(t, err)
			assert.Equal(t, "Jane C.", cert.Subject.CommonName)
			assert.Equal(t, []string{"jane@example.com"}, cert.EmailAddresses)
			assert.Nil(t, cert.URIs)
		}, assert.NoError},
		{"ok no sign options", a1, args{ctx, csr, &PKIMessage{
			CSRReqMessage: &scep.CSRReqMessage{CSR: csr},
			P7: &pkcs7.PKCS7{
				Certificates: []*x509.Certificate{ca.Intermediate},
			},
		}, []provisioner.SignCSROption{}}, func(t *testing.T, p *PKIMessage) {
			require.NotNil(t, p.CertRepMessage)
			cert, err := x509.ParseCertificate(p.Certificate.Raw)
			require.NoError(t, err)
			assert.Equal(t, "jane@example.com", cert.Subject.CommonName)
			assert.Nil(t, cert.EmailAddresses)
			assert.Equal(t, []*url.URL{{Scheme: "urn", Opaque: "uuid:81d19787-cfe8-4a04-82b2-8827f3727235"}}, cert.URIs)
		}, assert.NoError},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.authority.SignCSR(tt.args.ctx, tt.args.csr, tt.args.msg, tt.args.signCSROpts...)
			tt.assertion(t, err)
			tt.validate(t, got)
		})
	}
}

// chainProvisioner is a Provisioner returning fixed decrypter and
// signer certificates, for testing GetCACertificates.
type chainProvisioner struct {
	Provisioner
	decrypterCertificate *x509.Certificate
	signerCertificate    *x509.Certificate
	includeIntermediate  bool
	includeRoot          bool
}

func (p *chainProvisioner) GetDecrypter() (*x509.Certificate, crypto.Decrypter) {
	return p.decrypterCertificate, nil
}

func (p *chainProvisioner) GetSigner() (*x509.Certificate, crypto.Signer) {
	return p.signerCertificate, nil
}

func (p *chainProvisioner) ShouldIncludeIntermediateInChain() bool { return p.includeIntermediate }
func (p *chainProvisioner) ShouldIncludeRootInChain() bool         { return p.includeRoot }

func TestAuthority_GetCACertificates(t *testing.T) {
	ca, err := minica.New()
	require.NoError(t, err)
	newCert := func(cn string) *x509.Certificate {
		s, err := keyutil.GenerateSigner("RSA", "", 2048)
		require.NoError(t, err)
		cert, err := ca.Sign(&x509.Certificate{
			Subject:   pkix.Name{CommonName: cn},
			PublicKey: s.Public(),
		})
		require.NoError(t, err)
		return cert
	}
	decrypter := newCert("decrypter")
	signer := newCert("signer")

	a := &Authority{
		roots:         []*x509.Certificate{ca.Root},
		intermediates: []*x509.Certificate{ca.Intermediate},
	}

	tests := []struct {
		name string
		p    *chainProvisioner
		want []*x509.Certificate
	}{
		{"intermediate only", &chainProvisioner{includeIntermediate: true},
			[]*x509.Certificate{ca.Intermediate}},
		{"decrypter signs", &chainProvisioner{decrypterCertificate: decrypter, signerCertificate: decrypter, includeIntermediate: true},
			[]*x509.Certificate{decrypter, ca.Intermediate}},
		{"separate signer", &chainProvisioner{decrypterCertificate: decrypter, signerCertificate: signer, includeIntermediate: true},
			[]*x509.Certificate{decrypter, signer, ca.Intermediate}},
		{"separate signer with root", &chainProvisioner{decrypterCertificate: decrypter, signerCertificate: signer, includeIntermediate: true, includeRoot: true},
			[]*x509.Certificate{decrypter, signer, ca.Intermediate, ca.Root}},
		{"separate signer without intermediate", &chainProvisioner{decrypterCertificate: decrypter, signerCertificate: signer},
			[]*x509.Certificate{decrypter, signer}},
		{"intermediate signer", &chainProvisioner{decrypterCertificate: decrypter, signerCertificate: ca.Intermediate, includeIntermediate: true},
			[]*x509.Certificate{decrypter, ca.Intermediate}},
		{"intermediate signer without intermediate", &chainProvisioner{decrypterCertificate: decrypter, signerCertificate: ca.Intermediate},
			[]*x509.Certificate{decrypter, ca.Intermediate}},
		{"separate signer without decrypter", &chainProvisioner{signerCertificate: signer},
			[]*x509.Certificate{signer, ca.Intermediate}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.WithValue(context.Background(), provisionerKey{}, Provisioner(tt.p))
			got, err := a.GetCACertificates(ctx)
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestAuthority_SignCSR_separateSigner(t *testing.T) {
	ca, err := minica.New(minica.WithGetSignerFunc(func() (crypto.Signer, error) {
		return rsa.GenerateKey(rand.Reader, 2048)
	}))
	require.NoError(t, err)

	signerKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	signerCert, err := ca.Sign(&x509.Certificate{
		Subject:   pkix.Name{CommonName: "SCEP signer"},
		PublicKey: signerKey.Public(),
	})
	require.NoError(t, err)

	sa := &signAuthority{
		ca:                ca,
		signerCertificate: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: signerCert.Raw}),
		signerKeyPEM:      pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(signerKey)}),
	}
	a, err := New(sa, Options{
		Roots:                []*x509.Certificate{ca.Root},
		Intermediates:        []*x509.Certificate{ca.Intermediate},
		SignerCert:           ca.Intermediate,
		Signer:               ca.Signer,
		Decrypter:            ca.Signer.(*rsa.PrivateKey),
		DecrypterCert:        ca.Intermediate,
		SCEPProvisionerNames: []string{"scep"},
	})
	require.NoError(t, err)
	p, err := a.LoadProvisionerByName("scep")
	require.NoError(t, err)
	ctx := NewProvisionerContext(context.Background(), p.(*provisioner.SCEP))

	csrSigner, err := keyutil.GenerateDefaultSigner()
	require.NoError(t, err)
	csr, err := x509util.CreateCertificateRequest("jane@example.com", nil, csrSigner)
	require.NoError(t, err)

	msg := &PKIMessage{
		TransactionID: "tx",
		CSRReqMessage: &scep.CSRReqMessage{CSR: csr},
		P7:            &pkcs7.PKCS7{Certificates: []*x509.Certificate{ca.Intermediate}},
	}
	got, err := a.SignCSR(ctx, csr, msg)
	require.NoError(t, err)

	p7, err := pkcs7.Parse(got.Raw)
	require.NoError(t, err)
	require.NoError(t, p7.Verify())
	assert.Equal(t, signerCert, p7.GetOnlySigner())

	failure, err := a.CreateFailureResponse(ctx, csr, msg, FailInfoName(scep.BadRequest), "bad request")
	require.NoError(t, err)
	p7, err = pkcs7.Parse(failure.Raw)
	require.NoError(t, err)
	require.NoError(t, p7.Verify())
	assert.Equal(t, signerCert, p7.GetOnlySigner())
}
