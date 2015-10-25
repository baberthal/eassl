require 'eassl'

RSpec.describe EaSSL, '#certificate' do
  context 'given a valid CA' do
    let(:cert) { EaSSL::Certificate.new(signing_request: csr) }
    let(:csr) { EaSSL::SigningRequest.new(name: name, key: key) }
    let(:name) { EaSSL::CertificateName.new(common_name: 'foo.bar.com') }
    let(:key) { EaSSL::Key.new }
    let(:ca) do
      EaSSL::CertificateAuthority.load(ca_path: ca_path, ca_password: '1234')
    end
    let(:ca_path) { File.join(File.dirname(__FILE__), '../test', 'CA') }
    let(:key_usage) { cert.extensions.find { |e| e.oid == 'extendedKeyUsage' } }
    let(:alt_names) { cert.extensions.find { |e| e.oid == 'subjectAltName' } }

    it 'creates a self-signed certificate' do
      expect(cert.subject.to_s).to eq csr.subject.to_s
      expect(cert.subject.to_s).to eq cert.issuer.to_s
    end

    it 'creates a new certificate' do
      expect(cert.to_pem).to match(/BEGIN CERTIFICATE/)
    end

    context 'with a CA cert' do
      let(:cert) do
        EaSSL::Certificate.new(signing_request: csr,
                               ca_certificate: ca.certificate)
      end

      it 'creates a certifcate and signs with a CA cert' do
        cert.sign(ca.key)
        expect(cert.to_pem).to match(/BEGIN CERTIFICATE/)
        expect(cert.subject.to_s).to eq csr.subject.to_s
        expect(cert.issuer.to_s).to eq ca.certificate.subject.to_s
      end

      it 'sets usage for servers' do
        cert.sign(ca.key)
        expect(key_usage.value).to eq 'TLS Web Server Authentication'
      end
    end

    context 'with a client certificate request' do
      let(:cert) do
        EaSSL::Certificate.new(type: 'client',
                               signing_request: csr,
                               ca_certificate: ca.certificate)
      end

      it 'sets usage for clients' do
        cert.sign(ca.key)
        expect(key_usage.value).to eq(
          'TLS Web Client Authentication, E-mail Protection'
        )
      end
    end

    context 'with a subject alt name' do
      let(:cert) do
        EaSSL::Certificate.new(subject_alt_name: ['bar.com'],
                               signing_request: csr,
                               ca_certificate: ca.certificate)
      end
      it 'sets a subject alternative name' do
        cert.sign(ca.key)
        expect(alt_names.value).to match 'DNS:bar.com'
      end
    end

    context 'with multiple subject alt names' do
      let(:cert) do
        EaSSL::Certificate.new(subject_alt_name: ['bar.com', 'foo.com'],
                               signing_request: csr,
                               ca_certificate: ca.certificate)
      end
      it 'sets multiple subject alternative names' do
        cert.sign(ca.key)
        expect(alt_names.value).to match 'DNS:bar.com'
        expect(alt_names.value).to match 'DNS:foo.com'
      end
    end

    it 'loads and verifies a certificate fingerprint' do
      file = File.join(File.dirname(__FILE__), '../test', 'certificate.pem')
      cert = EaSSL::Certificate.load(file)

      expect(cert.sha1_fingerprint).to eq(
        '55:27:E8:46:50:03:39:F4:A3:24:3D:88:57:BA:67:5C:F1:E8:84:1D'
      )
    end

    it 'verifies a given text certificate fingerprint' do
      cert_text = <<CERT
-----BEGIN CERTIFICATE-----
MIIDzzCCAzigAwIBAgIBAjANBgkqhkiG9w0BAQUFADA8MQswCQYDVQQGEwJVUzEO
MAwGA1UECgwFVmVuZGExEDAOBgNVBAsMB2F1dG8tQ0ExCzAJBgNVBAMMAkNBMB4X
DTExMTIwNzE5MTIxN1oXDTE2MTIwNTE5MTIxN1owgakxCzAJBgNVBAYTAlVTMRcw
FQYDVQQIEw5Ob3J0aCBDYXJvbGluYTEWMBQGA1UEBxMNRnVxdWF5IFZhcmluYTEY
MBYGA1UECgwPV2ViUG93ZXIgRGVzaWduMRUwEwYDVQQLDAxXZWIgU2VjdXJpdHkx
FDASBgNVBAMMC2Zvby5iYXIuY29tMSIwIAYJKoZIhvcNAQkBDBNlYXNzbEBydWJ5
Zm9yZ2Uub3JnMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAyqWgYizb
EaafCYheeaTCGLK4FOq42e2CavOComQlWXEGR2YHYOL/cPK9Lpc+f/4qxse8SChx
1maDuUh+iT+fNa/jqbBExmK7h914mXW2pcZCfbboND0Va9wLm63HsMVwY2FGDC9P
Qh5hviVfIoGVbC2ZDI1pt98pexPsSOSHn2ch1q4s/9pfICnWN+KsEyNJuBwlo24t
Eg+zvnVE9w3YzlSQ7NCgPFf1aX2VBWZi50gbAwoxoKyrtZFQ/tIrF6WtMxYTpfYq
LYWLMsb9+xZHkhEc+XvvipD6Y25tlyDWoFOR3sy0B5SZGoik9ZD1bTCWHdEtNRzG
cRoChZSCv9+LeQIDAQABo4HuMIHrMAkGA1UdEwQCMAAwCwYDVR0PBAQDAgWgMB0G
A1UdDgQWBBT6dj30hJuziSwhPx9PnsTyGCi3BjATBgNVHSUEDDAKBggrBgEFBQcD
ATA3BglghkgBhvhCAQ0EKhYoUnVieS9PcGVuU1NML0VhU1NMIEdlbmVyYXRlZCBD
ZXJ0aWZpY2F0ZTBkBgNVHSMEXTBbgBT+n8Ml3oKlSBBaeaaDrWFS9THk5aFApD4w
PDELMAkGA1UEBhMCVVMxDjAMBgNVBAoMBVZlbmRhMRAwDgYDVQQLDAdhdXRvLUNB
MQswCQYDVQQDDAJDQYIBADANBgkqhkiG9w0BAQUFAAOBgQBjN8LEARLiWjxV0o6U
XSM4ubws0pAXya34TIAQnlDKEEssZ0i1IYyyqieCkdaH+n0wnhGLwGf21yyrqCLd
+nDavx/2EBrDcF0yE7aapzXcfeXZ2gZxkZycuwc8dKR6IEXLWrMYS7HKyT490G0R
XBbgCxQiIndLwRnNMavd+vx0Wg==
-----END CERTIFICATE-----
CERT
      cert = EaSSL::Certificate.new({}).load(cert_text)

      expect(cert.sha1_fingerprint).to eq(
        '55:27:E8:46:50:03:39:F4:A3:24:3D:88:57:BA:67:5C:F1:E8:84:1D'
      )
    end

    it 'fails to load a non-existent file' do
      expect { EaSSL::Certificate.load('./foo') }.to raise_error(Errno::ENOENT)
    end

    it 'fails to load a non-certificate file' do
      file = File.join(File.dirname(__FILE__), '..', 'Rakefile')
      expect { EaSSL::Certificate.load(file) }.to raise_error(RuntimeError)
    end
  end
end
