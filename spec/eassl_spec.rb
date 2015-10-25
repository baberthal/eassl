require 'eassl'

RSpec.describe EaSSL, '#self_signed_certificate' do
  context 'with no prior keys/certs' do
    it 'creates a self-signed certificate' do
      name = EaSSL::CertificateName.new(common_name: 'foo.bar.com')
      key = EaSSL::Key.new(bits: 4096)
      ca, sr, cert = EaSSL.generate_self_signed(name: name,
                                                key: key,
                                                subject_alt_name: ['bar.com'])
      key = sr.key

      expect(ca).to be_a EaSSL::CertificateAuthority
      expect(ca.certificate.subject.to_s).to eq '/CN=CA'

      expect(sr).to be_a EaSSL::SigningRequest
      expect(sr.subject.to_s).to eq '/CN=foo.bar.com'
      expect(sr.options[:subject_alt_name]).to eq ['bar.com']

      expect(cert).to be_a EaSSL::Certificate
      expect(cert.subject.to_s).to eq '/CN=foo.bar.com'
      expect(cert.extensions.find { |e| e.oid == 'subjectAltName' }.value)
        .to match 'bar.com'

      expect(key).to be_a EaSSL::Key
      expect(key.length).to eq 4096
    end
  end
end
