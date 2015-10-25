require 'eassl'

RSpec.describe EaSSL, '#certficate_authorities' do
  context 'with no prior keys/certs' do
    let(:key) { EaSSL::Key.new }
    let(:ca) { EaSSL::CertificateAuthority.new }
    let(:name) do
      EaSSL::CertificateName.new(
        country: 'GB',
        state: 'London',
        city: 'London',
        organization: 'Venda Ltd',
        department: 'Development',
        common_name: 'foo.bar.com',
        email: 'dev@venda.com'
      )
    end
    let(:csr) { EaSSL::SigningRequest.new(name: name, key: key) }
    let(:cert) { ca.create_certificate(csr) }
    let(:key_usage) do
      cert.extensions.find { |e| e.oid == 'extendedKeyUsage' }.value
    end
    let(:t) { Time.now }

    it 'creates a basic certificate authority' do
      expect(ca.key.length).to eq 2048
      expect(ca.certificate.subject.to_s).to eq '/CN=CA'
    end

    context 'with a server certificate' do
      it 'can properly sign a server certificate' do
        expect(cert.issuer.to_s).to eq '/CN=CA'
        expect(cert.subject.to_s).to eq(
          '/C=GB/ST=London/L=London/O=Venda Ltd/OU=Development/CN=foo.bar.com/emailAddress=dev@venda.com' # rubocop:disable Metrics/LineLength
        )
        expect(key_usage).to eq 'TLS Web Server Authentication'
      end
    end

    context 'with a client certificate' do
      let(:cert) { ca.create_certificate(csr, 'client') }
      it 'can properly sign a client certificate' do
        expect(cert.issuer.to_s).to eq '/CN=CA'
        expect(cert.subject.to_s).to eq(
          '/C=GB/ST=London/L=London/O=Venda Ltd/OU=Development/CN=foo.bar.com/emailAddress=dev@venda.com' # rubocop:disable Metrics/LineLength
        )
        expect(key_usage).to eq 'TLS Web Client Authentication, E-mail Protection' # rubocop:disable Metrics/LineLength
      end
    end

    context 'when options are passed to the certificate creation' do
      let(:cert) { ca.create_certificate(csr, 'server', 10) }
      it 'properly sets expiry on a certificate' do
        expect(cert.ssl.not_after.to_i).to be_within(1)
          .of((t + (24 * 60 * 60 * 10)).to_i)
      end
    end
  end

  context 'given certificate information but not keys/certs' do
    let(:key_usage) do
      cert.extensions.find { |e| e.oid == 'extendedKeyUsage' }.value
    end
    let(:key) { EaSSL::Key.new }
    let(:ca) do
      EaSSL::CertificateAuthority.new(
        name: {
          country: 'GB',
          state: 'London',
          city: 'London',
          organization: 'Venda Ltd',
          department: 'Development',
          common_name: 'CA',
          email: 'dev@venda.com'
        }
      )
    end
    let(:name) do
      EaSSL::CertificateName.new(
        country: 'GB',
        state: 'London',
        city: 'London',
        organization: 'Venda Ltd',
        department: 'Development',
        common_name: 'foo.bar.com',
        email: 'dev@venda.com')
    end
    let(:csr) { EaSSL::SigningRequest.new(name: name, key: key) }
    let(:cert) { ca.create_certificate(csr) }
    let(:t) { Time.now }

    it 'creates a valid CA certificate' do
      expect(ca.certificate.subject.to_s).to eq(
        '/C=GB/ST=London/L=London/O=Venda Ltd/OU=Development/CN=CA/emailAddress=dev@venda.com' # rubocop:disable Metrics/LineLength
      )
      expect(ca.key.length).to eq 2048
      expect(ca.serial).to be_a EaSSL::Serial
    end

    describe 'properly signing' do
      context 'a server certificate' do
        it 'signs the certificate' do
          expect(cert.issuer.to_s).to eq(
            '/C=GB/ST=London/L=London/O=Venda Ltd/OU=Development/CN=CA/emailAddress=dev@venda.com' # rubocop:disable Metrics/LineLength
          )
          expect(cert.subject.to_s).to eq(
            '/C=GB/ST=London/L=London/O=Venda Ltd/OU=Development/CN=foo.bar.com/emailAddress=dev@venda.com' # rubocop:disable Metrics/LineLength
          )
          expect(key_usage).to eq 'TLS Web Server Authentication'
        end
      end

      context 'a client certificate' do
        let(:cert) { ca.create_certificate(csr, 'client') }
        it 'signs the certificate' do
          expect(cert.issuer.to_s).to eq(
            '/C=GB/ST=London/L=London/O=Venda Ltd/OU=Development/CN=CA/emailAddress=dev@venda.com' # rubocop:disable Metrics/LineLength
          )
          expect(cert.subject.to_s).to eq(
            '/C=GB/ST=London/L=London/O=Venda Ltd/OU=Development/CN=foo.bar.com/emailAddress=dev@venda.com' # rubocop:disable Metrics/LineLength
          )
          expect(key_usage).to eq(
            'TLS Web Client Authentication, E-mail Protection'
          )
        end
      end

      context 'setting the expiration' do
        let(:cert) { ca.create_certificate(csr, 'server', 10) }
        it 'properly sets expiry on a certificate' do
          expect(cert.ssl.not_after.to_i).to be_within(1)
            .of((t + (24 * 60 * 60 * 10)).to_i)
        end
      end
    end
  end

  context 'with a certificate file, key, and serial' do
    let(:csr) { EaSSL::SigningRequest.new(name: name, key: key) }
    let(:ca_path) { File.join(File.dirname(__FILE__), '../test', 'CA') }
    let(:ca) do
      EaSSL::CertificateAuthority.load(ca_path: ca_path, ca_password: '1234')
    end
    let(:key_usage) do
      cert.extensions.find { |e| e.oid == 'extendedKeyUsage' }.value
    end
    let(:key) { EaSSL::Key.new }
    let(:name) do
      EaSSL::CertificateName.new(
        country: 'GB',
        state: 'London',
        city: 'London',
        organization: 'Venda Ltd',
        department: 'Development',
        common_name: 'foo.bar.com',
        email: 'dev@venda.com'
      )
    end
    let(:t) { Time.now }

    before(:all) do
      ca_path = File.join(File.dirname(__FILE__), '../test', 'CA')
      File.open(File.join(ca_path, 'serial.txt'), 'w') { |f| f.write('000B') }
    end

    it 'loads the CA certficate' do
      expect(ca.certificate.subject.to_s).to eq '/C=US/O=Venda/OU=auto-CA/CN=CA'
      expect(ca.key.length).to eq 1024
      expect(ca.serial.next).to eq 11
    end

    context 'with a server certificate' do
      let(:cert) { ca.create_certificate(csr) }
      it 'can properly sign a thecertificate' do
        expect(cert.issuer.to_s).to eq '/C=US/O=Venda/OU=auto-CA/CN=CA'
        expect(cert.subject.to_s).to eq(
          '/C=GB/ST=London/L=London/O=Venda Ltd/OU=Development/CN=foo.bar.com/emailAddress=dev@venda.com' # rubocop:disable Metrics/LineLength
        )
        expect(key_usage).to eq 'TLS Web Server Authentication'
      end
    end

    context 'with a client certificate' do
      let(:cert) { ca.create_certificate(csr, 'client') }
      it 'can properly sign a client certificate' do
        expect(cert.issuer.to_s).to eq '/C=US/O=Venda/OU=auto-CA/CN=CA'
        expect(cert.subject.to_s).to eq(
          '/C=GB/ST=London/L=London/O=Venda Ltd/OU=Development/CN=foo.bar.com/emailAddress=dev@venda.com' # rubocop:disable Metrics/LineLength
        )
        expect(key_usage).to eq(
          'TLS Web Client Authentication, E-mail Protection'
        )
      end
    end

    context 'with a server certficate with explicit expiration' do
      let(:cert) { ca.create_certificate(csr, 'server', 10) }
      it 'properly sets expiry on a certificate' do
        expect(cert.ssl.not_after.to_i).to be_within(1)
          .of((t + (24 * 60 * 60 * 10)).to_i)
      end
    end

    describe 'incrementing the serial' do
      it 'increments the serial after signing a certificate' do
        next_serial = ca.serial.next
        csr = EaSSL::SigningRequest.new(name: name, key: key)
        cert = ca.create_certificate(csr)

        expect(cert.serial.to_i).to eq next_serial
        expect(ca.serial.next).to eq next_serial + 1

        ca = EaSSL::CertificateAuthority.load(
          ca_path: ca_path, ca_password: '1234'
        )
        expect(ca.serial.next).to eq next_serial + 1
      end
    end
  end
end
