require 'eassl'

RSpec.describe EaSSL, '#key' do
  let(:key) { EaSSL::Key.new }
  let(:enckey) { key.to_pem }
  it 'creates a new key' do
    expect(key.ssl).to be_a OpenSSL::PKey::RSA
  end

  it 'creates a new private key' do
    expect(key.private_key).to be_a OpenSSL::PKey::RSA
  end

  it 'creates a 2048-bit key by default' do
    expect(key.length).to eq 2048
  end

  context 'with an explicit key size' do
    let(:key) { EaSSL::Key.new(bits: 4096) }
    it 'creates a specified key size' do
      expect(key.length).to eq 4096
    end
  end

  it 'creates a key with a default password' do
    key2 = OpenSSL::PKey::RSA.new(enckey, 'ssl_password')
    expect(key.ssl.to_s).to eq key2.to_s
  end

  context 'with a specified password' do
    let(:key) { EaSSL::Key.new(password: 'xyzzy') }
    let(:enckey) { key.to_pem }

    it 'creates a key with a specified password' do
      key2 = OpenSSL::PKey::RSA.new(enckey, 'xyzzy')
      expect(key.ssl.to_s).to eq key2.to_s
    end

    it 'creates a formatted PEM string' do
      expect(enckey).to match 'BEGIN RSA PRIVATE KEY'
      expect(enckey).to match 'ENCRYPTED'
    end
  end

  describe 'loading a key' do
    context 'from string input' do
      it 'loads a key from string input' do
        key_text = <<KEY
-----BEGIN RSA PRIVATE KEY-----
MIGsAgEAAiEAy57X7ZFkqicM+Nb9kOjCBs0Fz3dc3F3nhqx9cDnwHaMCAwEAAQIh
ALOYKsOzVaJuRxbEKWpCob5hIpOCJqwmdA9cFbrEv9zhAhEA/B/sb8dzCvaFM/p5
Bt6Y7QIRAM7AD/gt+xiWUH8z+ra7js8CEQCXelqkofFloc1P+GnkjbLVAhAriPXT
5JrDCqPYpTFd2RCxAhEA+WMGuSLXT3xK5XP/LHIiVg==
-----END RSA PRIVATE KEY-----
KEY
        key = EaSSL::Key.new.load(key_text)
        expect(key.length).to eq 256
      end

      it 'loads an encrypted key from string input' do
        key_text = <<KEY
-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: DES-EDE3-CBC,95157FEDE26860DF

QtQcPFoYz58qBAE1BgrhZriIF8CFvMYgK5p92fSSHt9V2ySeEuBMwLJncp4tBJGG
IbjBVK9v4VB8NxrGoC7Qs/0JI5PkMVxwUIuzRC+KAXnImRaV258t+ydboYIwnsfl
2Do9eQonjPOWHvU1vWCQMXa/Jku9cqJnL3a7quZaGPHDW0ch/v2zPbF2LOFFJV8v
YvdYo7ml27+Zrr0rmnhF/XVtDwkQd/K0I3sXIr92fHk=
-----END RSA PRIVATE KEY-----
KEY
        key = EaSSL::Key.new.load(key_text)
        expect(key.length).to eq 256
      end
    end

    context 'from a file' do
      context 'with an unencrypted key' do
        let(:key) { EaSSL::Key.load(file) }
        let(:file) do
          File.join(File.dirname(__FILE__), '../test/unencrypted_key.pem')
        end

        it 'loads a key from a file' do
          expect(key.length).to eq 256
        end
      end

      context 'with an encrypted key' do
        let(:key) { EaSSL::Key.load(file, 'ssl_password') }
        let(:file) do
          File.join(File.dirname(__FILE__), '../test/encrypted_key.pem')
        end

        it 'loads an encrypted key from a file' do
          expect(key.length).to eq 256
        end
      end

      context 'when the key does not exist' do
        it 'fails to load' do
          expect { EaSSL::Key.load('./foo') }.to raise_error(Errno::ENOENT)
        end
      end

      context 'when the key is improperly formatted' do
        let(:file) { File.join(File.dirname(__FILE__), '..', 'Rakefile') }
        it 'fails to load' do
          expect { EaSSL::Key.load(file) }.to raise_error(RuntimeError)
        end
      end
    end
  end
end
