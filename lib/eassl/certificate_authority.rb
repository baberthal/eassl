require 'openssl'
require 'eassl'
module EaSSL
  # Author::    Paul Nicholson  (mailto:paul@webpowerdesign.net)
  # Co-Author:: Adam Williams (mailto:adam@thewilliams.ws)
  # Copyright:: Copyright (c) 2006 WebPower Design
  # License::   Distributes under the same terms as Ruby
  class CertificateAuthority
    attr_reader :key, :certificate, :serial
    def initialize(options = {})
      if options[:key] && options[:certificate] && options[:serial]
        @key = options[:key]
        @certificate = options[:certificate]
        @serial = options[:serial]
      else
        options[:name] ||= {}
        @key = Key.new({ password: 'ca_ssl_password' }.update(options))
        @certificate = AuthorityCertificate.new(key: @key, name: options[:name])
        @serial = Serial.new(next: 1)
      end
    end

    def self.load(options)
      key = Key.load(File.join(options[:ca_path], 'cakey.pem'), options[:ca_password])
      certificate = AuthorityCertificate.load(File.join(options[:ca_path], 'cacert.pem'))
      serial = Serial.load(File.join(options[:ca_path], 'serial.txt'))
      new(key: key, certificate: certificate, serial: serial)
    end

    def create_certificate(signing_request, type = 'server', days_valid = nil, digest = OpenSSL::Digest::SHA512.new)
      options = {
        signing_request: signing_request,
        ca_certificate: @certificate,
        serial: @serial.issue_serial,
        type: type
      }
      options[:days_valid] = days_valid if days_valid
      cert = Certificate.new(options)
      @serial.save!
      cert.sign(@key, digest)
      cert
    end
  end
end
