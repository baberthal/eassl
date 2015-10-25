require 'openssl'
require 'eassl'
module EaSSL
  # Author::    Paul Nicholson  (mailto:paul@webpowerdesign.net)
  # Co-Author:: Adam Williams (mailto:adam@thewilliams.ws)
  # Copyright:: Copyright (c) 2006 WebPower Design
  # License::   Distributes under the same terms as Ruby
  class Certificate
    def initialize(options)
      @options = {
        days_valid: (365 * 5),
        signing_request: nil, # required
        ca_certificate: nil, # required
        comment: 'Ruby/OpenSSL/EaSSL Generated Certificate',
        type: 'server',
        subject_alt_name: nil, # optional e.g. [ "*.example.com", "example.com" ]
        override_req: true
      }.update(options)
    end

    def ssl
      unless @ssl
        @ssl = OpenSSL::X509::Certificate.new
        @ssl.not_before = Time.now
        @ssl.subject = @options[:signing_request].subject
        @ssl.issuer = @options[:ca_certificate] ? @options[:ca_certificate].subject : @ssl.subject
        @ssl.not_after = @ssl.not_before + @options[:days_valid] * 24 * 60 * 60
        @ssl.public_key = @options[:signing_request].public_key
        @ssl.serial = @options[:serial] || 2
        @ssl.version = 2 # X509v3

        ef = OpenSSL::X509::ExtensionFactory.new
        ef.subject_certificate = @ssl
        ef.issuer_certificate = @options[:ca_certificate] ? @options[:ca_certificate].ssl : @ssl
        @ssl.extensions = [ef.create_extension('subjectKeyIdentifier', 'hash')]
        @ssl.add_extension(ef.create_extension('authorityKeyIdentifier', 'keyid:always,issuer:always'))

        extensions = []

        extensions << ef.create_extension('basicConstraints', 'CA:FALSE')
        extensions << ef.create_extension('nsComment', @options[:comment])

        case @options[:type]
        when 'server'
          extensions << ef.create_extension('keyUsage', 'digitalSignature,keyEncipherment')
          extensions << ef.create_extension('extendedKeyUsage', 'serverAuth')
        when 'client'
          extensions << ef.create_extension('keyUsage', 'nonRepudiation,digitalSignature,keyEncipherment')
          extensions << ef.create_extension('extendedKeyUsage', 'clientAuth,emailProtection')
        end

        # add subject alternate names
        if @options[:subject_alt_name]
          subjectAltName = @options[:subject_alt_name].map { |d| "DNS: #{d}" }.join(',')
          extensions << ef.create_extension('subjectAltName', subjectAltName)
        end

        if sr = @options[:signing_request]
          sr.extensions.each do |ext|
            if @options[:override_req] # CA extensions take precedence in merge, default behavior
              extensions << ext unless extensions.any? { |e| e.oid == ext.oid }
            else # Req extensions take precedence in merge
              extensions.delete_if { |e| e.oid == ext.oid }
              extensions << ext
            end
          end
        end

        extensions.each do |ext|
          @ssl.add_extension(ext)
        end

      end
      @ssl
    end

    def sign(ca_key, digest = OpenSSL::Digest::SHA1.new)
      ssl.sign(ca_key.private_key, digest)
    end

    def to_pem
      ssl.to_pem
    end

    # Returns a SHA1 fingerprint of the certificate in the OpenSSL style
    def sha1_fingerprint
      Digest::SHA1.hexdigest(ssl.to_der).upcase.gsub(/(..)/, '\1:').chop
    end

    # This method is used to intercept and pass-thru calls to openSSL methods and instance
    # variables.
    def method_missing(method)
      ssl.send(method)
    end

    def self.load(pem_file_path)
      new({}).load(File.read(pem_file_path))
    end

    def load(pem_string)
      begin
        @ssl = OpenSSL::X509::Certificate.new(pem_string)
      rescue
        raise 'CertificateLoader: Error loading certificate'
      end
      self
    end
  end
end
