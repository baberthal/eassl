require 'openssl'
require 'eassl'
module EaSSL
  # Author::    Paul Nicholson  (mailto:paul@webpowerdesign.net)
  # Co-Author:: Adam Williams (mailto:adam@thewilliams.ws)
  # Copyright:: Copyright (c) 2006 WebPower Design
  # License::   Distributes under the same terms as Ruby
  class SigningRequest
    attr_reader :extensions

    def initialize(options = {})
      @options = {
        name: {}, # required, CertificateName
        key: nil, # required
        digest: OpenSSL::Digest::SHA512.new
      }.update(options)
      @options[:key] ||= Key.new(@options)
    end

    def ssl
      unless @ssl
        @ssl = OpenSSL::X509::Request.new
        @ssl.version = 0
        @ssl.subject = CertificateName.new(@options[:name].options).name
        @ssl.public_key = key.public_key

        @extensions = []
        ef = OpenSSL::X509::ExtensionFactory.new

        case @options[:type]
        when 'subordinate'
          @extensions << ef.create_extension('basicConstraints', 'CA:TRUE')
        when 'server'
          @extensions << ef.create_extension('basicConstraints', 'CA:FALSE')
          @extensions << ef.create_extension('keyUsage', 'digitalSignature,keyEncipherment')
          @extensions << ef.create_extension('extendedKeyUsage', 'serverAuth')
        when 'client'
          @extensions << ef.create_extension('basicConstraints', 'CA:FALSE')
          @extensions << ef.create_extension('keyUsage', 'nonRepudiation,digitalSignature,keyEncipherment')
          @extensions << ef.create_extension('extendedKeyUsage', 'clientAuth,emailProtection')
        end

        if @options[:subject_alt_name]
          subjectAltName = @options[:subject_alt_name].map { |d| "DNS: #{d}" }.join(',')
          @extensions << ef.create_extension('subjectAltName', subjectAltName)
        end

        if @extensions.count > 0
          seq = OpenSSL::ASN1::Sequence.new(extensions)
          set = OpenSSL::ASN1::Set.new([seq])
          attr = OpenSSL::X509::Attribute.new('extReq', set)
          @ssl.add_attribute(attr)
        end

        @ssl.sign(key.private_key, @options[:digest])
      end
      @ssl
    end

    def key
      @options[:key]
    end

    attr_reader :options

    def to_pem
      ssl.to_pem
    end

    # This method is used to intercept and pass-thru calls to openSSL methods and instance
    # variables.
    def method_missing(method)
      ssl.send(method)
    end

    def self.load(pem_file_path)
      new.load(File.read(pem_file_path))
    end

    def load(pem_string)
      begin
        @ssl = OpenSSL::X509::Request.new(pem_string)
        @extensions = begin
          if attr = ssl.attributes.detect { |a| %w(extReq msExtReq).include?(a.oid) }
            set = OpenSSL::ASN1.decode(attr.value)
            seq = set.value.first
            seq.value.collect { |e| OpenSSL::X509::Extension.new(e) }
          end
        end
      rescue
        raise 'SigningRequestLoader: Error loading signing request'
      end
      self
    end
  end
end
