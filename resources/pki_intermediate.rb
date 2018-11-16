# rubocop:disable Layout/LeadingCommentSpace, Style/BlockComments
require 'vault'

resource_name :vault_pki_intermediate

property :signing_ca, Hash, required: true, desired_state: false, sensitive: true
property :common_name, String, name_property: true
property :destination_path, String, default: '/tmp', desired_state: false
#<> @property type internal or exported, if exported the private key will be written with the certificate in `destination_path/common_name`
property :type, ['internal','exported'], default: 'internal', desired_state: false
#<> @property alt_names Array of alternative names (sans) to add into the certificate
property :alt_names, Array, default: []
property :ip_sans, Array, default: []
property :uri_sans, Array, default: []
property :other_sans, Array, default: []
property :format, %w(pem der pem_bundle), default: 'pem', desired_state: false
property :private_key_format, %w(der pkcs8), desired_state: false
property :key_type, %w(rsa ec), default: 'rsa', desired_state: false
property :key_bits, Integer, default: 2048, desired_state: false
property :exclude_cn_from_sans, [true, false], default: false, desired_state: false
property :ou, String, default: ''
property :organization, String, default: ''
property :country, String, default: ''
property :locality, String, default: ''
property :province, String, default: ''
property :street_address, String, default: ''
property :postal_code, String, default: ''
property :ca_url, String, default: ''
property :crl_url, String, default: ''
property :ocsp_servers, String, default: ''
# Files properties (when exported)
property :owner, String
property :mode, String, default: '0600'
property :group, String
# Vault properties
#<> @property reissue_within_days Issue a new CA certificate if the current one is due to expire in less than this value in days
property :reissue_within_days, Integer, default: 90, desired_state: false
property :force_issue, [true, false], default: false
property :vault_auth_method, String, default: 'token', desired_state: false, callbacks: {
    "should be one of Vault::Authenticate methods: #{Vault::Authenticate.instance_methods(false)}" => lambda do |m|
      Vault.auth.respond_to?(m)
    end,
}
property :vault_auth_credentials, Array, desired_state: false, default: [], sensitive: true
#<> @property vault_client_options Define the option to pass to vault client, could be empty to use environment variables.
property :vault_client_options, Hash, desired_state: false, default: {}, callbacks: {
    "options should only include valid keys: #{Vault::Configurable.keys}" => lambda do |v|
      (v.keys.map { |k| k.is_a?(String) ? k.to_sym : k } - Vault::Configurable.keys).empty?
    end,
    'address should be a valid url' => lambda do |v|
      v.empty? || URI.parse(v['address'])
    end,
}
#<> @property vault_role where to mount this pki backend in vault.
property :vault_role, String, default: 'pki', desired_state: false

load_current_value do |desired|
  cert_path = "#{desired.certificate_path}/#{desired.common_name}/certificate.pem"
  vault_auth
  begin
    current_cert = @vault.with_retries do |attempts, error|
      Chef::Log.info "Received exception #{error.class} from Vault - attempt #{attempts}" unless attempts == 0
      @vault.logical.read(
          "/#{new_resource.vault_role}/ca"
      )
    end
  rescue Vault::HTTPError
    current_cert = nil
  end
  begin
    urls = @vault.with_retries do |attempts, error|
      Chef::Log.info "Received exception #{error.class} from Vault - attempt #{attempts}" unless attempts == 0
      @vault.logical.read(
          "/#{new_resource.vault_role}/config/urls"
      )
    end
    unless urls.nil?
      issuing_certificates urls.data['issuing_certificates']
      crl_distribution_points urls.data['crl_distribution_points']
      ocsp_servers urls.data['ocsp_servers']
    end
  rescue Vault::HTTPError
    issuing_certificates ''
    crl_distribution_points ''
    ocsp_servers ''
  end
  if ::File.exist?(cert_path)
    current_cert = OpenSSL::X509::Certificate.new ::File.read cert_path
  end
  if current_cert != nil
    cert = OpenSSL::X509::Certificate.new ::File.read cert_path
    cert_common_name = cert.subject.to_s(OpenSSL::X509::Name::COMPAT).split('=')[1]
    common_name cert_common_name
    current_alt_names = []
    current_ip_sans = []
    current_uri_sans = []
    current_other_sans = []
    cert.issuer.to_a.each do |entry|
      case entry[0]
      when 'C'
        country entry[1]
      when 'ST'
        province entry[1]
      when 'L'
        locality entry[1]
      when 'O'
        organization entry[1]
      when 'OU'
        ou entry[1]
      when 'street'
        street_address entry[1]
      when 'postalCode'
        postal_code entry[1]
      end
    end
    cert.extensions.each do |ext|
      next unless ext.oid().to_s == 'subjectAltName'
      # "subjectAltName = DNS:test.wherefor.com, DNS:test2.wherefor.com, DNS:test3.wherefor.com, IP Address:127.0.0.1, IP Address:127.0.0.2"
      ext.to_s.split('=')[1].split(',').each do |name|
        type, value = name.split(':',1)
        case type.strip
        when 'DNS'
          current_alt_names.push(value)
        when 'IP Address'
          current_ip_sans.push(value)
        when 'URI'
          current_uri_sans.push(value)
        when 'otherName'
          current_other_sans.push(value)
        end
        alt_names current_alt_names.sort - [desired.common_name, cert_common_name]
        ip_sans current_ip_sans.sort
        uri_sans current_uri_sans.sort
        other_sans current_other_sans.sort
      end
    end
  else
    common_name ''
  end
end

action :issue do
  issuing, reason = should_issue?
  vault_auth
  if issuing
    converge_by reason do
      issue_ca
    end
  else
    converge_if_changed :common_name, :alt_names, :ip_sans do
      issue_ca
    end
  end
end

action_class do
  def should_issue?
    cert_path = "#{new_resource.destination_path}/#{new_resource.common_name}/certificate.pem"
    return [true, 'issuing because :force_issue is true'] if new_resource.force_issue
    return [true, "issuing because no cert at :certificate_path (#{cert_path}) exists"] unless ::File.exist?(cert_path)
    cert = OpenSSL::X509::Certificate.new ::File.read cert_path
    not_after = cert.not_after
    days_until_expiry = (not_after - Time.now.utc()) / (60 * 60 * 24)
    return [true, "reissuing because cert is set to expire within :reissue_within_days (#{new_resource.reissue_within_days}) (expires in #{days_until_expiry})"] if days_until_expiry < new_resource.reissue_within_days
    [false, '']
  end

  def vault_auth
    @vault = Vault::Client.new(new_resource.vault_client_options)
    @vault.auth.send new_resource.vault_auth_method, *new_resource.vault_auth_credentials
  end

  def issue_ca
    begin
      secret = @vault.with_retries do |attempts, error|
        Chef::Log.info "Received exception #{error.class} from Vault - attempt #{attempts}" unless attempts == 0
        @vault.logical.write(
            "/#{new_resource.vault_role}/intermediate/generate/#{new_resource.type}",
            common_name: new_resource.common_name,
            alt_names: new_resource.alt_names.join(',').strip().chomp(','),
            ip_sans: new_resource.ip_sans.sort.join(',').strip().chomp(','),
            uri_sans: new_resource.uri_sans.sort.join(',').strip().chomp(','),
            other_sans: new_resource.other_sans.sort.join(',').strip().chomp(','),
            ttl: (new_resource.ttl_days * 24).to_s + 'h',
            format: new_resource.format,
            private_key_format: new_resource.private_key_format,
            key_type: new_resource.key_type,
            key_bits: new_resource.key_bits,
            exclude_cn_from_sans: new_resource.exclude_cn_from_sans,
            ou: new_resource.ou,
            organization: new_resource.organization,
            country: new_resource.country,
            locality: new_resource.locality,
            province: new_resource.province,
            street_address: new_resource.street_address,
            postal_code: new_resource.postal_code,
            )
      end
    rescue Vault::HTTPError => e
      message = "Failed to create CA cert - #{new_resource.common_name}.\n#{e.message}"
      Chef::Log.fatal message
    end
    if secret.nil?
      message = "Could not create CA cert - #{new_resource.common_name}, no data retrieved"
      Chef::Log.fatal message
      return
    end
    Chef::Log.warn secret.inspect
    ca = OpenSSL::X509::Certificate.new new_resource.signing_ca['cert']
    ca_key = OpenSSL::X509.read File.read(new_resource.signing_ca['key']), new_resource.signing_ca['passphrase']
    csr = OpenSSL::X509::Certificate.new secret.data['csr']
    csr.issuer = ca.subject
    csr.sign ca_key, OpenSSL::Digest::SHA512.new
    secret.data['cert'] = csr.to_pem
    begin
      @vault.with_retries do |attempts, error|
        Chef::Log.info "Received exception #{error.class} from Vault - attempt #{attempts}" unless attempts == 0
        @vault.logical.write(
            "/#{new_resource.vault_role}/intermediate/set_signed",
            certificate: csr.to_pem
        )
      end
    rescue Vault::HTTPError => e
      message = "Failed to create CA cert - #{new_resource.common_name}.\n#{e.message}"
      Chef::Log.fatal message
    end
    converge_if_changed :issuing_certificatesn, :crl_distribution_points, :ocsp_servers do
      begin
        @vault.with_retries do |attempts, error|
          Chef::Log.info "Received exception #{error.class} from Vault - attempt #{attempts}" unless attempts == 0
          @vault.logical.write(
              "/#{new_resource.vault_role}/config/urls",
              issuing_certificates: new_resource.ca_url,
              crl_distribution_points: new_resource.crl_url,
              ocsp_servers: new_resource.ocsp_servers
          )
        end
      rescue Vault::HTTPError => e
        message = "Failed to set urls - #{new_resource.common_name}.\n#{e.message}"
        Chef::Log.fatal message
      end
    end
    return unless new_resource.type == 'exported'
    directory "#{new_resource.destination_path}/#{new_resource.common_name}" do
      owner new_resource.owner
      group new_resource.group
      mode new_resource.mode
      recursive true
    end
    secret.data.keys.each do |f|
      file "#{new_resource.certificate_path.chomp('/')}/#{new_resource.common_name}/#{f}.pem" do
        owner new_resource.owner
        group new_resource.group
        mode new_resource.mode
        content secret.data[f].to_s
        sensitive true
      end
    end
  end
end