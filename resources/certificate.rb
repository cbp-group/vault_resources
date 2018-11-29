# Work derived from:
# WhereTo vault_pki  https://github.com/wherefortravel/vault_pki
# sous-chef's vault cookbook secret https://github.com/sous-chefs/vault

# rubocop:disable Layout/LeadingCommentSpace, Style/BlockComments
=begin
#<
This resource allow to request certificates from a vault server

@action issue Require the certificate

@section Remarks

  The certificates files will be created under <certificate_path>/<common_name>

  - `vault_auth method` is one supported by [Vault::Authenticate](https://www.rubydoc.info/github/hashicorp/vault-ruby/Vault/Authenticate)
  - `vault_auth_credentials` is an array which should match the method parameters of `vault_auth_method`
  - `vault_client_options` is a hash for which keys should be in Vault::Configurable.keys, the token will be set by the auth method and can be avoided
  - `vault_role` is the role in the pki backend to which requesting the certificate, must be of the form `<backend>/issue/<role>`

  You can omit the vault_client_options like address if you want to use the environment variables for vault.

@section Examples

  ```
  vault_certificate 'test.example.com' do
    certificate_path '/tmp'
    alt_names ['test2.example.com', 'test3.example.com']
    ip_sans ['127.0.0.1', node['ipaddress']]
    ttl_days 30

    vault_auth_method 'token'
    vault_auth_credentials ['3VRLzAKbpU58Wgio1a5K8G1E']
    vault_client_options('server_url' => 'http://127.0.0.1:8200')
    vault_role 'pki/issue/webserver'
  end
  ```
#>
=end
require 'vault'

resource_name :vault_certificate

#<> @property common_name The common_name of the certificate, taken fromt he resource name
property :common_name, String, name_property: true
#<> @property certificate_path Where to write the resulting certificate files
property :certificate_path, String, required: true
# Files properties
property :owner, String
property :mode, String
property :group, String
#<> @property alt_names Array of alternative names (sans) to add into the certificate
property :alt_names, Array, default: []
#<> @property ip_sans Array of alternative names in IP format to add into the certificate
property :ip_sans, Array, default: []
#<> @property uri_sans Array of URI:value to add into the certificate
property :uri_sans, Array, default: []
#<> @property other_sans Array of OID;UTF-8:value to add into the certificate
property :other_sans, Array, default: []
#<> @property ttl_days Validity of the certificate in days
property :ttl_days, Integer, default: 365
property :format, %w(pem der pem_bundle), default: 'pem', desired_state: false
property :private_key_format, %w(der pkcs8), desired_state: false
property :exclude_cn_from_sans, [true, false], default: false, desired_state: false
#<> @property reissue_within_days Issue a new certificate if the current one is due to expire in less than this value in days
property :reissue_within_days, Integer, default: 15, desired_state: false
property :force_issue, [true, false], default: false, desired_state: false
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
}, coerce: proc { |i|
  i.map { |k, v| [k.to_sym, v] }.to_h
}
property :vault_role, String, default: 'pki/issue/webserver', desired_state: false, callbacks: {
  'must be a issue endpoint' => lambda do |r|
    !(r =~ %r{.+/issue/.+}).nil?
  end,
}

load_current_value do |desired|
  cert_path = "#{desired.certificate_path}/#{desired.common_name}/certificate.pem"
  if ::File.exist?(cert_path)
    cert = OpenSSL::X509::Certificate.new ::File.read cert_path
    Chef::Log.warn cert.inspect
    cert_common_name = ''
    cert.subject.to_a.each do |entry|
      case entry[0]
      when 'CN'
        cert_common_name = entry[1]
        common_name entry[1]
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
    current_alt_names = []
    current_ip_sans = []
    current_uri_sans = []
    current_other_sans = []
    cert.extensions.each do |ext|
      next unless ext.oid.to_s == 'subjectAltName'
      # "subjectAltName = DNS:test.wherefor.com, DNS:test2.wherefor.com, DNS:test3.wherefor.com, IP Address:127.0.0.1, IP Address:127.0.0.2"
      ext.value.to_s.split(',').each do |name|
        type, value = name.split(':')
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
      issue_cert
    end
  else
    converge_if_changed :common_name, :alt_names, :ip_sans do
      issue_cert
    end
  end
end

action_class do
  def should_issue?
    cert_path = "#{new_resource.certificate_path}/#{new_resource.common_name}/certificate.pem"
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

  def issue_cert
    secret = @vault.with_retries do |attempts, error|
      Chef::Log.info "Received exception #{error.class} from Vault - attempt #{attempts}" unless attempts == 0
      @vault.logical.write(
        new_resource.vault_role,
        common_name: new_resource.common_name,
        alt_names: new_resource.alt_names.join(',').strip().chomp(','),
        ip_sans: new_resource.ip_sans.sort.join(',').strip().chomp(','),
        ttl: (new_resource.ttl_days * 24).to_s + 'h'
      )
    end

    if secret.nil?
      message = "Could not create cert - #{new_resource.common_name}"
      raise message
    end

    directory "#{new_resource.certificate_path}/#{new_resource.common_name}" do
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
