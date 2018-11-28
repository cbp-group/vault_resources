# Description

Collection of resources to interact with an hashicorp's vault server
Those resource are used internally by CBP-Group for various use cases, including a Letsencrypt like generation of certificates for private AWS Application Load Balancers (ALB)

This cookbook has been created by DTD-Platforms, part of the DTD-Platform & Services departement handling CBP-Group infrastructure.





# Requirements

Used on windows and ubuntu platforms, should work on eveything compatible with Chef 13 and above
## Platform:

* aix
* amazon
* centos
* fedora
* freebsd
* debian
* oracle
* mac_os_x
* redhat
* suse
* opensuse
* opensuseleap
* ubuntu
* windows
* zlinux

## Cookbooks:

*No dependencies defined*

# Attributes

*No attributes defined*

# Recipes

* vault_resources::default
* vault_resources::vault_certificate_example

# Resources

* [vault_certificate](#vault_certificate)
* [vault_pki_intermediate](#vault_pki_intermediate)
* [vault_pki_role](#vault_pki_role)
* [vault_pki_root](#vault_pki_root)

## vault_certificate

This resource allow to request certificates from a vault server

### Actions

- issue: Require the certificate Default action.

### Attribute Parameters

- common_name: The common_name of the certificate, taken fromt he resource name
- certificate_path: Where to write the resulting certificate files
- owner:
- mode:
- group:
- alt_names: Array of alternative names (sans) to add into the certificate Defaults to <code>[]</code>.
- ip_sans: Array of alternative names in IP format to add into the certificate Defaults to <code>[]</code>.
- uri_sans: Array of URI:value to add into the certificate Defaults to <code>[]</code>.
- other_sans: Array of OID;UTF-8:value to add into the certificate Defaults to <code>[]</code>.
- ttl_days: Validity of the certificate in days Defaults to <code>365</code>.
- format:  Defaults to <code>"pem"</code>.
- private_key_format:
- exclude_cn_from_sans:  Defaults to <code>false</code>.
- reissue_within_days: Issue a new certificate if the current one is due to expire in less than this value in days Defaults to <code>15</code>.
- force_issue:  Defaults to <code>false</code>.
- vault_auth_method:  Defaults to <code>"token"</code>.
- vault_auth_credentials:  Defaults to <code>[]</code>.
- vault_client_options: Define the option to pass to vault client, could be empty to use environment variables. Defaults to <code>{}</code>.
- vault_role:  Defaults to <code>"pki/issue/webserver"</code>.

### Remarks

  The certificates files will be created under <certificate_path>/<common_name>

  - `vault_auth method` is one supported by [Vault::Authenticate](https://www.rubydoc.info/github/hashicorp/vault-ruby/Vault/Authenticate)
  - `vault_auth_credentials` is an array which should match the method parameters of `vault_auth_method`
  - `vault_client_options` is a hash for which keys should be in Vault::Configurable.keys, the token will be set by the auth method and can be avoided
  - `vault_role` is the role in the pki backend to which requesting the certificate, must be of the form `<backend>/issue/<role>`

  You can omit the vault_client_options like address if you want to use the environment variables for vault.

### Examples

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

## vault_pki_intermediate

### Actions

- issue:  Default action.

### Attribute Parameters

- signing_ca:
- common_name:
- destination_path:  Defaults to <code>"/tmp"</code>.
- type: internal or exported, if exported the private key will be written with the certificate in `destination_path/common_name` Defaults to <code>"internal"</code>.
- alt_names: Array of alternative names (sans) to add into the certificate Defaults to <code>[]</code>.
- ip_sans: Array of alternative names in IP format to add into the certificate Defaults to <code>[]</code>.
- uri_sans: Array of URI:value to add into the certificate Defaults to <code>[]</code>.
- other_sans: Array of OID;UTF-8:value to add into the certificate Defaults to <code>[]</code>.
- format:  Defaults to <code>"pem"</code>.
- private_key_format:
- key_type:  Defaults to <code>"rsa"</code>.
- key_bits:  Defaults to <code>2048</code>.
- exclude_cn_from_sans:  Defaults to <code>false</code>.
- ou:  Defaults to <code>""</code>.
- organization:  Defaults to <code>""</code>.
- country:  Defaults to <code>""</code>.
- locality:  Defaults to <code>""</code>.
- province:  Defaults to <code>""</code>.
- street_address:  Defaults to <code>""</code>.
- postal_code:  Defaults to <code>""</code>.
- issuing_certificates:  Defaults to <code>""</code>.
- crl_distribution_points:  Defaults to <code>""</code>.
- ocsp_servers:  Defaults to <code>""</code>.
- ttl_days: Validity of the CA certificate in days Defaults to <code>365</code>.
- owner:
- mode:
- group:
- reissue_within_days: Issue a new CA certificate if the current one is due to expire in less than this value in days Defaults to <code>90</code>.
- force_issue:  Defaults to <code>false</code>.
- vault_auth_method:  Defaults to <code>"token"</code>.
- vault_auth_credentials:  Defaults to <code>[]</code>.
- vault_client_options: Define the option to pass to vault client, could be empty to use environment variables. Defaults to <code>{}</code>.
- vault_role: where to mount this pki backend in vault. Defaults to <code>"pki"</code>.

## vault_pki_role

### Actions

- create:  Default action.
- delete:

### Attribute Parameters

- ttl:  Defaults to <code>"2160h"</code>.
- max_ttl:  Defaults to <code>"8760h"</code>.
- allow_localhost:  Defaults to <code>true</code>.
- allowed_domains:  Defaults to <code>[]</code>.
- allow_bare_domains:  Defaults to <code>false</code>.
- allow_subdomains:  Defaults to <code>false</code>.
- allow_glob_domains:  Defaults to <code>false</code>.
- allow_any_name:  Defaults to <code>false</code>.
- enforce_hostnames:  Defaults to <code>true</code>.
- allow_ip_sans:  Defaults to <code>false</code>.
- allowed_uri_sans:  Defaults to <code>[]</code>.
- allowed_other_sans:  Defaults to <code>[]</code>.
- server_flag:  Defaults to <code>true</code>.
- client_flag:  Defaults to <code>true</code>.
- code_signing_flag:  Defaults to <code>false</code>.
- email_protection_flag:  Defaults to <code>false</code>.
- key_type:  Defaults to <code>"rsa"</code>.
- key_bits:  Defaults to <code>2048</code>.
- key_usage:  Defaults to <code>["DigitalSignature", "KeyAgreement", "KeyEncipherment"]</code>.
- ext_key_usage:  Defaults to <code>[]</code>.
- use_csr_common_name:  Defaults to <code>true</code>.
- use_csr_sans:  Defaults to <code>true</code>.
- ou:  Defaults to <code>[]</code>.
- organization:  Defaults to <code>[]</code>.
- country:  Defaults to <code>[]</code>.
- locality:  Defaults to <code>[]</code>.
- province:  Defaults to <code>[]</code>.
- street_address:  Defaults to <code>[]</code>.
- postal_code:  Defaults to <code>[]</code>.
- generate_lease:  Defaults to <code>false</code>.
- no_store:  Defaults to <code>false</code>.
- require_cn:  Defaults to <code>true</code>.
- policy_identifiers:  Defaults to <code>[]</code>.
- basic_constraints_valid_for_non_ca:  Defaults to <code>false</code>.
- not_before_duration:  Defaults to <code>30</code>.
- vault_pki:  Defaults to <code>"pki"</code>.
- vault_auth_method:  Defaults to <code>"token"</code>.
- vault_auth_credentials:  Defaults to <code>[]</code>.
- vault_client_options: Define the option to pass to vault client, could be empty to use environment variables. Defaults to <code>{}</code>.
- vault_role: name of the role to create, taken from resource name.

## vault_pki_root

### Actions

- issue:  Default action.

### Attribute Parameters

- common_name:
- destination_path:  Defaults to <code>"/tmp"</code>.
- type: internal or exported, if exported the private key will be written with the certificate in `destination_path/common_name` Defaults to <code>"internal"</code>.
- alt_names: Array of alternative names (sans) to add into the certificate Defaults to <code>[]</code>.
- ip_sans: Array of alternative names in IP format to add into the certificate Defaults to <code>[]</code>.
- uri_sans: Array of URI:value to add into the certificate Defaults to <code>[]</code>.
- other_sans: Array of OID;UTF-8:value to add into the certificate Defaults to <code>[]</code>.
- ttl_days: Validity of the CA certificate in days Defaults to <code>365</code>.
- format:  Defaults to <code>"pem"</code>.
- private_key_format:
- key_type:  Defaults to <code>"rsa"</code>.
- key_bits:  Defaults to <code>2048</code>.
- max_path_length:  Defaults to <code>-1</code>.
- exclude_cn_from_sans:  Defaults to <code>false</code>.
- permitted_dns_domains:  Defaults to <code>[]</code>.
- ou:  Defaults to <code>""</code>.
- organization:  Defaults to <code>""</code>.
- country:  Defaults to <code>""</code>.
- locality:  Defaults to <code>""</code>.
- province:  Defaults to <code>""</code>.
- street_address:  Defaults to <code>""</code>.
- postal_code:  Defaults to <code>""</code>.
- issuing_certificates:  Defaults to <code>""</code>.
- crl_distribution_points:  Defaults to <code>""</code>.
- ocsp_servers:  Defaults to <code>""</code>.
- owner:
- mode:
- group:
- reissue_within_days: Issue a new CA certificate if the current one is due to expire in less than this value in days Defaults to <code>90</code>.
- force_issue:  Defaults to <code>false</code>.
- vault_auth_method:  Defaults to <code>"token"</code>.
- vault_auth_credentials:  Defaults to <code>[]</code>.
- vault_client_options: Define the option to pass to vault client, could be empty to use environment variables. Defaults to <code>{}</code>.
- vault_role: where to mount this pki backend in vault. Defaults to <code>"pki"</code>.

# License and Maintainer

Maintainer:: DTD-Platforms (<dtd-plateformes@cbp-group.com>)

Source:: https://github.com/Tensibai/vault_resources

Issues:: https://github.com/Tensibai/vault_resources/issues

License:: MIT
