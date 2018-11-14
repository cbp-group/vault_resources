# Description

Library of vault resources to handle secrets

# Requirements

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

## vault_certificate

This resource allow to request certificates from a vault server

### Actions

- issue: Require the certificate Default action.

### Attribute Parameters

- common_name: The common_name of the certificate, taken fromt he resource name
- certificate_path: Where to write the resulting certificate files
- owner:
- mode:  Defaults to <code>"0600"</code>.
- group:
- alt_names: Array of alternative names (sans) to add into the certificate Defaults to <code>[]</code>.
- ip_sans: Array of alternative names in IP format to add into the certificate Defaults to <code>[]</code>.
- ttl_days: Validity of the certificate in days Defaults to <code>365</code>.
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
  - `vaul_role` is the role in the pki backend to which requesting the certificate, must be of the form `<backend>/issue/<role>`

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

# License and Maintainer

Maintainer:: Sous Chefs (<help@sous-chefs.org>)

Source:: https://github.com/sous-chefs/vault_resources

Issues:: https://github.com/sous-chefs/vault_resources/issues

License:: MIT
