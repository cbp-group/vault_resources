file '/tmp/hi' do
  content 'pretend this is a service restart'
  action :nothing
end

vault_pki_root 'test-root' do
  type 'exported'
  destination_path Dir.tmpdir
  ttl_days 3650
  ou 'root'
  organization 'test org'
  vault_auth_credentials ['3VRLzAKbpU58Wgio1a5K8G1E']
  vault_client_options('address' => 'http://127.0.0.1:8200')
  vault_role 'test-root-pki'
end

vault_pki_intermediate 'test-intermediate' do
  signing_ca lazy {
    {
      'cert' => ::File.read("#{Dir.tmpdir}/test-root/certificate.pem"),
      'key' => ::File.read("#{Dir.tmpdir}/test-root/private_key.pem"),
      'passphrase' => nil
    }
  }
  ttl_days 365
  ou 'intermediate'
  organization 'test org'
  vault_auth_credentials ['3VRLzAKbpU58Wgio1a5K8G1E']
  vault_client_options('address' => 'http://127.0.0.1:8200')
  vault_role 'test-intermediate-pki'
end

vault_pki_role 'webserver' do
  allow_any_name true
  allow_ip_sans true
  vault_auth_credentials ['3VRLzAKbpU58Wgio1a5K8G1E']
  vault_pki 'test-intermediate-pki'
end

vault_certificate 'test.example.com' do
  certificate_path Dir.tmpdir
  alt_names ['test2.example.com', 'test3.example.com']
  ip_sans ['127.0.0.1', node['ipaddress']]
  ttl_days 90
  format 'pem_bundle'
  vault_auth_method 'token'
  vault_auth_credentials ['3VRLzAKbpU58Wgio1a5K8G1E']
  vault_client_options('address' => 'http://127.0.0.1:8200')
  vault_role 'test-intermediate-pki/issue/webserver'

  notifies :create, 'file[/tmp/hi]'
end
