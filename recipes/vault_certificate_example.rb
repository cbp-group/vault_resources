file '/tmp/hi' do
  content 'pretend this is a service restart'
  action :nothing
end

vault_certificate 'test.example.com' do
  certificate_path '/tmp'
  alt_names ['test2.example.com', 'test3.example.com']
  ip_sans ['127.0.0.1', node['ipaddress']]
  ttl_days 30

  vault_auth_method 'token'
  vault_auth_credentials ['3VRLzAKbpU58Wgio1a5K8G1E']
  vault_client_options('address' => 'http://127.0.0.1:8200')
  vault_role 'pki/issue/webserver'

  notifies :create, 'file[/tmp/hi]'
end
