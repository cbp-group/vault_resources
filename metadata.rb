name 'vault_resources'
source_url "https://github.com/Tensibai/#{name}"
issues_url "https://github.com/Tensibai/#{name}/issues"
maintainer 'DTD-Platforms'
maintainer_email 'dtd-plateformes@cbp-group.com'
license 'MIT'
description 'Library of vault resources to handle secrets and backends'
long_description <<-EOH
= DESCRIPTION:

Collection of resources to interact with an hashicorp's vault server
Those resource are used internally by CBP-Group for various use cases, including a Letsencrypt like generation of certificates for private AWS Application Load Balancers (ALB)

This cookbook has been created by DTD-Platforms, part of the DTD-Platform & Services departement handling CBP-Group infrastructure.

= REQUIREMENTS:

Used on windows and ubuntu platforms, should work on eveything compatible with Chef 13 and above
EOH
version '0.1.0'
chef_version '>= 13' if respond_to?(:chef_version)

%w( aix amazon centos fedora freebsd debian oracle mac_os_x redhat suse opensuse opensuseleap ubuntu windows zlinux ).each do |os|
  supports os
end

gem 'vault', '~>0.12'
