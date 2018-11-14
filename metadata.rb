name 'vault_resources'
source_url "https://github.com/Tensibai/#{name}"
issues_url "https://github.com/Tensibai/#{name}/issues"
maintainer 'Sous Chefs'
maintainer_email 'help@sous-chefs.org'
license 'MIT'
description 'Library of vault resources to handle secrets'
long_description 'Library of vault resources to handle secrets'
version '0.1.0'
chef_version '>= 12.14' if respond_to?(:chef_version)

%w( aix amazon centos fedora freebsd debian oracle mac_os_x redhat suse opensuse opensuseleap ubuntu windows zlinux ).each do |os|
  supports os
end

gem 'vault', '~>0.12'
