#
# = Class: iptables
#
# This class installs and manages iptables
#
#
# == Parameters
#
# Refer to https://github.com/stdmod for official documentation
# on the stdmod parameters used
#
# Module specific parameters
#
# [*my_class*]
#   Inlcude your own class when this class is invoked
#
# [*service_autorestart*]
#   Restart the iptables service when the configuration has changed.
#   Defaults to true
#
# [*log*]
#   Define what packets to log. Can be 'all', 'drop' or 'none'. Defaults to 'drop'
#
# [*log_prefix*]
#   The prefix to use for logged lines. Defaults to 'iptables'
#
# [*log_limit_burst*]
#   The iptables log limit-burst directive. Defaults to 10
#
# [*log_limit*]
#   The iptables log limit. Defaults to '30/m'
#
# [*log_level*]
#   The desired default iptables log level. Defaults to 4
#   numeric or see syslog.conf(5)
#
# [*rejectWithICMPProhibited*]
#   Reject using --reject-with icmp-host-prohibited. Defaults to true
#
# [*default_target*]
#   Default target to use when adding a rule. Defaults to 'ACCEPT'
#
# [*default_order*]
#   Default order parameter to use when adding a new route. Defaults to 5000.
#
# [*configure_ipv6_nat*]
#   Configure NAT chain with IPv6. False by default.
#   Rationale for this setting and default is that many older versions
#   of linux and netfilter/iptables don't support the NAT table with
#   IPv6
#
# [*enable_v4*]
#   Use this module with IPv4. Defaults to true.
#
# [*enable_v6*]
#   Use this module with IPv6. Defaults to false.
#
# [*failsafe_ssh*]
#   Bool. Insert a rule allowing iptables at all cost. This is to prevent accidental
#   lockouts when implementing this module. You may want to disable this, and add
#   the desired rules yourself (allowing to implement specific white- and blacklists,
#   as well as blocking bruteforce attacks).
#
# [*template*]
#   The template file to use when config=file
#
# [*mode*]
#   Define how you want to manage iptables configuration:
#   "file" - To provide iptables rules as a normal file
#   "concat" - To build them up using different fragments
#      - This option, set as default, permits the use of the iptables::rule define
#      - and many other funny things
#
# Default class params - As defined in iptables::params.
# Note that these variables are mostly defined and used in the module itself,
# overriding the default values might not affected all the involved components.
# Set and override them only if you know what you're doing.
# Note also that you can't override/set them via top scope variables.
#
# [*package*]
#   The package of the Iptables software.
#
# [*version*]
#   The package version, used in the ensure parameter of package type.
#   Default: present. Can be 'latest' or a specific version number.
#   Note that if the argument absent (see below) is set to true, the
#   package is removed, whatever the value of version parameter.
#
# [*service*]
#   The name of the Iptables service
#
# [*service_override_restart*]
#   To use the distro's built-in service to reload iptables
#
# [*service_status*]
#   If the standard42 service init script supports status argument
#
# [*service_status_cmd*]
#   Command to check if the iptables service is running
#
# [*config_file*]
#   The IPv4 config file
#
# [*config_file_v6*]
#   The IPv6 config file
#
# [*config_file_mode*]
#   Main configuration file path mode
#
# [*config_file_owner*]
#   Main configuration file path owner
#
# [*config_file_group*]
#   Main configuration file path group
#
# [*absent*]
#   Set to 'true' to remove package(s) installed by module
#   Can be defined also by the (top scope) variable $standard42_absent
#
# [*disable*]
#   Set to 'true' to disable service(s) managed by module
#
# [*disableboot*]
#   Set to 'true' to disable service(s) at boot, without checks if it's running
#   Use this when the service is managed by a tool like a cluster software
#
# [*debug*]
#   Set to 'true' to enable modules debugging
#
# [*audit_only*]
#   Set to 'true' if you don't intend to override existing configuration files
#   and want to audit the difference between existing files and the ones
#   managed by Puppet.
#
# == Examples
#
# Include it to install and manage Iptables
# It defines package, service, tables, chains, policies and rules.
#
# Usage:
#
# See README for details.
#
#
# == Author
#   Alessandro Franceschi <al@lab42.it/>
#   Dolf Schimmel - Freeaqingme <dolf@dolfschimmel.nl/>
#
class iptables (
  $ensure                        = 'present',
  $version                       = undef,
  
  $package_name                   = $iptables::params::package_name,

  $service_name                   = $iptables::params::service_name,
  $service_ensure                 = 'running',
  $service_enable                 = true,

  $config_file_path_v4            = $iptables::params::config_file_path_v4,
  $config_file_path_v6            = $iptables::params::config_file_path_v6,
  $config_file_replace            = true,
  $config_file_require            = 'Package[iptables]',
  $config_file_notify             = 'Service[iptables]',
  $config_file_source             = undef,
  $config_file_template           = undef,
  $config_file_content            = undef,
  $config_file_options_hash       = undef,
  $config_file_owner              = 'root',
  $config_file_group              = 'root',
  $config_file_mode               = '0640',

  $config_dir_path                = $iptables::params::config_dir_path,
  $config_dir_source              = undef,
  $config_dir_purge               = false,
  $config_dir_recurse             = true,

  $dependency_class               = undef,
  $my_class                       = undef,

# TODO?
#  $monitor_class                 = undef,
#  $monitor_options_hash          = { } ,

  $scope_hash_filter              = '(uptime.*|timestamp)',

# Module specific variables
  $log                            = 'dropped',
  $log_prefix                     = 'iptables',
  $log_limit_burst                = 10,
  $log_limit                      = '30/m',
  $log_level                      = 4,

  $rejectWithICMPProhibited       = true,
  $default_target                 = 'ACCEPT',
  $default_order                  = 5000,

  $enable_v4                      = $iptables::params::enable_v4,
  $enable_v6                      = $iptables::params::enable_v6,

  $failsafe_ssh                   = true,
  $configure_ipv6_nat             = $iptables::params::configure_ipv6_nat,

  $service_name_override_restart  = $iptables::params::service_override_restart,
  $service_name_status_cmd        = $iptables::params::service_status_cmd,
  ) inherits iptables::params {
    
  # Input parameters validation

  validate_re($ensure, ['present','absent'], 'Valid values: present, absent.')
  validate_bool($service_enable)
  validate_bool($config_dir_recurse)
  validate_bool($config_dir_purge)
  if $config_file_options_hash { validate_hash($config_file_options_hash) }
#  if $monitor_options_hash { validate_hash($monitor_options_hash) }
  validate_re($log, ['dropped','all','none',false], 'Valid values: dropped, all or none.')
#  validate_int($log_limit_burst)
  validate_string($log_limit)
#  validate_int($log_level)
  validate_bool($rejectWithICMPProhibited)
  validate_string($default_target)
#  validate_int($default_order)
  validate_bool($enable_v4)
  validate_bool($enable_v6)
  validate_bool($failsafe_ssh)
  validate_bool($configure_ipv6_nat)
  validate_bool($service_name_override_restart)
  validate_string($service_name_status_cmd)
  
   # Calculation of variables used in the module

  if $config_file_content {
    $manage_config_file_content = $config_file_content
  } else {
    if $config_file_template {
      $manage_config_file_content = template($config_file_template)
    } else {
      $manage_config_file_content = undef
    }
  }
  
  if $config_file_notify {
    $manage_config_file_notify = $config_file_notify
  } else {
    $manage_config_file_notify = undef
  }

  if $version {
    $manage_package_ensure = $version
  } else {
    $manage_package_ensure = $ensure
  }

  
  if $ensure == 'absent' {
    $manage_service_enable = undef
    $manage_service_ensure = stopped
    $config_dir_ensure = absent
    $config_file_ensure = absent
  } else {
    $manage_service_enable = $service_enable
    $manage_service_ensure = $service_ensure
    $config_dir_ensure = directory
    $config_file_ensure = present
  }
  
  if $config_file_ensure == 'present' and $enable_v4 {
    $config_file_ensure_v4 = 'present'
  } else {
    $config_file_ensure_v4 = 'absent'
  }

  if $config_file_ensure == 'present' and $enable_v6 {
    $config_file_ensure_v6 = 'present'
  } else {
    $config_file_ensure_v6 = 'absent'
  }

  $reject_string_v4 = any2bool($rejectWithICMPProhibited) ? {
    true    => 'REJECT --reject-with icmp-host-prohibited',
    false   => 'REJECT'
  }

  $reject_string_v6 = any2bool($rejectWithICMPProhibited) ? {
    true    => 'REJECT --reject-with icmp6-adm-prohibited',
    false   => 'REJECT'
  }
  
  $cmd_restart_v4 = inline_template('iptables-restore < <%= scope.lookupvar("iptables::config_file_path_v4") %>')
  $cmd_restart_v6 = inline_template('ip6tables-restore < <%= scope.lookupvar("iptables::config_file_path_v6") %>')

  if $enable_v4 and $enable_v6 {
    $cmd_restart  = "${cmd_restart_v4} && ${cmd_restart_v6}"
    $ifup_content = "#!/bin/sh\n${cmd_restart_v4}\n${cmd_restart_v6}\n"
  } elsif $enable_v4 {
    $cmd_restart = $cmd_restart_v4
    $ifup_content = "#!/bin/sh\n${cmd_restart_v4}\n"
  } else {
    $cmd_restart = $cmd_restart_v6
    $ifup_content = "#!/bin/sh\n${cmd_restart_v6}\n"
  }

  # Resources manage

  if $iptables::package_name {
    package { 'iptables':
      name     => $iptables::package_name,
      ensure   => $iptables::manage_package_ensure,
    }
  }

  if $iptables::service_name {

    $service_status = $::operatingsystem ? {
      /(?i:Debian|Ubuntu|Mint)/ => false,
      default                   => true,
    }

    $service_status_cmd = $::operatingsystem ? {if-
      /(?i:Debian|Ubuntu|Mint)/ => '/bin/true',
      default                   => undef,
    }

    service { 'iptables':
      name       => $service_name,
      ensure     => $iptables::manage_service_ensure,
      enable     => $iptables::manage_service_enable,
      hasstatus  => $iptables::service_status,
      status     => $iptables::service_status_cmd,
      hasrestart => false,
      restart    => $cmd_restart
    }
  }

  if $::operatingsystem =~ /(?i:Debian|Ubuntu|Mint)/ {
    file { '/etc/network/if-up.d/iptables':
      ensure  => present,
      owner   => root,
      group   => root,
      mode    => 0755,
      content => $ifup_content
    }
  }

  if $iptables::config_file_path_v4 {
    if $iptables::manage_config_file_content or $iptables::config_file_source {
      file { 'iptables_v4.conf':
        ensure  => $iptables::config_file_ensure_v4,
        path    => $iptables::config_file_path_v4,
        mode    => $iptables::config_file_mode,
        owner   => $iptables::config_file_owner,
        group   => $iptables::config_file_group,
        source  => $iptables::config_file_source,
        content => $iptables::manage_config_file_content,
        notify  => $iptables::manage_config_file_notify,
        require => $iptables::config_file_require,
      }
    } else {
      
      # No source specified. Lets generate it!
      iptables::conf { 'iptables::conf::v4':
        ip_version    => 4,
        path          => $iptables::config_file_path_v4,
        mode          => $iptables::config_file_mode,
        owner         => $iptables::config_file_owner,
        group         => $iptables::config_file_group,
        notify        => $iptables::manage_config_file_notify,
        require       => $iptables::config_file_require,
        replace       => $config_file_replace,
      }
      
    }
  }

  if $iptables::config_file_path_v6 {
    if $iptables::manage_config_file_content or $iptables::config_file_source {
    
      file { 'iptables_v6.conf':
        ensure  => $iptables::config_file_ensure_v6,
        path    => $iptables::config_file_path_v6,
        mode    => $iptables::config_file_mode,
        owner   => $iptables::config_file_owner,
        group   => $iptables::config_file_group,
        source  => $iptables::config_file_source,
        content => $iptables::manage_config_file_content,
        notify  => $iptables::manage_config_file_notify,
        require => $iptables::config_file_require,
      }
    
    } else {
      
      # No source specified. Lets generate it!
      iptables::conf { 'iptables::conf::v6':
        ip_version    => 6,
        path          => $iptables::config_file_path_v6,
        mode          => $iptables::config_file_mode,
        owner         => $iptables::config_file_owner,
        group         => $iptables::config_file_group,
        notify        => $iptables::manage_config_file_notify,
        require       => $iptables::config_file_require,
        replace       => $config_file_replace,
      }
      
    }
  }

  if $iptables::config_dir_source {
    file { 'iptables.dir':
      ensure  => $iptables::config_dir_ensure,
      path    => $iptables::config_dir_path,
      source  => $iptables::config_dir_source,
      recurse => $iptables::config_dir_recurse,
      purge   => $iptables::config_dir_purge,
      force   => $iptables::config_dir_purge,
      notify  => $iptables::config_file_notify,
      require => $iptables::config_file_require,
    }
  }

  file { [ '/var/lib/puppet/iptables',
           '/var/lib/puppet/iptables/tables/' ]:
    ensure  => $iptables::config_dir_ensure,
    mode    => $iptables::config_file_mode,
    owner   => $iptables::config_file_owner,
    group   => $iptables::config_file_group,
    recurse => true
  }

  include iptables::ruleset::default_action
  include iptables::ruleset::loopback
  include iptables::ruleset::invalid
  include iptables::ruleset::related_established

  if $failsafe_ssh {
    include iptables::ruleset::failsafe_ssh
  }

  if $iptables::dependency_class {
    include $iptables::dependency_class
  }

  if $iptables::my_class {
    include $iptables::my_class
  }

# Todo
#  if $iptables::monitor_class {
#    class { $iptables::monitor_class:
#      options_hash => $iptables::monitor_options_hash,
#      scope_hash   => {}, # TODO: Find a good way to inject class' scope
#    }
#  }

#  ### Debugging, if enabled ( debug => true )
#  if $iptables::bool_debug == true {
#    file { 'debug_iptables':
#      ensure  => $iptables::manage_file,
#      path    => "${settings::vardir}/debug-iptables",
#      mode    => '0640',
#      owner   => 'root',
#      group   => 'root',
#      content => inline_template('<%= scope.to_hash.reject { |k,v| k.to_s =~ /(uptime.*|path|timestamp|free|.*password.*|.*psk.*|.*key)/ }.to_yaml %>'),
#    }
#  }
}
