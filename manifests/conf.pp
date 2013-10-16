#
# = Define: iptables::conf
#
# With this define you can manage any iptables configuration file
#
# == Parameters
#
# [*template*]
#   String. Optional. Default: undef. Alternative to: source, content.
#   Sets the module path of a custom template to use as content of
#   the config file
#   When defined, config file has: content => content($template),
#   Example: template => 'site/iptables/my.conf.erb',
#
# [*content*]
#   String. Optional. Default: undef. Alternative to: template, source.
#   Sets directly the value of the file's content parameter
#   When defined, config file has: content => $content,
#   Example: content => "# File manage by Puppet \n",
#
# [*source*]
#   String. Optional. Default: undef. Alternative to: template, content.
#   Sets the value of the file's source parameter
#   When defined, config file has: source => $source,
#   Example: source => 'puppet:///site/iptables/my.conf',
#
# [*ensure*]
#   String. Default: present
#   Manages config file presence. Possible values:
#   * 'present' - Create and manages the file.
#   * 'absent' - Remove the file.
#
# [*path*]
#   String. Optional. Default: $config_dir/$title
#   The path of the created config file. If not defined a file
#   name like the  the name of the title a custom template to use as content of configfile
#   If defined, configfile file has: content => content("$template")
#
define iptables::conf (

  $ip_version,

  $path         = undef,
  $mode         = undef,
  $owner        = undef,
  $group        = undef,
  $notify       = undef,
  $require      = undef,
  $replace      = undef,

  $ensure       = present
  
) {

  # Input parameters validation

  validate_re($ensure, ['present','absent'], 'Valid values are: present, absent. WARNING: If set to absent the conf file is removed.')
  validate_int($ip_version)

  include iptables
  include concat::setup


  # Calculation of variables used in the module

  $manage_path = $path ? {
    undef   => "${iptables::config_dir_path}/${name}",
    default => $path,
  }

  $manage_content = $content ? {
    undef   => $template ? {
      undef => undef,
      default => template($template),
    },
    default => $content,
  }

  $manage_mode = $mode ? {
    undef   => $iptables::config_file_mode,
    default => $mode,
  }

  $manage_owner = $owner ? {
    undef   => $iptables::config_file_owner,
    default => $owner,
  }

  $manage_group = $group ? {
    undef   => $iptables::config_file_group,
    default => $group,
  }

  $manage_require = $require ? {
    undef   => $iptables::config_file_require,
    default => $require,
  }

  $manage_notify = $notify ? {
    undef   => $iptables::manage_config_file_notify,
    default => $notify,
  }

  $manage_replace = $replace ? {
    undef   => $iptables::config_file_replace,
    default => $replace,
  }

  # Resources manage

  concat { $manage_path:
    owner   => $manage_owner,
    group   => $manage_group,
    mode    => $manage_mode,
    replace => $manage_replace,
    notify  => $manage_notify,
  }

  # The File Header. With Puppet comment
  concat::fragment { "iptables_header_$name":
    target  => $manage_path,
    content => "# File Managed by Puppet\n",
    order   => 01,
    notify  => Service['iptables'],
  }

  iptables::table { "v${ip_version}_filter":
    emitter_target => $manage_path,
    order          => 05,
    table_name     => 'filter',
    ip_version     => $ip_version,
    chains         => [ 'INPUT', 'FORWARD', 'OUTPUT' ]
  }

  if ! $ip_version == 4 or $iptables::configure_ipv6_nat {
    # Linux did not use to support NAT on IPv6. You'll have to declare thse
    # items yourself explicitly if your kernel and Netfilter does support this.
    # Feel free to write (and contribute back!) a mechanism that actually
    # does support this. Thank you! ;-)

    # See https://github.com/example42/puppet-iptables/issues/35
    # for why there's currently no INPUT chain in the nat table
    iptables::table { "v${ip_version}_nat":
      emitter_target => $manage_path,
      order          => 45,
      table_name     => 'nat',
      ip_version     => $ip_version,
      chains         => [ 'PREROUTING', 'OUTPUT', 'POSTROUTING' ]
    }
  }

  iptables::table { "v${ip_version}_mangle":
    emitter_target => $manage_path,
    order          => 65,
    table_name     => 'mangle',
    ip_version     => $ip_version,
    chains         => [ 'PREROUTING', 'INPUT', 'FORWARD', 'OUTPUT', 'POSTROUTING' ]
  }

  iptables::table { "v${ip_version}_raw":
    emitter_target => $manage_path,
    order          => 65,
    table_name     => 'raw',
    ip_version     => $ip_version,
    chains         => [ 'PREROUTING', 'OUTPUT' ]
  }

}
