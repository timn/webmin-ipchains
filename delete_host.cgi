#!/usr/bin/perl
#
#    IPchains Firewalling Webmin Module
#    Copyright (C) 1999-2000 by Tim Niemueller
#
#    This program is free software; you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation; either version 2 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.

#    Created  : 30.10.1999


require "./ipchains-lib.pl";

if (! $access{'dhosts'}) { &error($text{'delhost_err_acl'}) }
if ($in{'host'} eq "") { &error($text{'delhost_err_nohost'}) }

$lines=&read_file_lines("$module_config_directory/hosts.db");
splice(@{$lines}, $in{'host'}, 1);
&flush_file_lines;

redirect("list_hosts.cgi");

### END of delete_host.cgi ###.