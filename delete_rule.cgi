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

#    Created  : 10.10.1999

require "./ipchains-lib.pl";

if (! $access{'drules'}) { &error($text{'delrule_err_acl'}) }
if ($in{'rule'} eq "") { &error($text{'delrule_err_norule'}) }
if ($in{'chain'} eq "") { &error($text{'delrule_err_nochain'}) }

$lines=&read_file_lines($config{'scriptfile'});
splice(@{$lines}, $in{'rule'}, 1);
&flush_file_lines;

&redirect("edit_chain.cgi?chain=$in{'chain'}");

### END of delete_rule.cgi ###.