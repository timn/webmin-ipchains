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

#    Created  : 10.03.2000

require "./ipchains-lib.pl";

if (! $access{'crules'}) { &error($text{'srule_err_acl'}) }

if ($in{'rule'} eq "") { &error($text{'clonerule_err_norule'}) }
if ($in{'chain'} eq "") { &error($text{'clonerule_err_nochain'}) }

$lines=&read_file_lines($config{'scriptfile'});
my @tmpl=($lines->[$in{'rule'}], $lines->[$in{'rule'}]);
splice(@{$lines}, $in{'rule'}, 1, @tmpl);
&flush_file_lines;

redirect("edit_chain.cgi?chain=$in{'chain'}");

### END of clone_rule.cgi ###.
