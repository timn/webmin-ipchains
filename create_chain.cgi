#!/usr/bin/perl
#
#    IPchains Firewalling Webmin Module
#    Copyright (C) 1999 by Tim Niemueller
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

#
# Created  : 10.10.1999
#


#######################
#    Configuration    #
#######################

require "./ipchains-lib.pl";

if (! $access{'cchains'}) { &error($text{'createchain_err_acl'}) }

if ($in{'chain'} eq "") { &error($text{'createchain_err_nochain'}) }

$lines=&read_file_lines($config{'scriptfile'});
$newline="$ipchains -N $in{'chain'}";
push(@{$lines}, $newline);
&flush_file_lines;

redirect("");

### END of create_chain.cgi ###.