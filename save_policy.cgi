#!/usr/bin/perl
#
#    IPchains Firewalling Webmin Module
#    Copyright (C) 1999-2000 by Tim Niemueller <tim@niemueller.de>
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


if ($in{'chain'} eq "") { &error($text{'savepol_err_nochain'}) }
if ($in{'policy'} eq "MASQ" && $in{'chain'} ne "forward") {
 &error($text{'savepol_err_masq'});
}

@ps=&parse_script;
$pols=&find_arg_struct('-P', \@ps);

foreach $l (@{$pols}) {
 $c=&find_arg('-P', $l);
  if ($c->{'value1'} eq $in{'chain'}) {
   $line=$c->{'line'};
  }
}

$lines=&read_file_lines($config{'scriptfile'});

$newline="$ipchains -P $in{'chain'} $in{'policy'}";

if ($in{'line'}) {
 # we are changing an existing rule
 $lines->[$line]=$newline;
} else {
 # we are creating a new rule
 &insert_line($newline, $lines, \@ps) || push(@{$lines}, $newline);
}

&flush_file_lines;

redirect("edit_chain.cgi?chain=$in{'chain'}");

### END of save_policy.cgi ###.
