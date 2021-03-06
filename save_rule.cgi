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

#    Created  : 10.10.1999

require "./ipchains-lib.pl";

if (($in{'rule'} ne "") && ($in{'mode'} ne 'insert')) {
 if (! $access{'erules'}) { &error($text{'srule_err_acl2'}) }
} else {
 if (! $access{'crules'}) { &error($text{'srule_err_acl'}) }
}


if ($in{'chain'} eq "") { &error($text{'srule_err_nochain'}) }
if ((&indexof($in{'sport'}, &get_services_list()) >= 0) && $in{'proto'} !~ /^(tcp|udp)$/i) {
 &error($text{'srule_err_servport'});
}
if ((&indexof($in{'dport'}, &get_services_list()) >= 0) && $in{'proto'} !~ /^(tcp|udp)$/i) {
 &error($text{'srule_err_servport'});
}

if ($in{'syn'} && $in{'insyn'}) { &error($text{'srule_err_syn'}) }
if (($in{'syn'} || $in{'insyn'}) && ($in{'frag'} || $in{'infrag'})) { &error($text{'srule_err_synfrag'}) }
if (($in{'frag'} || $in{'infrag'}) && ($in{'dport'} || $in{'sport'})) { &error($text{'srule_err_fragport'}) }
if ($in{'frag'} && $in{'infrag'}) { &error($text{'srule_err_frag'}) }
if ($in{'target'} eq "port" && !$in{'redport'}) {
 &error($text{'srule_err_port'});
}
if ($in{'target'} eq "port") {
 $target="REDIRECT $in{'redport'}";
} else {
 $target=$in{'target'};
}
if ($in{'target'} eq $in{'chain'}) {
 &error($text{'srule_err_selfjump'});
}

if ($in{'target'} eq "MASQ") {
 @ps=&parse_script;
 $jumps=&find_jump_struct($in{'chain'}, \@ps);

 foreach $j (@{$jumps}) {
  local $tmp=undef;
  $tmp=&find_arg('-A', $j);
  $tmp || ($tmp=&find_arg('-I', $j));


  if ($tmp && ($tmp->{'value'} ne "forward") && ($tmp->{'value1'} ne "forward")) {
    &error(&error('srule_err_masqfw', ($tmp->{'value'}) ? $tmp->{'value'} : $tmp->{'value1'}));
  }
 }
 if (($in{'chain'} =~ /^input$/i) || ($in{'chain'} =~ /^output$/i)) {
    &error($text{'srule_err_masqinout'});
 }
}

if ((&indexof($in{'target'}, @policies) < 0) && ($in{'chain'} !~ /forward/i) && ($in{'target'} !~ /port/i)) {
 @ps=&parse_script;
 $chain=&find_chain_struct($in{'target'}, \@ps);

 foreach $l (@{$chain}) {
  $tmp=&find_arg('-j', $l);
  if ($tmp->{'value'} eq 'MASQ') {
    &error($text{'srule_err_masqjump'});
  }
 }
}



if ($in{'target'} eq "port" && $in{'chain'} ne "input") {
 &error($text{'srule_err_red'});
}

$lines=&read_file_lines($config{'scriptfile'});

$newline="$ipchains -A $in{'chain'}";

if ($in{'source'}) {
  $newline .= " -s";
  $newline .= ($in{'sneg'}) ? " !" : "";
  $newline .= " $in{'source'}";
  $newline .= ($in{'spneg'}) ? " !" : "";
  $newline .= " $in{'sport'}";
}
if ($in{'dest'}) {
  $newline .= " -d";
  $newline .= ($in{'dneg'}) ? " !" : "";
  $newline .= " $in{'dest'}";
  $newline .= ($in{'dpneg'}) ? " !" : "";
  $newline .= " $in{'dport'}";
}
if ($in{'proto'}) {
 $newline .= " -p";
 $newline .= ($in{'pneg'}) ? " !" : "";
 $newline .= " $in{'proto'}";
}

$newline .= (($in{'proto'} eq "icmp") && $in{'icmptype'}) ? " --icmp-type $in{'icmptype'}" : "";

if ($in{'dev'}) {
 $newline .= " -i";
 $newline .= ($in{'devneg'}) ? " !" : "";
 $newline .= " $in{'dev'}";
}

$newline .= ($in{'syn'}) ? " -y" : "";
$newline .= ($in{'insyn'}) ? " ! -y" : "";

$newline .= ($in{'frag'}) ? " -f" : "";
$newline .= ($in{'infrag'}) ? " ! -f" : "";

$newline .= ($in{'log'}) ? " -l" : "";

$newline .= ($in{'tos'} ne "0x00") ? " -t 0x01 $in{'tos'}" : "";

$newline .= ($target) ? " -j $target" : "";

if ($in{'mode'} eq 'edit') {
  # we are changing an existing rule
  $lines->[$in{'rule'}]=$newline;
} elsif ($in{'mode'} eq 'append') {
  # we are appending a new rule
   push(@{$lines}, $newline);
} elsif ($in{'mode'} eq 'insert') {
  # we are inserting a rule after current rule
  my @tmpl=($lines->[$in{'rule'}], $newline);
  splice(@{$lines}, $in{'rule'}, 1, @tmpl);
} else {
  &error($text{'srule_nomode'});
}

&flush_file_lines;


redirect("edit_chain.cgi?chain=$in{'chain'}");

### END of save_rule.cgi ###.
