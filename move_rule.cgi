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

#    Created  : 30.06.2000

require "./ipchains-lib.pl";

if (! $access{'erules'}) { &error($text{'mrule_err_acl'}) }
if ($in{'rule'} eq "") { &error($text{'mrule_err_norule'}) }
if ($in{'chain'} eq "") { &error($text{'mrule_err_nochain'}) }
if (($in{'dir'} ne "up") && ($in{'dir'} ne "down")) { &error($text{'mrule_err_invdir'}) }

@ps=&parse_script();
$chainrules=&find_chain_struct($in{'chain'}, \@ps);

for ( my $i=0; $i<@{$chainrules}; $i++) {

  $line="";

  $tmp=&find_arg('-A', $chainrules->[$i]);
  $tmp && ($line=$tmp->{'line'});
  ($line ne "") || &error(&text('mrule_err_line', 1));

  if ($i) {
  }

  if ($line eq $in{'rule'}) {
    $lines=&read_file_lines($config{'scriptfile'});

    if ($in{'dir'} eq "up") {
      # we move a rule up
      if ($i) {
        # We have a rule which is not already the first in chain
        # and move it

        $lastline="";
        $tmp=&find_arg('-A', $chainrules->[$i-1]);
        $tmp && ($lastline=$tmp->{'line'});
        ($lastline ne "") || &error(&text('mrule_err_line', 2));

        $temp = $lines->[$line];
        splice(@{$lines}, $line, 1, $lines->[$lastline]);
        splice(@{$lines}, $lastline, 1, $temp);
        
      } else {
        &error($text{'mrule_err_top'});
      }
    } else {
      # we move a rule down
      if ($i < scalar(@{$chainrules}-1)) {
        # we are moving down a rule which is not already the last one

        $nextline="";
        $tmp=&find_arg('-A', $chainrules->[$i+1]);
        $tmp && ($nextline=$tmp->{'line'});
        ($nextline ne "") || &error(&text('mrule_err_line', 3));

        $temp = $lines->[$line];
        splice(@{$lines}, $line, 1, $lines->[$nextline]);
        splice(@{$lines}, $nextline, 1, $temp);

      } else {
        &error($text{'mrule_err_last'});
      }
    }

    &flush_file_lines();
  }

}

&redirect("edit_chain.cgi?chain=$in{'chain'}");

### END of move_rule.cgi ###.