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

#    Created  : 29.08.2000

require "./ipchains-lib.pl";
$DESC=1;

my %miniserv;
&get_miniserv_config(\%miniserv);

if (! -f "$miniserv{'root'}/$module_name/templates/$in{'ruleset'}") {
  &error($text{'desc_err_notfound'});
}

(my $name, my $type) = split(/-/, $in{'ruleset'});
$name =~ s/\./-/g;

&header("Ruleset Description - $name");
print "<H3>$name (", $text{"index_$type"}, ")</H3>\n";
print "<HR><BR>\n";

print "<H3>$text{'desc_heading'}</H3>\n";

my @rules = ();
open(RULESET, "$miniserv{'root'}/$module_name/templates/$in{'ruleset'}");
  while (<RULESET>)
  {
    chomp;
    if (/^##-> (.+)+/) {
      print $1;
    } else {
      push(@rules, &fill_tokens($_));
    }
  }
close(RULESET);

print "<BR><BR><BR><H3>$text{'desc_rules'}</H3>\n";
print join("<BR>\n", @rules);


print "<BR><BR><BR><HR>\n";
print "<FORM><INPUT TYPE=button onClick='top.close(); return false' VALUE=$text{'desc_close'}></FORM>";



### END of desc.cgi ###.
