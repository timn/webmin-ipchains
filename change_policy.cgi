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

@ps=&parse_script();

if ($in{'chain'} eq "input" || $in{'chain'} eq "output" || $in{'chain'} eq "forward") {
 $sc=1;
 $dp=&find_arg_struct('-P', \@ps);
 foreach $l (@{$dp}) {
  $p=&find_arg('-P', $l);
  if ($p->{'value1'} eq $in{'chain'}) {
   $policy=$p->{'value2'};
   $line=$p->{'line'};
   last;
  }
 }
 if (!$policy) { $policy="ACCEPT" }
} else {
 &error($text{'changepol_err_builtin'});
}

@pols=("ACCEPT", "REJECT", "DENY", "MASQ", "RETURN");


&header($text{'changepol_title'}, undef, undef, 1, 1, undef,
        "Written by<BR><A HREF=mailto:tim\@niemueller.de>Tim Niemueller</A><BR><A HREF=http://www.niemueller.de>Home://page</A>");

print "<BR><HR>";

$header=&text('changepol_pol', $in{'chain'});

print <<EOM;
<FORM ACTION="save_policy.cgi" METHOD=post>
<INPUT TYPE=hidden NAME="chain" VALUE="$in{'chain'}">
<INPUT TYPE=hidden NAME="line" VALUE="$line">
<TABLE BORDER=2 CELLPADDING=2 CELLSPACING=0 $cb>
 <TR>
  <TD COLSPAN=2 $tb WIDTH=100%><B>$header</B></TD>
 </TR>
 <TR>
  <TD $cb><SELECT NAME="policy">
EOM

for $p (sort @pols) {
 print " <OPTION VALUE=\"$p\"", ($policy eq $p) ? " selected" : "", ">$p\n";
}

print <<EOM;
  </SELECT>
  </TD>
  <TD><INPUT TYPE=submit NAME="savepol" VALUE=" $text{'changepol_save'} "></TD>
 </TR>
</TABLE>
</FORM>
<BR><BR>
EOM

&footer("edit_chain.cgi?chain=$in{'chain'}", &text('changepol_return', $in{'chain'}));

### END of change_policy.cgi ###.