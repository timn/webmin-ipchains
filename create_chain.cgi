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
if (! $access{'cchains'}) { &error($text{'cchain_err_acl'}) }


if ($ENV{'REQUEST_METHOD'} eq "GET") {

  &header($text{'index_title'}, undef, "cchain", 1, 1, undef,
         "Written by<BR><A HREF=mailto:tim\@niemueller.de>Tim Niemueller</A>".
         "<BR><A HREF=http://www.niemueller.de>Home://page</A>");
  print "<HR><BR>\n";

print <<EOM;
<FORM ACTION="$ENV{'SCRIPT_NAME'}" METHOD=post>
<TABLE BORDER=1 CELLSPACING=0 CELLPADDING=2 $cb>
 <TR $tb>
  <TD><b>$text{'cchain_heading'}</b></TD>
 </TR>
 <TR $cb>
  <TD>
   <TABLE BORDER=0>
    <TR>
     <TD><B>$text{'cchain_name'}:</B></TD>
     <TD><INPUT TYPE=text NAME="chain" SIZE=20></TD>
     <TD ALIGN=right><INPUT TYPE=submit VALUE="$text{'cchain_createbut'}"></TD>
    </TR>
   </TABLE>
  </TD>
 </TR>
</TABLE>
</FORM>
<HR>
EOM

&footer("", $text{'cchain_return'});


} else {
  # POST method, so it should be a creation request

  $in{'chain'} || &error($text{'cchain_err_nochain'});

  @ps=&parse_script();
  $lines=&read_file_lines($config{'scriptfile'});
  $newline="$ipchains -N $in{'chain'}";
  &insert_line($newline, $lines, \@ps) || push(@{$lines}, $newline);
  &flush_file_lines;

  redirect("");

}

### END of create_chain.cgi ###.
