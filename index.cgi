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

#    Created  : 20.09.1999

#    Changes and To Do are now in the file CHANGES

require "./ipchains-lib.pl";

@ps=&parse_script();
$chains=&find_arg_struct('-N', \@ps);

 $dp=&find_arg_struct('-P', \@ps);
 foreach $l (@{$dp}) {
  $p=&find_arg('-P', $l);
  if ($p->{'value1'} =~ /input/i ) {
   $ipol=$p->{'value2'};
  } elsif ($p->{'value1'} =~ /output/i ) {
   $opol=$p->{'value2'};
  } elsif ($p->{'value1'} =~ /forward/i ) {
   $fpol=$p->{'value2'};
  }
 }
if (!$ipol) { $ipol="ACCEPT" }
if (!$opol) { $opol="ACCEPT" }
if (!$fpol) { $fpol="ACCEPT" }

foreach $l (@{$chains}) {
 $c=&find_arg('-N', $l);
 push(@images, "images/chain.other.gif");
 push(@texts, $c->{'value'});
 push(@links, "edit_chain.cgi?chain=$c->{'value'}");
}


&header($text{'index_title'}, undef, "intro", 1, 1, undef,
        "Written by<BR><A HREF=mailto:tim\@niemueller.de>Tim Niemueller</A><BR><A HREF=http://www.niemueller.de>Home://page</A>");


print <<EOM;
<BR><HR>
<H3>$text{'index_standard'}</H3>

<TABLE BORDER=0 WIDTH=100%>
 <TR>
  <TD ROWSPAN=2 ALIGN=right>
   <TABLE BORDER>
     <TR><TD><A HREF="edit_chain.cgi?chain=input"><IMG SRC="images/chain.input.gif" BORDER=0></A></TD></TR>
   </TABLE>
  </TD>
  <TD><A HREF="edit_chain.cgi?chain=input">$text{'input'}</A></TD>
  
  <TD ROWSPAN=2 ALIGN=right>
   <TABLE BORDER>
     <TR><TD><A HREF="edit_chain.cgi?chain=output"><IMG SRC="images/chain.output.gif" BORDER=0></A></TD></TR>
   </TABLE>
  </TD>
  <TD><A HREF="edit_chain.cgi?chain=output">$text{'output'}</A></TD>

  <TD ROWSPAN=2 ALIGN=right>
   <TABLE BORDER>
     <TR><TD><A HREF="edit_chain.cgi?chain=forward"><IMG SRC="images/chain.forward.gif" BORDER=0></A></TD></TR>
   </TABLE>
  </TD>
  <TD><A HREF="edit_chain.cgi?chain=forward">$text{'forward'}</A></TD>
 </TR>
 <TR>
  <TD>$text{'index_standpol'}: $ipol</TD>
  <TD>$text{'index_standpol'}: $opol</TD>
  <TD>$text{'index_standpol'}: $fpol</TD>
 </TR>
</TABLE>
<HR>

EOM

print "<H3>$text{'index_userdef'}</H3>";
if (!@links) { print "<B>$text{'index_noudef'}</B>" }
else { &icons_table(\@links, \@texts, \@images, 5) }
print "<HR>\n";

print <<EOM;

<TABLE BORDER=0 CELLSPACING=0 CELLPADDING=0 WIDTH=100%>
<TR><TD VALIGN=top ALIGN=left>

<TABLE BORDER=0 CELLSPACING=10>
 <TR>
  <TD VALIGN=top>

   <FORM ACTION=create_chain.cgi METHOD=post>
   <TABLE BORDER=1 CELLSPACING=0 CELLPADDING=2 $cb>
    <TR $tb>
     <TD><b>$text{'index_chaincreate'}</b></TD>
    </TR>
    <TR $cb>
     <TD>
     <TABLE BORDER=0>
      <TR>
       <TD><B>Name:</B></TD>
       <TD><INPUT TYPE=text NAME="chain" SIZE=20></TD>
       <TD ALIGN=right><INPUT TYPE=submit VALUE="$text{'index_createbut'}"></TD>
      </TR>
      </TABLE>
     </TD>
    </TR>
   </TABLE>
   </FORM>
  </TD>
  <TD VALIGN=top>

   <FORM ACTION=list_hosts.cgi METHOD=get>
   <TABLE BORDER=1 CELLSPACING=0 CELLPADDING=2 $cb>
    <TR $tb>
     <TH>$text{'index_list'}</TD>
    </TR>
    <TR $cb>
     <TD ALIGN=center>
     <TABLE BORDER=0>
      <TR>
       <TD ALIGN=center> <INPUT TYPE=submit VALUE="$text{'index_listbut'}"> </TD>
      </TR>
     </TABLE>
     </TD>
    </TR>
   </TABLE>
   </FORM>

  </TD>
  <TD VALIGN=top>

   <FORM ACTION=script_manager.cgi METHOD=get>
   <TABLE BORDER=1 CELLSPACING=0 CELLPADDING=2 $cb>
    <TR $tb>
     <TH>$text{'index_scripts'}</TD>
    </TR>
    <TR $cb>
     <TD ALIGN=center>
     <TABLE BORDER=0>
      <TR>
       <TD ALIGN=center> <INPUT TYPE=submit VALUE="$text{'index_scriptsman'}"></TD>
      </TR>
     </TABLE>
     </TD>
    </TR>
   </TABLE>
   </FORM>

  </TD>
 </TR>
</TABLE>

</TD>
<TD VALIGN=top ALIGN=right><FONT FACE="Arial,helvetica" COLOR="#505050">[ IPchains Firewalling $version ] </FONT></TD>
</TR></TABLE>

EOM

&footer("/", $text{'index_return'});



### END of index.cgi ###.