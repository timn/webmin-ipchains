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

if (! $access{'echains'}) { &error($text{'echain_err_acl'}) }

@ps=&parse_script();

if ($in{'chain'} eq "input" || $in{'chain'} eq "output" || $in{'chain'} eq "forward") {
 $sc=1;
 $dp=&find_arg_struct('-P', \@ps);
 foreach $l (@{$dp}) {
  $p=&find_arg('-P', $l);
  if ($p->{'value1'} eq $in{'chain'}) {
   $policy=$p->{'value2'};
  }
 }
 if (!$policy) { $policy="ACCEPT" }
}

$chains=&find_arg_struct('-N', \@ps);
$chainrules=&find_chain_struct($in{'chain'}, \@ps);

$chainname=$in{'chain'};
if ($chainname eq "output") {
 $chainname=$text{'output'};
} else {
 if ($chainname eq "input") {
  $chainname=$text{'input'};
 } else {
  if ($chainname eq "forward") {
   $chainname=$text{'forward'};
  }
 }
}


&header($text{'echain_title'}, undef, "echain", undef, undef, undef,
        "Written by<BR><A HREF=mailto:tim\@niemueller.de>Tim Niemueller</A><BR><A HREF=http://www.niemueller.de>Home://page</A>");

print "<BR><HR>";

print "<TABLE BORDER=2 CELLPADDING=2 CELLSPACING=0 $cb WIDTH=100%>\n<TR>",
      "<TD COLSPAN=12 $tb WIDTH=100%><B>$chainname</B></TD></TR>\n";
if ($sc) {
 print "<TR><TD COLSPAN=12 $cb><B>$text{'echain_standpol'}: </B>$policy (",
       "<A HREF=\"change_policy.cgi?chain=$in{'chain'}&policy=$policy\">$text{'echain_spchange'}</A>)</TD></TR>\n\n";
}
print "<TR><TD><B>$text{'echain_source'}</B></TD>";
print "<TD><B>$text{'echain_port'}</B></TD>";
print "<TD><B>$text{'echain_dest'}</B></TD>";
print "<TD><B>$text{'echain_port'}</B></TD>";
print "<TD><B>$text{'echain_proto'}</B></TD>";
print "<TD><B>$text{'echain_iface'}</B></TD>";
print "<TH><B>$text{'echain_syn'}</B></TD>";
print "<TH><B>$text{'echain_frag'}</B></TD>";
print "<TH><B>$text{'echain_log'}</B></TD>";
print "<TD><B>$text{'echain_tos'}</B></TD>";
## print "<TD ALIGN=center><B>$text{'echain_type'}</B></TD>";
print "<TD><B>$text{'echain_target'}</B></TD>";
print "<TD ALIGN=right><B>$text{'echain_action'}</B></TD></TR>\n";

for ( my $i=0; $i<@{$chainrules}; $i++) {
 local($l);
 $l=$chainrules->[$i];

 $line="";
 $tmp=&find_arg('-A', $l);
 $tmp && ($line=$tmp->{'line'});
 if ($line eq "") {
   $tmp=&find_arg('-I', $l);
   $tmp || &error($text{'echain_err_line'});
   $line=$tmp->{'line'};
 }

 $tmp=&find_arg('-s', $l);
 $source=($tmp->{'neg1'}) ? "<B>!</B> $tmp->{'value1'}" : $tmp->{'value1'};
 $source || ($source = "&nbsp;");
 $sport=($tmp->{'value2'}) ? ($tmp->{'neg2'}) ? "<B>!</B> $tmp->{'value2'}" : $tmp->{'value2'} : "&nbsp;";

 $tmp=&find_arg('-d', $l);
 $dest=($tmp->{'neg1'}) ? "<B>!</B> $tmp->{'value1'}" : $tmp->{'value1'};
 $dest || ($dest = "&nbsp;");

 $dport=($tmp->{'value2'}) ? ($tmp->{'neg2'}) ? "<B>!</B> $tmp->{'value2'}" : $tmp->{'value2'} : "&nbsp;";
 $tmp=&find_arg('-p', $l);

 $proto=($tmp->{'name'}) ? ($tmp->{'neg'}) ? "<B>!</B> $tmp->{'value'}" : $tmp->{'value'} : "<i>$text{'echain_any'}</i>";

 $protoplain=$tmp->{'value'};
 if ($protoplain eq "icmp") {
  $tmp=&find_arg('--icmptype', $l);
  $proto.=($tmp->{'name'}) ? " ($tmp->{'value'})" : "";
 }
 $tmp=&find_arg('-i', $l);
 $dev=($tmp->{'name'}) ? ($tmp->{'neg'}) ? "<B>!</B> $tmp->{'value'}" : $tmp->{'value'} : "&nbsp;";
 $tmp=&find_arg('-j', $l);
 $target=($tmp) ? "$tmp->{'value'}" : "&nbsp;";

 $tmp=&find_arg('-y', $l);
 $syn=($tmp->{'name'}) ? ($tmp->{'neg'}) ? "!" : "X" : "&nbsp;";

 $tmp=&find_arg('-f', $l);
 $frag=($tmp->{'name'}) ? ($tmp->{'neg'}) ? "!" : "X" : "&nbsp;";

 $tmp=&find_arg('-l', $l);
 $log=($tmp->{'name'}) ? "X" : "&nbsp;";

 $tmp=&find_arg('-t', $l);
 $tos=($tmp->{'name'}) ? "$tos{$tmp->{'value2'}}" : "&nbsp;";

 $writetype="";
 
# $tmp=&find_arg('-A', $l);
# $writetype.=($tmp->{'name'}) ? "A" : "";

# $tmp=&find_arg('-I', $l);
# $writetype.=($tmp->{'name'}) ? "I" : "";

 print "<TR $cb><TD>$source</TD>",
       "<TD $cb>$sport</TD>",
       "<TD $cb>$dest</TD>",
       "<TD $cb>$dport</TD>",
       "<TD $cb>$proto</TD>",
       "<TD $cb>$dev</TD>",
       "<TD $cb ALIGN=center><B>$syn</B></TD>",
       "<TD $cb ALIGN=center><B>$frag</B></TD>",
       "<TD $cb ALIGN=center><B>$log</B></TD>",
       "<TD $cb>$tos</TD>",
       "<TD $cb>$target</TD>",
       "<TD $cb ALIGN=right>",
       "<A HREF=\"edit_rule.cgi?chain=$in{'chain'}&rule=$line\">",
       "<IMG SRC=\"images/echain.edit.gif\" BORDER=0 ",
       "ALT=\"$text{'echain_edit'}\"></A> ",
       "<A HREF=\"delete_rule.cgi?chain=$in{'chain'}&rule=$line\">",
       "<IMG SRC=\"images/echain.delete.gif\" BORDER=0 ",
       "ALT=\"$text{'echain_delete'}\"></A> ",
       "<A HREF=\"clone_rule.cgi?chain=$in{'chain'}&rule=$line\">",
       "<IMG SRC=\"images/echain.clone.gif\" BORDER=0 ",
       "ALT=\"$text{'echain_clone'}\"></A> ",
       "<A HREF=\"edit_rule.cgi?chain=$in{'chain'}&rule=$line&mode=insert\">",
       "<IMG SRC=\"images/echain.insert.gif\" BORDER=0 ",
       "ALT=\"$text{'echain_insert'}\"></A> ",
       "<A HREF=\"move_rule.cgi?chain=$in{'chain'}&dir=up&rule=$line\">",
       "<IMG SRC=\"images/echain.up.gif\" BORDER=0 ",
       "ALT=\"$text{'echain_up'}\"></A> ",
       "<A HREF=\"move_rule.cgi?chain=$in{'chain'}&dir=down&rule=$line\">",
       "<IMG SRC=\"images/echain.down.gif\" BORDER=0 ",
       "ALT=\"$text{'echain_down'}\"></A>",
       "</TD></TR>\n";
}

if (!@{$chainrules}) {
 print "<TR><TD COLSPAN=13 $cb>$text{'echain_norules'}</TD></TR>";
}

print "</TABLE>\n";
print "S=$text{'echain_synbitdesc'}, F=$text{'echain_fragdesc'}, ",
      "L=$text{'echain_logdesc'},  TOS=$text{'echain_tosdesc'}<BR>\n";

if (!$sc) {
print "<FORM ACTION=\"delete_chain.cgi\" METHOD=post>\n",
      "<INPUT TYPE=hidden NAME=\"chain\" VALUE=\"$in{'chain'}\">\n",
      "<INPUT TYPE=submit NAME=\"delete\" VALUE=\"$text{'echain_delchain'}\"></FORM>";
}

print "<BR><BR>\n";
print "<A HREF=\"edit_rule.cgi?chain=$in{'chain'}\">$text{'echain_crule'}</A>\n";
print "<HR>\n";



&footer("", $text{'echain_return'});



### END of edit_chain.cgi ###.
