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

@ps=&parse_script;

if (($in{'rule'} ne "") && ($in{'mode'} ne 'insert')) {
  @lines=&read_script;
  $l=&parse_line($lines[$in{'rule'}]);
  if (!$l) { &error("No such rule found") }
  $chainrules=&find_chain_struct($in{'chain'}, \@ps);
}


if ($in{'rule'} ne "") {
  if ($in{'mode'} eq 'insert') {
    # Insert a rule
    $title=$text{'editrule_title_insert'};
    $desc=&text('editrule_desc_insert', $in{'rule'});
    $help="erule_insert";
  } else {
    # OK, edit an existing rule
    $title=$text{'editrule_title_edit'};
    $desc=&text('editrule_desc_edit', $in{'rule'});
    $help="erule_edit";
  }
} else {
  # Append new rule at end of file
  $title=$text{'editrule_title_create'};
  $desc=$text{'editrule_desc_create'};
  $help="erule_append";
}

&header($title, undef, $help, undef, undef, undef,
        "Written by<BR><A HREF=mailto:tim\@niemueller.de>Tim Niemueller</A>".
        "<BR><A HREF=http://www.niemueller.de>Home://page</A>");
print "<BR><HR>";


if (($in{'rule'} ne "") && ($in{'mode'} ne 'insert')) {
 $tmp=&find_arg('-s', $l);
 $line=$tmp->{'line'};
 $source=$tmp->{'value1'};
 if ($tmp->{'neg1'}) { $sneg=" checked" }
 $sport=$tmp->{'value2'};
 if ($tmp->{'neg2'}) { $spneg=" checked" }

 $tmp=&find_arg('-d', $l);
 $dest=$tmp->{'value1'};
 if ($tmp->{'neg1'}) { $dneg=" checked" }
 $dport=$tmp->{'value2'};
 if ($tmp->{'neg2'}) { $dpneg=" checked" }

 $tmp=&find_arg('-p', $l);
 $proto=$tmp->{'value'};
 if ($tmp->{'neg'}) { $pneg=" checked" }

 $tmp=&find_arg('-i', $l);
 $dev=$tmp->{'value'};
 if ($tmp->{'neg'}) { $devneg=" checked" }

 $tmp=&find_arg('-j', $l);
 $target=($tmp->{'name'}) ? "$tmp->{'value'}" : "&nbsp;";

 $tmp=&find_arg('--icmp-type', $l);
 if ($tmp->{'neg'}) { $icmptypeneg=" checked" }
 $icmptype=$tmp->{'value'};

 $tmp=&find_arg('-t', $l);
 $tos=$tmp->{'value2'};

 $tmp=&find_arg('-y', $l);
 if ($tmp->{'name'}) {
  if ($tmp->{'neg'}) {
   $insynneg=" CHECKED";
  } else {
   $synneg=" CHECKED";
  }
 }

 $tmp=&find_arg('-f', $l);
 if ($tmp->{'name'}) {
  if ($tmp->{'neg'}) {
   $infragneg=" CHECKED";
  } else {
   $fragneg=" CHECKED";
  }
 }

 $tmp=&find_arg('-l', $l);
 if ($tmp->{'name'}) {
  $log=" CHECKED";
 }


 $tmp=&find_arg('-t', $l);
 $tos=$tmp->{'value2'};
}

 $proto_select=&proto_select($proto);
 $dev_select=&get_iface_select($dev);

$shc=&host_chooser_button("source"); # Source Host Chooser
$dhc=&host_chooser_button("dest"); # Destination Host Chooser

print "<FORM ACTION=\"save_rule.cgi\" METHOD=post>";

if ($in{'rule'} ne "") {
  if ($in{'mode'} eq 'insert') {
    print "<INPUT TYPE=hidden NAME=mode VALUE=insert>";
  } else {
    print "<INPUT TYPE=hidden NAME=mode VALUE=edit>";
  }
} else {
  print "<INPUT TYPE=hidden NAME=mode VALUE=append>";
}

print <<EOM;
<INPUT TYPE=hidden NAME="chain" VALUE="$in{'chain'}">
<INPUT TYPE=hidden NAME="rule" VALUE="$in{'rule'}">
<TABLE BORDER=2 CELLPADDING=2 CELLSPACING=0 $cb>
 <TR>
  <TD COLSPAN=5 $tb WIDTH=100%><B>$desc</B></TD>
 </TR>
 <TR>
  <TH><B>$text{'editrule_source'}</B></TH>
  <TH><B>$text{'editrule_dest'}</B></TH>
  <TH><B>$text{'editrule_proto'}</B></TH>
  <TH><B>$text{'editrule_iface'}</B></TH>
  <TH><B>$text{'editrule_target'}</B></TH>
 </TR>
 <TR>
  <TD>$text{'editrule_hostnet'}:<BR><INPUT TYPE=checkbox NAME="sneg" VALUE=1$sneg><B>!</B>
                   <INPUT TYPE=text NAME="source" SIZE=15 VALUE="$source"> $shc</TD>
  <TD>$text{'editrule_hostnet'}:<BR><INPUT TYPE=checkbox NAME="dneg" VALUE=1$dneg><B>!</B>
                   <INPUT TYPE=text NAME="dest" SIZE=15 VALUE="$dest"> $dhc</TD>
  <TD><INPUT TYPE=checkbox NAME="pneg" VALUE=1$pneg><B>!</B> $proto_select</TD>
  <TD><INPUT TYPE=checkbox NAME="devneg" VALUE=1$devneg><B>!</B> $dev_select</TD>
  <TD><SELECT NAME="target">
EOM

 $chains=&find_arg_struct('-N', \@ps);

 $redport="";
 if ($target ne "&nbsp;" && ! &chainindexof($target, $chains) &&
                            &indexof($target, @basechains)<0 &&
                            &indexof($target, @policies)<0) {
  $redport=$target;
 }

 print "<OPTION VALUE=\"\"", ($target eq "&nbsp;") ? " selected" : "", ">$text{'editrule_nojump'}\n";
 print "<OPTION VALUE=\"port\"", ($redport) ? " selected" : "", ">$text{'editrule_port'}:\n";
 print "<OPTION VALUE=\"ACCEPT\"", ($target eq "ACCEPT") ? " selected" : "", ">ACCEPT\n";
 print "<OPTION VALUE=\"DENY\"", ($target eq "DENY") ? " selected" : "", ">DENY\n";
 print "<OPTION VALUE=\"MASQ\"", ($target eq "MASQ") ? " selected" : "", ">MASQ\n";
 print "<OPTION VALUE=\"REJECT\"", ($target eq "REJECT") ? " selected" : "", ">REJECT\n";
 print "<OPTION VALUE=\"RETURN\"", ($target eq "RETURN") ? " selected" : "", ">RETURN\n";

 foreach $ch (sort @{$chains}) {
  $c=&find_arg('-N', $ch);
  print "<OPTION VALUE=\"$c->{'value'}\"", ($c && ($c->{'value'} eq $target)) ? " SELECTED" : "", ">$c->{'value'}\n";
 }

 $icmptype_select=&icmptype_select($icmptype);
 $tos_select=&tos_select($tos);

 $spc=&service_chooser_button("sport");
 $dpc=&service_chooser_button("dport");

print <<EOM;
  </SELECT>
  </TD>
 </TR>
 <TR>
  <TD>$text{'editrule_port'}<BR><INPUT TYPE=checkbox NAME="spneg" VALUE=1$spneg><B>!</B>
              <INPUT TYPE=text NAME="sport" SIZE=10 VALUE="$sport"> $spc</TD>
  <TD>$text{'editrule_port'}<BR><INPUT TYPE=checkbox NAME="dpneg" VALUE=1$dpneg><B>!</B>
              <INPUT TYPE=text NAME="dport" SIZE=10 VALUE="$dport"> $dpc</TD>
  <TD>$text{'editrule_icmptype'}<BR>$icmptype_select</TD>
  <TD><CENTER><B>$text{'editrule_tos'}</B></CENTER>$tos_select</TD>
  <TD>$text{'editrule_port'}<BR><INPUT TYPE=text NAME="redport" SIZE=10 VALUE="$redport"></TD>
 </TR>
 <TR>
  <TD><B>$text{'editrule_flags'}</B></TD>
  <TD><INPUT TYPE=checkbox NAME="syn" VALUE=1$synneg> $text{'editrule_syn'}<BR>
      <INPUT TYPE=checkbox NAME="insyn" VALUE=1$insynneg> $text{'editrule_insyn'}
  </TD>
  <TD><INPUT TYPE=checkbox NAME="frag" VALUE=1$fragneg> $text{'editrule_frag'}<BR>
      <INPUT TYPE=checkbox NAME="infrag" VALUE=1$infragneg> $text{'editrule_infrag'}
  </TD>
  <TD VALIGN=top><INPUT TYPE=checkbox NAME="log" VALUE=1$log> $text{'editrule_log'}</TD>
  <TD ALIGN=center><INPUT TYPE=reset VALUE=" $text{'editrule_reset'} "></TD>
 </TR>
</TABLE>
EOM

if ($in{'rule'} ne "") {
  if ($in{'mode'} eq 'insert') {
    print "<INPUT TYPE=submit NAME=\"insert\" VALUE=\"",
          " $text{'editrule_insert'} \">\n";
  } else {
    print "<INPUT TYPE=submit NAME=\"save\" VALUE=\"",
    " $text{'editrule_save'}\">\n";
  }
} else {
  print "<INPUT TYPE=submit NAME=\"append\" VALUE=\"",
        " $text{'editrule_append'} \">\n";
}


print "</FORM><BR><HR>\n";



&footer("./edit_chain.cgi?chain=$in{'chain'}", &text('editrule_return', $in{'chain'}));



### END of edit_rule.cgi ###.
