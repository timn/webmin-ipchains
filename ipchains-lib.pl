#
#    IPchains Firewalling Webmin Module Library
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

#    Created  : 20.09.1999

do '../web-lib.pl';
$|=1;


&init_config("ipchains");
%access=&get_module_acl;
$cl=$text{'config_link'};
$version="0.80.3";

$ipchains=($config{'ipchains_path'}) ? $config{'ipchains_path'} : "/sbin/ipchains";

if (!-e "/proc/net/ip_fwchains") { &error($text{'lib_err_nosupport'}) }
if (!-e "/proc/net/ip_fwnames") { &error($text{'lib_err_nosupport'}) }
if (!-x $ipchains) { &error(&text('lib_err_ipchains', $ipchains, $cl)) }
if (! $config{'scriptfile'}) { &error(&text('lib_err_sfcm', $cl)) }

if ((!-e "$config{'scriptfile'}") && ($ENV{'SCRIPT_NAME'} ne "/ipchains/script_manager.cgi")) {
  &error(&text('lib_err_sfmiss', $config{'scriptfile'}, $cl));
}

# Argument with 0, 1 or 2 following words (! is not a word)
@aw0=("-1", "-y", "-f", "-b", "-l");
@aw1=("-N", "-X", "-F", "-j", "-m", "-p", "-i", "-A", "-I", "--icmp-type");
@aw2=("-D", "-R", "-P", "-d", "-s", "-t");

%tos=("0x00" => "Not Set",
      "0x10" => "Minimum Delay",
      "0x08" => "Minimum Throughput",
      "0x04" => "Maximum Reliability",
      "0x02" => "Minimum Cost");

@basechains=("input", "output", "forward");
@policies=("ACCEPT", "DENY", "MASQ", "REJECT", "RETURN");

ReadParse();


sub tos_select {
 local($rv, $sel);
 $sel=$_[0];

 $rv="<SELECT NAME=\"tos\">\n";

 for (sort keys %tos) {
  $rv.= "<OPTION VALUE=\"$_\"";
  $rv.= ($_ eq $sel) ? " SELECTED" : "";
  $rv.= ">$tos{$_}\n";
 }
 $rv.="</SELECT>\n";

return $rv;
}


sub get_icmptype_list {
 local(@rv, $i);
 open (CHILD, "$ipchains -h icmp |");
  while (<CHILD>) {
   push(@rv, $_);
  }
 close(CHILD);

 for (my $i=0; $i<@rv; $i++) {
  if ($rv[$i] =~ /\(/) {
   $rv[$i] = substr($rv[$i], 0, index($rv[$i], '(')-1);
  }
 }

 while ($rv[0] !~ /Valid ICMP Types/) {
  splice(@rv, 0, 1);
 }
 splice(@rv, 0, 1);

return @rv;
}


sub icmptype_select {
 local($rv, @icmpt, $i, $sel);
 $sel=$_[0];

 $rv="<SELECT NAME=\"icmptype\">\n";
 $rv.="<OPTION VALUE=0>$text{'lib_icmptsel'}\n";
 @icmpt=&get_icmptype_list();
 foreach $i (@icmpt) {
  chomp($i);
  $i =~ s/ //g;
  $rv.= "<OPTION VALUE=\"$i\"";
  $rv.= ($i eq $sel) ? " SELECTED" : "";
  $rv.= ">$i\n";
 }
 $rv.="</SELECT>\n";

return $rv;
}

sub get_proto_list {
 local($file, @rv, $l, @lines);
 $file = ($config{'proto_file'}) ? $config{'proto_file'} : "/etc/protocols";
 
 (-e $file) || &error(&text('lib_err_protomis', $cl));
 
 open(PROTO, $file);
  @lines=<PROTO>;
 close(PROTO);
 @lines = grep(!/^#/, @lines);

 foreach $l (@lines) {
  local(@proto);
   $l =~ s/\t/ /g;
   $l =~ s/ {2,}/ /g;  
   chomp $l;
   next if (!$l);
   @proto=split(/ /, $l);
   push(@rv, $proto[0]);
 }

return sort @rv; 
}

sub proto_select {
 local(@proto, $p, $rv, $sel);
 $sel=$_[0];

 $rv="<SELECT NAME=\"proto\">\n";
 $rv.="<OPTION VALUE=0>Any\n";
 @proto=&get_proto_list();
 foreach $p (@proto) {
  $rv.= "<OPTION VALUE=\"$p\"";
  $rv.= ($p eq $sel) ? " SELECTED" : "";
  $rv.= ">$p\n";
 }
 $rv.="</SELECT>\n";

return $rv;
}

sub get_iface_select {
 local(@act, $rv, $a, $sel);
 $sel=$_[0];

 $rv="<SELECT NAME=\"dev\">\n";
 $rv.="<OPTION VALUE=\"\">Any Device\n";



 if (!$config{'netifaces'}) {
  # we use the network configuration module for getting
  # all interfaces

  &foreign_check('net') || &error($text{'lib_err_netmod'});
  &foreign_require('net', 'net-lib.pl');
  @act = &foreign_call('net', 'active_interfaces');
  @act = sort { "$a->{'name'}:$a->{'virtual'}" cmp
                "$b->{'name'}:$b->{'virtual'}" } @act;
  $rv="<SELECT NAME=\"dev\">\n";
  $rv.="<OPTION VALUE=\"\">Any Device\n";
 
  foreach $a (@act) {
   $rv.="<OPTION VALUE=\"$a->{'fullname'}\"";
   $rv.=($a->{'fullname'} eq $sel) ? " SELECTED" : "";
   $rv.=">$a->{'fullname'}\n";
  }
 } else {
  # we parse the interfaces from the entered list
  $a=$config{'netifaces'};
  $a=~tr/\s+//;
  @act=split(/,/, $a);
  foreach $a (@act) {
   $rv.="<OPTION VALUE=\"$a\"";
   $rv.=($a eq $sel) ? " SELECTED" : "";
   $rv.=">$a\n";
  }
 }

 $rv.="</SELECT>\n";

return $rv;
}


sub read_script {
 open(SCRIPT, $config{'scriptfile'});
  @lines=<SCRIPT>;
 close SCRIPT;
# @lines = grep(!/^#/, @lines);
return @lines;
}


sub parse_line {
  local($line, @parsedparams, $p, $tmpstr, $n);

  $tmpstr=$_[0];
  $n=$_[1];

  chomp($tmpstr);
  $tmpstr =~ s/\t/ /g;       # Convert tabs to spaces
  $tmpstr =~ s/[ ]{2,}/ /g;  # Convert multi-spaces to singel-spaces

  @params=split(/ /, $tmpstr);

  for ($i=0; $i<@aw0; $i++) {
   $line=&find_param_0($aw0[$i], \@params, $n);
   if ($line->{'name'}) {
    push(@parsedparams, $line);
   }
  }
  for ($i=0; $i<@aw1; $i++) {
   $line=&find_param_1($aw1[$i], \@params, $n);
   if ($line->{'name'}) {
    push(@parsedparams, $line);
   }
  }
  for ($i=0; $i<@aw2; $i++) {
   $line=&find_param_2($aw2[$i], \@params, $n);
   if ($line->{'name'}) {
    push(@parsedparams, $line);
   }
  }

return \@parsedparams;
}

sub parse_script {
 local(@lines, @rv, $tmpstr, $i) ;
 
 @lines=&read_script;
 
 for (my $n=0; $n<@lines; $n++) {
  $tmpstr=@lines[$n];
  next if ($tmpstr =~ /^#/);
  push(@rv, &parse_line($tmpstr, $n));
 }

return @rv;
}


# Find Parameters with 0 arguments
sub find_param_0 {
 local($param, $params, %rv);
 $param=$_[0];
 $params=$_[1];

 if (&indexof($param, @{$params}) >= 0) {
  $m=&indexof($param, @{$params});
  $rv{'name'}=$params->[$m];
  $rv{'type'}=0;
  $rv{'line'}=$_[2];
  if ($params->[$m-1] eq "!") {
   $rv{'neg'}=1;
  } else {
   $rv{'neg'}=0;
  }
 } else {
  %rv=();
 }
 
return \%rv;
}

sub find_param_1 {
 local($param, $params, %rv);
 $param=$_[0];
 $params=$_[1];

 if (&indexof($param, @{$params}) >= 0) {
  $m=&indexof($param, @{$params});
  $rv{'name'}=$params->[$m];
  $rv{'type'}=1;
  $rv{'line'}=$_[2];
  if ($params->[$m+1] eq "!") {
   $rv{'neg'}=1;
   $rv{'value'}=$params->[$m+2];
  } elsif ($params->[$m] eq "-j" && $params->[$m+1] eq "REDIRECT") {
    # Workaround for problem with PORT redirects on -j
    $rv{'value'}=$params->[$m+2];
  } else {
   $rv{'neg'}=0;
   $rv{'value'}=$params->[$m+1];
  }
 } else {
  %rv=();
 }
return \%rv;
}

sub find_param_2 {
 local($param, $params, %rv, $line);
 $param=$_[0];
 $params=$_[1];
 $line=$_[2];

 if (&indexof($param, @{$params}) >= 0) {
  $m=&indexof($param, @{$params});
  $rv{'name'}=$params->[$m];
  $rv{'type'}=2;
  $rv{'line'}=$_[2];
  if ($params->[$m+1] eq "!") {

   if ($params->[$m+2] =~ /^-/) { &error(&text('lib_err_syn', "1", $line)) }
   $rv{'neg1'}=1;
   $rv{'value1'}=$params->[$m+2];

   if (($params->[$m+3] eq "!") && ($params->[$m+4] !~ /^-/)) {
    if ($params->[$m+4] =~ /^-/) { &error(&text('lib_err_syn', "2", $line)) }
    $rv{'neg2'}=1;
    $rv{'value2'}=$params->[$m+4];
   } else {
    if (($params->[$m+3] =~ /^-/) && ($param ne "-s") && ($param ne "-d")) { &error(&text('lib_err_syn', "3", $line)) }
    $rv{'neg2'}=0;
    if (($params->[$m+3] =~ /^-/) || ($params->[$m+2] =~ /^!/)) { $rv{'value2'}=undef }
    else { $rv{'value2'}=$params->[$m+3] }
   }

  } else {

   $rv{'neg'}=0;
   $rv{'value1'}=$params->[$m+1];
   # next lines checks if the second argument is negated and if so check, if this
   # ! negation is really for the next argument or for the next line argument
   # example: -s 192.168.1.0/32 ! -y would not be our problem, because -y is
   # not the negated second value but the negated next line argument
   if (($params->[$m+2] eq "!") && ($params->[$m+3] !~ /^-/)) {
    $rv{'neg2'}=1;
    if (($params->[$m+3] =~ /^-/)) { &error(&text('lib_err_syn', "4", $line)) }
    $rv{'value2'}=$params->[$m+3];
   } else {
    $rv{'neg2'}=0;
    if ($params->[$m+2] =~ /^-/ && ($param ne "-s") && ($param ne "-d")) { &error(&text('lib_err_syn', "5", $line)) }
     if (($params->[$m+2] =~ /^-/) || ($params->[$m+2] =~ /^!/)) { $rv{'value2'}=undef }
     else { $rv{'value2'}=$params->[$m+2] }
   }
  }
 } else {
  %rv=();
 }
return \%rv;
}


# find_arg_struct(arg, &lines)
# Returns the reference to an array containing all lines including
# the argument arg
sub find_arg_struct {
 local(@lines, $arg, @rv, $l, $a);
 $arg=$_[0];
 @lines=@{$_[1]};

 foreach $l (@lines) {
  foreach $a (@{$l}) {
   if ($a->{'name'} eq $arg) {
    push(@rv, $l);
   }
  }
 }
return \@rv;
}

# find_arg(arg, &line)
# Returns the reference to a hash containing the argument arg
# from line &line
sub find_arg {
 local($line, $arg, $a, $rv);
 $arg=$_[0];
 $line=$_[1];

 foreach $a (@{$line}) {
  if ($a->{'name'} eq $arg) {
   $rv = $a;
  }
 }
if ($rv->{'name'}) { return $rv } else { return undef }
}

# find_chain_struct(chain, &parsedscript)
# Returns the reference to a hash containing the argument arg
# from line &line
sub find_chain_struct {
 local(@ps, $chain, @rv, $l);
 $chain=$_[0];
 @ps=@{$_[1]};

 foreach $ln (@ps) {
  local($a);
  $a = &find_arg('-A', $ln);
  if ($a) {
   if ($a->{'value'} eq $chain) {
    push(@rv, $ln);
   }
  } else {
   $a = &find_arg('-I', $ln);
   if ($a) {
    if ($a->{'value1'} eq $chain) {
     push(@rv, $ln);
    }
   }
  }
 }

return \@rv;
}


sub chainindexof {
 local($chain, $chains, $c);
 
 $chain=$_[0];
 $chains=$_[1];

 foreach $c (@{$chains}) {
  local $tmp=undef;
  $tmp=&find_arg('-N', $c);
  next if (!$tmp);
  if ($tmp->{'value'} eq $chain) { return 1 }
 }
return 0;
}

# find_jump_struct(chain, &parsedscript)
# Returns the reference to an array containing the lines
# with jump target chain
sub find_jump_struct {
 local($ps, $chain, @rv, $l, $jumps);
 $chain=$_[0];
 $ps=$_[1];

 $jumps=&find_arg_struct('-j', $ps);
 foreach $l (@{$jumps}) {
  local($c);
  $c=&find_arg('-j', $l);
  if ($c->{'value'} eq $chain) {
   push(@rv, $l);
  }
 }

if (@rv) { return \@rv } else { return undef }
}

# rm_jump(&line)
# Removes any jump argument from the line
sub rm_jump {
 local($l, $tmp, $chain, $source,
       $sport, $dest, $dport, $proto,
       $dev, $newline, $sneg, $spneg,
       $dneg, $dpneg, $pneg, $devneg);
 $l=$_[0];

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

 $tmp=&find_arg('-t', $l);
 $tos=$tmp->{'value2'};

 $tmp=&find_arg('-A', $l);
 if ($tmp->{'name'}) {
  $newline="$ipchains -A $tmp->{'value'}";
 }
 $tmp=&find_arg('-I', $l);
 if ($tmp->{'name'}) {
  $newline="$ipchains -I $tmp->{'value'}";
 }

$newline .= " -s";
$newline .= ($sneg) ? " !" : "";
$newline .= " $source";
$newline .= ($spneg) ? " !" : "";
$newline .= " $sport";
$newline .= " -d ";
$newline .= ($dneg) ? " !" : "";
$newline .= " $dest";
$newline .= ($dpneg) ? " !" : "";
$newline .= " $dport";
if ($in{'proto'}) {
 $newline .= " -p";
 $newline .= ($pneg) ? " !" : "";
 $newline .= " $proto";
}

$newline .= (($proto eq "icmp") && $icmptype) ? " --icmp-type $icmptype" : "";

if ($in{'dev'}) {
 $newline .= " -i";
 $newline .= ($devneg) ? " !" : "";
 $newline .= " $dev";
}

$newline .= ($syn) ? " -y" : "";
$newline .= ($insyn) ? " ! -y" : "";

$newline .= ($frag) ? " -f" : "";
$newline .= ($infrag) ? " ! -f" : "";

$newline .= ($tos && ($tos ne "0x00")) ? " -t 0x01 $tos" : "";

return $newline;
}


sub parse_host_line {
  local(%host, $line);
  $line=$_[0];

  ($host{'ip'}, $host{'names'}) = split(/ /, $line, 2);
  ($host{'ip'}, $host{'netmask'}) = split(/\//, $host{'ip'}, 2);
  if (!$host{'netmask'}) { $host{'netmask'} = "32" }
  $host{'orig'} = $$lines[$i];
  $host{'line'} = $_[1];

return %host;
}

sub get_hosts {
 local($file, @rv, $i, $lines);
 $file=$_[0];

 if (!-e $file) { &error(&text('lib_err_host', $file)) }
 $lines = read_file_lines($file);
 @rv=();

 for (my $i=0; $i <= @$lines - 1; $i++)
 {
  local(%host);
  next if ($$lines[$i] =~ m/^#/i);
  $$lines[$i] =~ s/\t/ /g;
  $$lines[$i] =~ s/[ ]{2,}/ /g;
  next if (!$$lines[$i]);
  %host=&parse_host_line($$lines[$i], $i);
  push (@rv, \%host);
 }

return @rv;
}


sub generate_hostsfile {
 local($file, $si);
 $file=$_[0];
 
  open(FILE, ">$file") || error(&text('lib_err_create', $file));
   print FILE "# IPchains Firewalling - User defined hosts\n";
   print FILE "# Generated by IPchains Firewalling Webmin Module\n";
   print FILE "# Copyright (C) 1999-2000 by Tim Niemueller, GPL\n";
   print FILE "# Created on ", &make_date(time), "\n";
  close(FILE);

}

# host_chooser_button(field, [form])
# Returns HTML for a javascript button for choosing a host
sub host_chooser_button
{
local $form = @_ > 1 ? $_[1] : 0;
return "<input type=button onClick='ifield = document.forms[$form].$_[0]; chooser = window.open(\"/ipchains/host_chooser.cgi\", \"chooser\", \"toolbar=no,menubar=no,scrollbars=yes,width=500,height=300\"); chooser.ifield = ifield' value=\"...\">\n";
}

sub get_services {
 local(@rv, @lines, $l);

 return () if (!-e "/etc/services");
 open(SERVICES, "/etc/services");
  @lines=<SERVICES>;
 close(SERVICES);
 push(@lines, "0:65535 0:65535/tcp # Any Port");
 
 @rv=();

 foreach $l (sort @lines) {
  local(%service);
  next if ($l =~ m/^#/i);
  $l =~ s/\t/ /g;
  $l =~ s/[ ]{2,}/ /g;
  ($service{'name'}, $service{'port'}, $service{'comment'}) = split(/ /, $l, 3);
  ($service{'port'}, $service{'proto'}) = split(/\//, $service{'port'}, 2);
  if (($service{'proto'} eq "tcp") || ($service{'proto'} eq "udp")) {
   push(@rv, \%service);
  }
 }

return @rv;
}

sub get_services_list {
 local(@rv, @lines, $l);

 return () if (!-e "/etc/services");
 open(SERVICES, "/etc/services");
  @lines=<SERVICES>;
 close(SERVICES);
 push(@lines, "any	0:65535	# Any Port");
 
 @rv=();
 foreach $l (sort @lines) {
  local($name, $rest);
  next if ($l =~ m/^#/i);
  $l =~ s/\t/ /g;
  $l =~ s/[ ]{2,}/ /g;
  ($name, $rest) = split(/ /, $l, 2);
   push(@rv, $name);
 }

return @rv;
}


# service_chooser_button(field, [form])
# Returns HTML for a javascript button for choosing a host
sub service_chooser_button
{
local $form = @_ > 1 ? $_[1] : 0;
return "<input type=button onClick='ifield = document.forms[$form].$_[0]; chooser = window.open(\"/ipchains/service_chooser.cgi\", \"chooser\", \"toolbar=no,menubar=no,scrollbars=yes,width=500,height=300\"); chooser.ifield = ifield' value=\"...\">\n";
}




1;
### END of ipchains-lib.cgi ###.
