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

&init_config();
%access=&get_module_acl();
$cl=$text{'config_link'};
$version="0.82.1";
$intiface=undef;
$extiface=undef;
$bootdir=undef;
$extdhcp=undef;

$ipchains=($config{'ipchains_path'}) ? $config{'ipchains_path'} : "/sbin/ipchains";

if (!-e "/proc/net/ip_fwchains") { &error($text{'lib_err_nosupport'}) }
if (!-e "/proc/net/ip_fwnames") { &error($text{'lib_err_nosupport'}) }
if (!-x $ipchains) { &error(&text('lib_err_ipchains', $ipchains, $cl)) }
if ((! $config{'scriptfile'}) &&
    ($ENV{'SCRIPT_NAME'} !~ /(index\.cgi|ipchains\/|save_config\.cgi)$/)) { &error(&text('lib_err_sfcm', $cl)) }

if ((!-e "$config{'scriptfile'}") &&
    ($ENV{'SCRIPT_NAME'} !~ /(script_manager\.cgi|index\.cgi|save_config\.cgi|ipchains\/)$/)) {
  &error(&text('lib_err_sfmiss', $cl));
}


if ($config{'bootloc'}) {
  $bootdir=$config{'bootloc'};
} else {
  # we try to get the information from the init module
  my %initconf;
  &read_env_file("$config_directory/init/config", \%initconf);
  if ($initconf{'init_dir'}) {
    $bootdir=$initconf{'init_dir'};
  } else {
    &error(&text('lib_noinit', $cl)) if ($ENV{'SCRIPT_NAME'} !~ /(index\.cgi|ipchains\/|save_config\.cgi)$/);
  }
}

if ($config{'extdhcp'} == 1) {
  # we try to figure out if DHCP is used or not by using the net conf mod

  if (&foreign_check('net')) {
    # OK, net conf mod available otherwise do nothing, extdhcp will be
    # undef and the questionaire will come up in index.cgi

    &foreign_require('net', 'net-lib.pl');
    my @boot = &foreign_call('net', 'boot_interfaces');
    my $b;

    foreach $b (@boot) {
      if ($b->{'fullname'} eq $config{'extdev'}) {
        # We found the interface
        if ($b->{'dhcp'}) {
          # Oh no, DHCP ;)
          $extdhcp=1;
        } else {
          $extdhcp=0;
        }
      }
    }
  }

} elsif ($config{'extdhcp'} == 2) {
  # Manual override, we assume DHCP
  $extdhcp=1;
} else {
  $extdhcp=0;
}

# Argument with 0, 1 or 2 following words (! is not a word)
@aw0=("-1", "-y", "-f", "-b", "-l");
@aw1=("-N", "-X", "-F", "-j", "-m", "-p", "-i", "-A", "-I", "--icmp-type");
@aw2=("-D", "-R", "-P", "-d", "-s", "-t");

%tos=("0x00" => $text{'lib_tosnotset'},
      "0x10" => $text{'lib_tosmindel'},
      "0x08" => $text{'lib_tosmaxthr'},
      "0x04" => $text{'lib_tosmaxrel'},
      "0x02" => $text{'lib_tosmincost'});

@basechains=("input", "output", "forward");
@policies=("ACCEPT", "DENY", "MASQ", "REJECT", "RETURN");

&ReadParse();
$MASQ=$in{'masq'};
$DESC=undef;

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
 $rv.="<OPTION VALUE=0>$text{'lib_any'}\n";
 @proto=&get_proto_list();
 foreach $p (@proto) {
  $rv.= "<OPTION VALUE=\"$p\"";
  $rv.= ($p eq $sel) ? " SELECTED" : "";
  $rv.= ">$p\n";
 }
 $rv.="</SELECT>\n";

return $rv;
}

# get_iface_select([devicename], [selectname])
# returns the HTML code for an device selectbox with devicename checked and
# the box named selectname
sub get_iface_select {
 my $sel = $_[0];
 my $selname = ($_[1]) ? $_[1] : "dev";

 my $rv = "<SELECT NAME=\"$selname\">\n";
 $rv .= "<OPTION VALUE=\"\">$text{'lib_anydev'}\n";



 if (&foreign_check('net')) {
  # we use the network configuration module for getting
  # all interfaces

  &foreign_require('net', 'net-lib.pl');
  my @act = &foreign_call('net', 'active_interfaces');
  @act = sort { "$a->{'name'}:$a->{'virtual'}" cmp
                "$b->{'name'}:$b->{'virtual'}" } @act;
 
  my $a;
  foreach $a (@act) {
   $rv.="<OPTION VALUE=\"$a->{'fullname'}\"";
   $rv.=($a->{'fullname'} eq $sel) ? " SELECTED" : "";
   $rv.=">$a->{'fullname'}\n";
  }
 } else {
  # we parse the interfaces from the entered list
  defined($config{'netifaces'}) || &error($text{'lib_err_netmod'});
  my $a=$config{'netifaces'};
  $a=~tr/\s+//;
  my @act=split(/,/, $a);
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


# insert_line(line, \lines, \ps)
# inserts line at the first possible location in \lines from the parsed script
# \ps. This is either after the last -P rule (which should be right in the
# beginning of the script for well know reasons) or after the first -X rule
# (which should have been created when creating the basic script file) and
# a newline.
sub insert_line {

  my $l;
  my $line=undef;
  my $pols=&find_arg_struct('-P', $_[2]);
  if (scalar(@{$pols})) {
    # we have at least one policy rule, so we insert it after the last
    foreach $l (@{$pols}) {
      my $c=&find_arg('-P', $l);
      $line=$c->{'line'} if (! defined($line) || ($c->{'line'} > $line));
    }
    my @tmpln=($_[1]->[$line], $_[0]);
    splice(@{$_[1]}, $line, 1, @tmpln);
    return 1;
  } else {
    my $cdels=&find_arg_struct('-X', $_[2]);
    if (scalar(@{$cdels})) {
      # OK, at least we found some -X
      foreach $l (@{$cdels}) {
        $c=&find_arg('-X', $l);
        $line=$c->{'line'} if (! defined($line) || ($c->{'line'} < $line));
      }
      my @tmpln=($_[1]->[$line], "\n", $_[0]);
      splice(@{$_[1]}, $line, 1, @tmpln);
      return 1;
    }
  }

return 0;
}


sub parse_line {
  local($line, @parsedparams, $p, $tmpstr, $n, $rawline);

  $tmpstr=$_[0];
  $n=$_[1];

  chomp($tmpstr);
  $rawline=$tmpstr;
  $tmpstr =~ s/\t/ /g;       # Convert tabs to spaces
  $tmpstr =~ s/[ ]{2,}/ /g;  # Convert multi-spaces to singel-spaces

  @params=split(/ /, $tmpstr);

  if ($params[0] eq $ipchains) {
    # we have a rule

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

  } elsif ($rawline =~ /^#/) {
    # We have a comment
    my %tmp=( 'name' => "Comment",
              'type' => "C",
              'line' => $n,
              'cont' => $rawline );
    push(@parsedparams, \%tmp);
  } else {
    # Not a rule, we do not know what it is
    my %tmp=( 'name' => "Unknown",
              'type' => "U",
              'line' => $n,
              'cont' => $rawline );
    push(@parsedparams, \%tmp);
  }

return \@parsedparams;
}

sub parse_script {
 local(@lines, @rv, $tmpstr, $i) ;
 
 @lines=&read_script;
 
 for (my $n=0; $n<@lines; $n++) {
  $tmpstr=@lines[$n];
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

# get_services()
# This function returns an array of hashes containing the information about the services
# keys            meaning
#------------------------------------------------------------------------
# name            Service Name
# port            Port assigned to this service
# comment         Comments stored in the services file for this service
# proto           Protocol used, either TCP oder UDP
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

# get_services_list()
# This function returns an arraw containing all known service names
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



# fill_tokens(line1, [line2, [line3, [...]]])
# Replace tokens in templates
sub fill_tokens
{
  my @lines = @_;
  if (! (defined($intiface) && defined($extiface)))  {
    # something like a cache, it is a little bit two slow to do that for
    # all 12312 lines again...
    if (&foreign_check('net')) {
      &foreign_require('net', 'net-lib.pl');
      my @act = &foreign_call('net', 'active_interfaces');
      @act = sort { "$a->{'name'}:$a->{'virtual'}" cmp
                    "$b->{'name'}:$b->{'virtual'}" } @act;
      my $a;
      foreach $a (@act) {
        $intiface = $a if ($a->{'fullname'} eq $config{'intdev'});
        $extiface = $a if ($a->{'fullname'} eq $config{'extdev'});
      }
    } else {
      $intiface->{'address'} = `ifconfig $config{'intdev'} | grep 'inet addr' | awk -F: '{ print \$2 } ' | awk '{ print \$1 }'`;
      $extiface->{'address'} = `ifconfig $config{'extdev'} | grep 'inet addr' | awk -F: '{ print \$2 } ' | awk '{ print \$1 }'`;
      $intiface->{'netmask'} = `ifconfig $config{'intdev'} | grep 'inet addr' | awk -F: '{ print \$4 } ' | awk '{ print \$1 }'`;
      $extiface->{'netmask'} = `ifconfig $config{'extdev'} | grep 'inet addr' | awk -F: '{ print \$4 } ' | awk '{ print \$1 }'`;
      chomp $intiface->{'address'};
      chomp $extiface->{'address'};
      chomp $intiface->{'netmask'};
      chomp $extiface->{'netmask'};
    } # END if net module available
  }

  &error($text{'lib_err_noint'}) if (! defined($intiface));
  &error($text{'lib_err_noint'}) if (! defined($extiface));

  my $intnet=&network($intiface->{'address'}, $intiface->{'netmask'}) .
             "/$intiface->{'netmask'}";
  my $extnet=&network($extiface->{'address'}, $extiface->{'netmask'}) .
             "/$extiface->{'netmask'}";
  my $intbc=&broadcast($intiface->{'address'}, $intiface->{'netmask'});
  my $extbc=&broadcast($extiface->{'address'}, $extiface->{'netmask'});

  foreach (@lines) {
    s/\@IPCHAINS\@/$ipchains/g;
    s/\@INTDEV\@/$config{'intdev'}/g;
    s/\@EXTDEV\@/$config{'extdev'}/g;
    s/\@INTIP\@/$intiface->{'address'}/g;
    s/\@INTNM\@/$intiface->{'netmask'}/g;
    s/\@INTBC\@/$intbc/g;
    s/\@EXTIP\@/$extiface->{'address'}/g if (! $extdhcp);
    s/\@EXTIP\@/\$EXTIP/g if ($extdhcp);
    s/\@EXTNM\@/$extiface->{'netmask'}/g if (! $extdhcp);
    s/\@EXTNM\@/\$EXTNM/g if ($extdhcp);
    s/\@EXTBC\@/$extbc/g if (! $extdhcp);
    s/\@EXTBC\@/\$EXTBC/g if ($extdhcp);
    s/\@WEBMINPORT\@/$ENV{'SERVER_PORT'}/g;
    s/\@INTNET\@/$intnet/g;
    s/\@EXTNET\@/$extnet/g if (! $config{'internet'} && ! $extdhcp);
    s/\@EXTNET\@/\$EXTNW\/\$EXTNM/g if (! $config{'internet'} && $extdhcp);
    s/\@EXTNET\@/! $intiface->{'address'}/g if ($config{'internet'});
    s/##MASQ: //g if (! $DESC && $MASQ);
    s/##NOMASQ: //g if (! $DESC && ! $MASQ);
  }
return (wantarray) ? @lines : $lines[0];
}


# create_basic_script(filename)
# Creates a script file with basic calls to delete all existing rules and chains
sub create_basic_script
{

  my $si = ($config{'scriptinterpreter'}) ? $config{'scriptinterpreter'} : "/bin/sh";

  open(FILE, ">$_[0]") || return 0;
   print FILE "#!$si\n",
              "# IPchains Firewalling Script File\n",
              "# Generated by IPchains Firewalling Webmin Module\n",
              "# Copyright (C) 1999-2000 by Tim Niemueller, GPL\n",
              "# http://www.niemueller.de/webmin/modules/ipchains/\n",
              "# Created on ", &make_date(time), "\n",
              "\n$ipchains -F\n$ipchains -X\n\n";
  close(FILE);

return 1;
}

# write_basics(filename, externalname, external-ip)
# Writes basic stuff like spoof protection for private ranges, acceptance
# for loopback traffic etc.
sub write_basics {

  open(SCRIPT, ">>$_[0]") || return 0;

   if ($extdhcp) {
     # Oh sh..oot, work to do, he wants dhcp on the outside iface :)
     print SCRIPT "\n# Dynamic IP Hack for outside interface\n",
                  "EXTIP=`ifconfig $config{'extdev'} | grep 'inet addr' | awk -F: '{ print \$2 } ' | awk '{ print \$1 }'`\n",
                  "EXTNM=`ifconfig $config{'extdev'} | grep 'inet addr' | awk -F: '{ print \$4 } ' | awk '{ print \$1 }'`\n",
                  "EXTBC=`ifconfig $config{'extdev'} | grep 'inet addr' | awk -F: '{ print \$3 } ' | awk '{ print \$1 }'`\n",
                  "EXTNW=`ipcalc --network \$EXTIP \$EXTNM | awk -F= '{ print \$2 }'`\n";
     $_[2]='$EXTIP';
   }

   print SCRIPT "\n$ipchains -A input -i lo -j ACCEPT\n",
                "$ipchains -A output -i lo -j ACCEPT\n\n",
                "\n#Do not accept packets from private class A on ext NIC\n",
                "$ipchains -A input -i $_[1] -s 10.0.0.0/8 -j DENY\n",
                "$ipchains -A input -i $_[1] -d 10.0.0.0/8 -j DENY\n",
                "$ipchains -A output -i $_[1] -s 10.0.0.0/8 -j DENY\n",
                "$ipchains -A output -i $_[1] -d 10.0.0.0/8 -j DENY\n",
                "\n#Do not accept packets from private class B on ext NIC\n",
                "$ipchains -A input -i $_[1] -s 172.16.0.0/12 -j DENY\n",
                "$ipchains -A input -i $_[1] -d 172.16.0.0/12 -j DENY\n",
                "$ipchains -A output -i $_[1] -s 172.16.0.0/12 -j DENY\n",
                "$ipchains -A output -i $_[1] -d 172.16.0.0/12 -j DENY\n",
                "\n#Do not accept packets from private class C on ext NIC\n",
                "$ipchains -A input -i $_[1] -s 192.168.0.0/16 -j DENY\n",
                "$ipchains -A input -i $_[1] -d 192.168.0.0/16 -j DENY\n",
                "$ipchains -A output -i $_[1] -s 192.168.0.0/16 -j DENY\n",
                "$ipchains -A output -i $_[1] -d 192.168.0.0/16 -j DENY\n",
                "\n# Loopback packets should not be handled from ext NIC\n",
                "$ipchains -A input -i $_[1] -s 127.0.0.0/8 -j DENY\n",
                "$ipchains -A output -i $_[1] -s 127.0.0.0/8 -j DENY\n",
                "\n#Refuse Bogus Broadcasts\n",
                "$ipchains -A input -i $_[1] -s 255.255.255.255 -j DENY\n",
                "$ipchains -A input -i $_[1] -d 0.0.0.0 -j DENY\n",
                "\n# Refuse Requests from reserved IANA/ICANN adresses\n",
                "$ipchains -A input -i $_[1] -s 1.0.0.0/8 -j DENY\n",
                "$ipchains -A input -i $_[1] -s 2.0.0.0/8 -j DENY\n",
                "$ipchains -A input -i $_[1] -s 5.0.0.0/8 -j DENY\n",
                "$ipchains -A input -i $_[1] -s 7.0.0.0/8 -j DENY\n",
                "# They have the Illuminati number of course :)\n",
                "$ipchains -A input -i $_[1] -s 23.0.0.0/8 -j DENY\n";
   my $num;
   foreach $num (27, 31, 36, 37, 39, 41, 42, 58, 59, 60, 67, 218, 219) {
     print SCRIPT "$ipchains -A input -i $_[1] -s ${num}.0.0.0/8 -j DENY\n";
   }

   print SCRIPT "$ipchains -A input -i $_[1] -s 68.0.0.0/6 -j DENY\n",
                "$ipchains -A input -i $_[1] -s 72.0.0.0/5 -j DENY\n",
                "$ipchains -A input -i $_[1] -s 80.0.0.0/3 -j DENY\n",
                "$ipchains -A input -i $_[1] -s 112.0.0.0/4 -j DENY\n",
                "$ipchains -A input -i $_[1] -s 220.0.0.0/6 -j DENY\n",
                "\n# Basic ICMP packages are needed for running a network\n",
                "$ipchains -A input -i $_[1] -p icmp --icmp-type source-quench -d $_[2] -j ACCEPT\n",
                "$ipchains -A output -i $_[1] -p icmp --icmp-type source-quench -d 0.0.0.0/0 -j ACCEPT\n",
                "$ipchains -A input -i $_[1] -p icmp --icmp-type parameter-problem -d $_[2] -j ACCEPT\n",
                "$ipchains -A output -i $_[1] -p icmp --icmp-type parameter-problem -d 0.0.0.0/0 -j ACCEPT\n",
                "$ipchains -A input -i $_[1] -p icmp --icmp-type destination-unreachable -d $_[2] -j ACCEPT\n",
                "$ipchains -A output -i $_[1] -p icmp --icmp-type destination-unreachable -d 0.0.0.0/0 -j ACCEPT\n",
                "$ipchains -A input -i $_[1] -p icmp --icmp-type time-exceeded -d $_[2] -j ACCEPT\n",
                "$ipchains -A output -i $_[1] -p icmp --icmp-type time-exceeded -d 0.0.0.0/0 -j ACCEPT\n\n";

  close(SCRIPT);

}





sub broadcast {

 my $ipnum = &numberize($_[0]);
 my $nmnum = &numberize($_[1]);
 my $broadcast = &denumberize($ipnum | ~ $nmnum);

return $broadcast;
}

sub network {

 my $ipnum = &numberize($_[0]);
 my $nmnum = &numberize($_[1]);
 my $network = &denumberize($ipnum & $nmnum);

return $network;
}

sub numberize {
 (my $a, my $b, my $c, my $d) = split(/\./, $_[0]);
 return (($a << 24) | ($b << 16) | ($c << 8) | $d);
}

sub denumberize {
 return join('.', ($_[0] & 0xff000000) >> 24,
                  ($_[0] & 0x00ff0000) >> 16,
                  ($_[0] & 0x0000ff00) >> 8,
                  ($_[0] & 0x000000ff) );
}




1;
### END of ipchains-lib.cgi ###.
