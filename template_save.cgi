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

#    Created  : 30.08.2000

require "./ipchains-lib.pl";


  my %miniserv;
  &get_miniserv_config(\%miniserv);
  my %templates=();
  opendir(TEMPLATES, "$miniserv{'root'}/$module_name/templates") || print "FAILED to open template dir";
    while($_ = readdir(TEMPLATES)) {
      next if (/^\./);
      next if (! /-(inout|infw|outin|outfw|fwin|fwout)$/);
      /^(\S+){1}-(inout|infw|outin|outfw|fwin|fwout){1}$/;
      $templates{$1}->{$2}++;
    }
  closedir(TEMPLATES);


  my $mode;
  open(SCRIPT, $config{'scriptfile'});
    while (<SCRIPT>) {
      $mode = $1 if (/^##MODE (\d){1}/);
    }
  close(SCRIPT);

  if (($mode != 2) && ! $in{'confirm'}) {
    &header($text{'templsave_title'}, undef, undef, undef, undef, undef,
       "Written by<BR><A HREF=mailto:tim\@niemueller.de>Tim Niemueller</A><BR><A HREF=http://www.niemueller.de>Home://page</A>");
     
    print "<HR><BR><H3>$text{'templsave_wrongmode'}</H3>\n<FORM ACTION=$ENV{'SCRIPT_NAME'} METHOD=POST>\n";
    for (keys %templates) {
      foreach $t (infw, inout, outfw, outin, fwin, fwout) {
        if ($templates{$_}->{$t} && $in{"$_-$t"}) {
          print "<INPUT TYPE=hidden NAME=\"$_-$t\">\n";
        }
      }
    }
    print "<INPUT TYPE=submit NAME=confirm VALUE=\"$text{'templsave_overwrite'}\"></FORM><HR>";
    
    &footer("", $text{'templsave_return'});

    exit 0;

  }


  &create_basic_script($config{'scriptfile'}) || &error($text{'templsave_err_write'});

  open(SCRIPT, ">>$config{'scriptfile'}");
  print SCRIPT "##MODE 2\n",
               ($MASQ) ? "##MASQ\n" : "",
               "\n\n$ipchains -P input $config{'policy'}\n",
               "$ipchains -P output $config{'policy'}\n",
               "$ipchains -P forward $config{'policy'}\n";
  close(SCRIPT);

  # Seems useless but creates the cached interface information
  &fill_tokens();
  &write_basics($config{'scriptfile'}, $config{'extdev'}, $extiface->{'address'});


  # &header("DEBUG");
  # for (keys %templates) {
  #    foreach $t (inout, infw, outin, outfw, fwin, fwout) {
  #      print "$_: $t: $templates{$_}->{$t}<BR>\n";
  #    }
  # }
  # exit;


  my %already=();
  my $k;
  my $t;
  my @keys = keys %templates;
  open(SCRIPT, "$config{'scriptfile'}");
    my @lines=<SCRIPT>;
    my $ln=scalar(@lines);
  close(SCRIPT);
  open(SCRIPT, ">>$config{'scriptfile'}");
  foreach $k (@keys) {
    foreach $t (infw, inout, outfw, outin, fwin, fwout) {
      if (defined($templates{$k}->{$t}) && $in{"$k-$t"}) {
        open(TEMPL, "$miniserv{'root'}/$module_name/templates/$k-$t");
          print SCRIPT "\n\n##=> $k-$t\n";
          $ln += 3;
          while (<TEMPL>) {
            chomp;
            $ln++;
            my $line=&fill_tokens($_);
            if (defined($already{$line}) && ($line !~ /^#/)) {
              print SCRIPT "# Already set in line $already{$line}\n";
            } else {
              print SCRIPT "$line\n";
              $already{$line}=$ln;
            }
          }
        close(TEMPL);
      }
    }
  }

  close(SCRIPT);

  # Now run the script to make the changes active
  if (!-x $config{'scriptfile'}) {
    chmod 0700, $config{'scriptfile'};
  }

  # Run that... firewall script
  system($config{'scriptfile'});


&redirect("");

### END of template_save.cgi ###.
