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

&error($text{'changelev_err_wrong'}) if ($in{'level'} !~ /^(disabled|low|medium|high|full)$/);

my %miniserv;
&get_miniserv_config(\%miniserv);


( -e "$miniserv{'root'}/$module_name/templates/".uc($in{'level'}).
     "-" . $config{'fwtype'} . "-level") ||
         &error($text{'changelev_err_nofile'});

open(LEVEL, "$miniserv{'root'}/$module_name/templates/".uc($in{'level'}).
            "-" . $config{'fwtype'} . "-level");
  my @templates=<LEVEL>;
close(LEVEL);

my $input_policy=shift @templates;
my $output_policy=shift @templates;
my $forward_policy=shift @templates;
chomp $input_policy;
chomp $output_policy;
chomp $forward_policy;


if ($in{'confirm'}) {
  # confirmed, change it

  &create_basic_script($config{'scriptfile'}) || &error($text{'changelev_err_write'});
  open(SCRIPT, ">>$config{'scriptfile'}");
  print SCRIPT "##MODE 1\n",
               "##LEVEL ", uc($in{'level'}), "\n",
               ($MASQ) ? "##MASQ\n" : "",
               "##FWTYPE ", uc($config{'fwtype'}), "\n",
               "\n\n$ipchains -P input $input_policy\n",
               "$ipchains -P output $output_policy\n",
               "$ipchains -P forward $forward_policy\n";  
  close(SCRIPT);

  if ($in{'level'} ne 'disabled') {
    # Seems useless but creates the cached interface information
    &fill_tokens();
    &write_basics($config{'scriptfile'}, $config{'extdev'}, $extiface->{'address'});

    my %already=();
    open(SCRIPT, "$config{'scriptfile'}");
      my @lines=<SCRIPT>;
      my $ln=scalar(@lines);
    close(SCRIPT);
    open(SCRIPT, ">>$config{'scriptfile'}");
    my $temp;
    foreach $temp (@templates) {
      chomp $temp;
      ($name, @dirs) = split(/-/, $temp);
      my $t;
      foreach $t (@dirs) {
        if (-e "$miniserv{'root'}/$module_name/templates/$name-$t") {
          print SCRIPT "\n\n##=> $name-$t\n";
          $ln += 3;

 
          $lang = $gconfig{"lang_$u"} ? $gconfig{"lang_$u"} :
                  $gconfig{"lang"} ? $gconfig{"lang"} : "en";

          if (-e "$miniserv{'root'}/$module_name/descriptions/$lang/$name-$t") {
            $descfile = "$miniserv{'root'}/$module_name/descriptions/$lang/$name-$t";
          } else {
            $descfile = "$miniserv{'root'}/$module_name/descriptions/en/$name-$t";
          }

          open(DESC, $descfile);
            while (<DESC>) {
              chomp;
              $ln++;
              print SCRIPT "$_\n";
            }
          close(DESC);

          open(TEMPL, "$miniserv{'root'}/$module_name/templates/$name-$t");
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
  } ## END if disabled

  # Now run the script to make the changes active
  if (!-x $config{'scriptfile'}) {
    chmod 0700, $config{'scriptfile'};
  }

  # Run that... firewall script
  system($config{'scriptfile'});

  &redirect("");

} else {
  # not confirmed, display description

  &header($text{'changelev_title'}, undef, "changelevel", undef, undef, undef,
          "Written by<BR><A HREF=mailto:tim\@niemueller.de>Tim Niemueller</A>".
          "<BR><A HREF=http://www.niemueller.de>Home://page</A>");

  print "<HR><BR>\n<H3>",
        &text('changelev_heading', $text{"index_$config{'fwtype'}for"}),
        "</H3>\n",
        $text{"changelev_desc_$in{'level'}"},
        "<BR><BR><BR>";
  if (scalar(@templates)) {
    print "<TABLE BORDER=0>\n<TR>",
          "<TD><B>$text{'changelev_prot'}</B></TD><TD>&nbsp;</TD>",
          "<TD><B>$text{'changelev_dirs'}</B></TD></TR>\n",
          "<TR><TD COLSPAN=3><HR></TD></TR>\n";

    foreach $t (@templates) {
      ($name, @dirs) = split(/-/, $t);
      $name =~ s/\./-/g;
      for (my $i=0; $i < @dirs; $i++) {
        chomp $dirs[$i];
        $dirs[$i] = $text{"index_$dirs[$i]"};
      }
      print "<TR><TD><B>$name</B></TD><TD>&nbsp;</TD><TD>",
            join(', ', @dirs),
            "</TD></TR>\n";
    }

    print "</TABLE>\n";

  } else {
    if ($in{'level'} eq 'full') {
      print "<TR><TD COLSPAN=3><B>$text{'changelev_nocons'}</B></TD></TR>\n";
    }
  }

  print "<BR><BR><BR><FORM ACTION=\"$ENV{'SCRIPT_NAME'}\" METHOD=post>",
        ($config{'fwtype'} eq 'router') ?
           $text{"changelev_$in{'level'}_masq"}."<BR><BR><BR>" : "",
        "<INPUT TYPE=hidden NAME=level VALUE=$in{'level'}>",
        "<INPUT TYPE=submit NAME=confirm VALUE=\"$text{'changelev_change'}\">",
        "</FORM><BR><HR>\n";

  &footer("", $text{'changelev_return'});

}



### END of change_level.cgi ###.
