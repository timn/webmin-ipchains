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

#    Created  : 15.09.2000
#    Inherited from sendmail/edit_file.cgi

require "./ipchains-lib.pl";
&error_setup($text{'rawedit_err'});

&header($text{'rawedit_title'}, undef, "cchain", 1, 1, undef,
       "Written by<BR><A HREF=mailto:tim\@niemueller.de>Tim Niemueller</A>".
       "<BR><A HREF=http://www.niemueller.de>Home://page</A>");
print "<HR><BR>\n";


open(FILE, $config{'scriptfile'});
@lines = <FILE>;
close(FILE);


print "<B>$text{'rawedit_desc'}</B><BR><BR>\n",
      "<form action=save_file.cgi method=post>\n",
      "<textarea name=text rows=20 cols=80>",
        join("", @lines),"</textarea><p>\n",
      "<input type=submit value=\"$text{'save'}\"> ",
      "<input type=reset value=\"$text{'rawedit_undo'}\">\n",
      "</form>\n",
      "<hr>\n";

&footer($return, $text{'rawedit_return'});

### END of rawedit.cgi ###.
