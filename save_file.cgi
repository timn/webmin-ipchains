#!/usr/bin/perl

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
#    Inherited from sendmail/save_file.cgi

require './ipchains-lib.pl';
&error_setup($text{'sfile_err'});

$in{'text'} =~ s/\r//g;
open(FILE, ">$config{'scriptfile'}");
 print FILE $in{'text'};
close(FILE);

&redirect("");

### END of save_file.cgi ###.
