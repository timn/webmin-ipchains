#!/usr/bin/perl
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

#    Created  : 30.08.2000
#    Partly taken from /config_save.cgi

require './ipchains-lib.pl';

&read_file("$config_directory/$module_name/config", \%config);

for (keys %in) {
  next if ($_ eq 'save');
  $config{$_} = $in{$_};
}

mkdir("$config_directory/$module_name", 0700);
&write_file("$config_directory/$module_name/config", \%config);
&redirect("");

### END of save_config.cgi ###.