#!/usr/bin/perl
# host_chooser.cgi
# This CGI generated the HTML for choosing a host.
# Created 29.10.1999

require './ipchains-lib.pl';

# Build list of hosts
if (!$config{'hostsfile'}) { $hostsfile="/etc/hosts" } else { $hostsfile=$config{'hostsfile'} }
@hosts=&get_hosts($hostsfile);

if (-e "$module_config_directory/hosts.db") {
 push(@hosts, &get_hosts("$module_config_directory/hosts.db"));
}

&header();

print <<EOM;
<SCRIPT LANGUAGE="JavaScript">
function select(f)
{
 ifield.value = f;
 top.close();
 return false;
}
</SCRIPT>
<TITLE>$text{'selhost_title'}</TITLE>
<TABLE WIDTH=100%>
EOM
 foreach $h (@hosts) {
  print "<TR>\n";
  print "<TD><a href=\"\" onClick='return select(\"$h->{'ip'}/$h->{'netmask'}\")'>$h->{'ip'}/$h->{'netmask'}</TD>",
        "<TD>$h->{'names'}</TD></TR>\n";
 }
print "</TABLE>\n</BODY></HTML>";

### END of host_chooser.cgi ###.