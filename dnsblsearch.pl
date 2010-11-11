#!/usr/bin/perl
use strict;
use warnings;
use Net::DNS;

##############################################################################
#                                                                            #
# Copyright 2009, Mike Cardwell <dnsblsearch@grepular.com>                   #
#                                                                            #
# This program is free software; you can redistribute it and/or modify       #
# it under the terms of the GNU General Public License as published by       #
# the Free Software Foundation; either version 2 of the License, or          #
# any later version.                                                         #
#                                                                            #
# This program is distributed in the hope that it will be useful,            #
# but WITHOUT ANY WARRANTY; without even the implied warranty of             #
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the              #
# GNU General Public License for more details.                               #
#                                                                            #
# You should have received a copy of the GNU General Public License          #
# along with this program; if not, write to the Free Software                #
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA #
#                                                                            #
##############################################################################

## Maximum number of simultaneous DNS lookups. Your system will have a limit
#  on the maximum number of sockets so you *may* need to reduce this value if
#  you get an error telling you to do so 
  my $max_sockets = 512;

## A list of ips/nets to lookup.
  my @nets = int(@ARGV) ? @ARGV : qw(
     127.0.0.1
     127.0.0.2/32
  );

## A list of DNSBL's to query against
  my @lists = qw(
     b.barracudacentral.org
     bl.spamcop.net
     bl.spameatingmonkey.net
     combined.njabl.org
     dnsbl.sorbs.net
     dnsbl-1.uceprotect.net
     dnsbl-2.uceprotect.net
     dnsbl-3.uceprotect.net
     ips.backscatterer.org
     ix.dnsbl.manitu.net
     no-more-funn.moensted.dk
     psbl.surriel.com
     spamguard.leadmon.net
     spamsources.fabel.dk
     ubl.unsubscore.com
     zen.spamhaus.org
  );

## A list of exceptions, not to look up. Format: "ip listname"
  my @exceptions = (
     '127.0.0.2  dnsbl.sorbs.net',
  );

  my $res = new Net::DNS::Resolver;
  my %socket = ();
  my $counter = 0;
  my $net_netmask_required = 0;
  while( my $net = shift @nets ){

     my @ips = ( $net );
     if( $net !~ /^\d+(?:\.\d+){3}$/ ){
        unless( $net_netmask_required ){
           eval 'use Net::Netmask'; die "You must install Net::Netmask to use network notation in your list\n" if $@;
           $net_netmask_required = 1;
        }
        @ips = Net::Netmask->new($net)->enumerate();
     }

     foreach my $ip ( @ips ){
        foreach my $list ( @lists ){
           next if grep( "$ip $list" eq $_, map {s/\s{2,}/ /;$_} @exceptions, );
           $socket{"$ip:$list"} = $res->bgsend(join('.',reverse(split(/\./,$ip)),$list));
           if( ++$counter == $max_sockets ){
              check_results();
              $counter = 0;
           }
        }
     }
  }
  check_results();

sub check_results {
   foreach my $lookup ( keys %socket ){
      my( $ip, $dnsbl, ) = $lookup =~ /^(.+):(.+)$/;

      my @ips = ();
      my @answer = eval { $res->bgread($socket{$lookup})->answer; };
      die "Exceeded maximum allowed system sockets. Try reducing the value of \$max_sockets from $max_sockets\n" if $@;

      foreach( @answer ){
         push @ips, $_->address if $_->type eq 'A';
      }
      delete $socket{$lookup};
      printf( "%s is listed on %s %s\n", $ip, $dnsbl, join(', ',@ips) ) if @ips;
   }
}
