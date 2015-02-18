#!/usr/bin/perl -w
#

use strict;
use warnings;

use Net::DNS;

my @supported_types = qw(SOA A AAAA CNAME TXT MX NAPTR NS SRV PTR);
my %support;
my $resolver = new Net::DNS::Resolver();
my @reply;

my ($domain, $ns) = @ARGV;

$resolver->nameserver($ns);

@reply = $resolver->axfr($domain);

die $resolver->errorstring unless @reply;

for my $type (@supported_types) {
	$support{$type} = 1;
}

for my $rr (@reply) {
	if ($rr->type eq 'SOA') {
		printf("\$ORIGIN %s.\n", $rr->name);
	}

	if ($support{$rr->type}) {
		printf("%s\n", $rr->string);
	} else {
		printf("%s.\t%d\t%s\tTYPE%d\t\\# %d %s\n",
			$rr->name, $rr->ttl, $rr->class,
		       	Net::DNS::typesbyname($rr->type),
			length($rr->rdata),
			unpack("H*", $rr->rdata));
	}
}
