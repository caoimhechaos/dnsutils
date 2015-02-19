#!/usr/bin/perl -w
#

use strict;
use warnings;

use File::Slurp qw(read_file write_file);
use Net::DNS;

my @supported_types = qw(SOA A AAAA CNAME TXT MX NAPTR NS SRV PTR);
my %support;
my $resolver = new Net::DNS::Resolver();
my @reply;
my $text;
my $serial = 0;
my $remote_serial = 0;
my $answer;
my $fh;

my ($domain, $ns) = @ARGV;

die('Usage: ' . __FILE__ . ' <domain> <nameserver>')
	unless (defined($domain) && defined($ns));

$resolver->nameserver($ns);

eval {
	$text = read_file($domain);
};
unless ($@) {
	if ($text =~ /$domain.*SOA\D+(\d*)\D/) {
		$serial = $1;
	}
}

if (int($serial) > 0) {
	$answer = $resolver->query($domain, 'SOA');
	@reply = $answer->answer;

	foreach $answer (@reply) {
		if ($answer->type eq 'SOA') {
			$remote_serial = $answer->serial;
		}
	}
}

if ($serial && $remote_serial && $serial eq $remote_serial) {
	printf("%s is already up to date at %d\n",
		$domain, $serial);
	exit(0);
}

@reply = $resolver->axfr($domain);

die $resolver->errorstring unless @reply;

for my $type (@supported_types) {
	$support{$type} = 1;
}

$fh = IO::File->new('> ' . $domain);
unless (defined($fh)) {
	die('Unable to open ' . $domain);
}

for my $rr (@reply) {
	if ($rr->type eq 'SOA') {
		printf($fh "\$ORIGIN %s.\n", $rr->name);
	}

	if ($support{$rr->type}) {
		printf($fh "%s\n", $rr->string);
	} else {
		printf($fh "%s.\t%d\t%s\tTYPE%d\t\\# %d %s\n",
			$rr->name, $rr->ttl, $rr->class,
		       	Net::DNS::typesbyname($rr->type),
			length($rr->rdata),
			unpack('H*', $rr->rdata));
	}
}
