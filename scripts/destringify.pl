#!/usr/bin/perl -w
#
# Author: Ilya V. Matveychikov 
#
# https://github.com/milabs
#

use FindBin qw($Bin);
use lib "$Bin/lib";
use Unescape;

sub translate($) {
	my $str = shift;

	my $i = 0;
	my @tokens = ();
	push @tokens, "unsigned int *p = __builtin_alloca(%d)";
	map { push @tokens, sprintf("p[%d] = 0x%08x", $i++, $_) } unpack("V*", pack("(C4)*", unpack("C*", String::Unescape->unescape($str)), 0));
	push @tokens, "(char *)p";
	my $body = join("; ", @tokens);

	return sprintf("({ $body; })", scalar($i) << 2);
}

while (my $line = <STDIN>) {

	next if ($line =~ /asm/);
	next if ($line =~ /include/);
	next if ($line =~ /__attribute__/);

	while ($line =~ /"(.*?)"/) {
		my $replace = translate($1);
		$line =~ s/(".*?")/$replace/;
	}
} continue {
	print "$line"
}
