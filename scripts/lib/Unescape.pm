package String::Unescape;

use 5.008;
use strict;
use warnings;

# ABSTRACT: Unescape perl-escaped string
our $VERSION = 'v0.0.3'; # VERSION

require Exporter;
our (@EXPORT_OK) = qw(unescape);

use Carp;

my %map = (
    t => "\t",
    n => "\n",
    r => "\r",
    f => "\f",
    b => "\b",
    a => "\a",
    e => "\e",
);

my %mapc = map { chr($_) => chr($_ ^ 0x60) } 97..122;

my %convs = (
    l => sub { lcfirst shift },
    u => sub { ucfirst shift },
);

my %convp = (
    L => sub { lc shift },
    U => sub { uc shift },
    Q => sub { quotemeta shift },
);

if($^V ge v5.16.0) {
    # All constant stringy eval so this should be safe.
    eval q{use feature qw(fc); $convp{F} = sub { fc(shift) };}; ## no critic (ProhibitStringyEval)
} else {
    $convp{F} = sub { 'F'.shift }; # \E omitted
}

my $from_code = sub { chr(hex(shift)); };
my $from_name;

if($^V ge v5.14.0) {
    $from_name = sub {
        my $name = shift;
        return charnames::string_vianame($name) || die "Unknown charname $name";
    };
} else {
    $from_name = sub {
        my $name = shift;
        my $code = charnames::vianame($name);
        die "Unknown charname $name" if ! defined $code;
        return chr($code);
    };
}

my $re_single = qr/
    \\([tnrfbae]) |                  # $1 : one char
    \\c(.) |                         # $2 : control
    \\x\{([0-9a-fA-F]*)[^}]*\} |     # $3 : \x{}
    \\x([0-9a-fA-F]{0,2}) |          # $4 : \x
    \\([0-7]{1,3}) |                 # $5 : \077
    \\o\{([0-7]*)([^}]*)\} |         # $6, $7 : \o{}
    \\N\{U\+([^}]*)\} |              # $8 : \N{U+}
    \\N\{([^}]*)\} |                 # $9 : \N{name}

    \\(l|u)(.?) |                    # $10, $11 : \l, \u
    \\E |                            #
    \\?(.)                           # $12
/xs;

my $convert_single = sub {
    require charnames if defined $8 || defined $9;

    return $map{$1} if defined $1;
    return exists $mapc{$2} ? $mapc{$2} : chr(ord($2) ^ 0x40) if defined $2;
    return chr(hex($3)) if defined $3;
    return chr(hex($4)) if defined $4;
    return chr(oct($5)) if defined $5;
    return chr(oct($6)) if defined $6 && $^V ge v5.14.0;
    return 'o{'.$6.$7.'}' if defined $6;
# TODO: Need to check invalid cases
    return $from_code->($8) if defined $8;
    return $from_name->($9) if defined $9;
    return $convs{$10}($11) if defined $10;
    return $12 if defined $12;
    return ''; # \E
};

my $apply_single = sub {
    my $target = shift;
    while($target =~ s/\G$re_single/$convert_single->()/gxse) {
        last unless defined pos($target);
    }
    return $target;
};

# NOTE: I'm not sure the reason, but my $_re_recur; causes a error.
our $_re_recur;
$_re_recur = qr/
    \\([LUQF])
    (?:(?>(?:[^\\]|\\[^LUQFE])+)|(??{$_re_recur}))*
    (?:\\E|\Z)
/xs;

my $re_range = qr/
    ((?:[^\\]|\\[^LUQF])*)                                # $1: pre
    (?:
        \\([LUQF])                                        # $2: marker
        ((?:(?>(?:[^\\]|\\[^LUQFE])+)|(??{$_re_recur}))*) # $3: content
        (?:\\E|\Z)
    )*
/xs;

my $apply_range;

my $convert_range = sub {
    my ($pre, $marker, $content) = @_;
    return
        (defined $pre ? $apply_single->($pre) : '').
        (defined $marker ? $convp{$marker}($apply_range->($content)) : '');
};

$apply_range = sub {
    my $target = shift;
    while($target =~ s/\G$re_range/$convert_range->($1, $2, $3)/gxse) {
        last unless defined pos($target);
    }
    return $target;
};

sub unescape
{
    shift if @_ && eval { $_[0]->isa(__PACKAGE__); };
    croak 'No string is given' unless @_;
    croak 'More than one argument are given' unless @_ == 1;

    return $apply_range->($_[0]);
}

1;

__END__

=pod

=head1 NAME

String::Unescape - Unescape perl-escaped string

=head1 VERSION

version v0.0.3

=head1 SYNOPSIS

  # Call as class method
  print String::Unescape->unescape('\t\c@\x41\n');

  # Call as function
  use String::Escape qw(unescape);
  print unescape('\t\c@\x41\n');

=head1 DESCRIPTION

This module provides just one function, Perl's unescaping without variable interpolation. Sometimes, I want to provide a string including a character difficult to represent without escaping, outside from Perl. Also, sometimes, I can not rely on shell expansion.

  # App-count
  count -t '\t'

C<eval> can handle this situation but it has too more power than required. This is the purpose for this module.

This module is intented to be compatible with Perl's native unescaping as much as possible, with the following limitation.
If the result is different from one by Perl beyond the limitation, it is considered as a bug. Please report it.

=head2 LIMITATION

There are the following exceptions that Perl's behavior is not emulated.

=over 4

=item 1

Whether warning is produced or not.

=item 2

Strings that perl doesn't accept. For those strings, the results by this module are undefined.

=item 3

\L in \U and \U in \L. By perl, they are not stacked, which means all \Q, \L, \U and \F (if available) modifiers from the prior \L, \U or \F become to have no effect then restart the new \L, \U or \F conversion. By this module, stacked.

=item 4

\L\u and \U\l. By Perl, they are swapped as \u\L and \l\U, respectively. By this module, not swapped.

=back

For 3 and 4, t/quirks_in_perl.t contains actual examples.

=head1 METHODS

=head2 C<unescape($str)>

Returns unescaped C<$str>. For escaping, see L<perlop/Quote-and-Quote-like-Operators>.

=head1 REMARKS

L<charnames> in Perl 5.6 does not have required functionality that is Unicode name E<lt>-E<gt> code conversion in runtime, thus Perl 5.6 support is explicitly dropped.

=head1 AUTHOR

Yasutaka ATARASHI <yakex@cpan.org>

=head1 COPYRIGHT AND LICENSE

This software is copyright (c) 2013 by Yasutaka ATARASHI.

This is free software; you can redistribute it and/or modify it under
the same terms as the Perl 5 programming language system itself.

=cut
