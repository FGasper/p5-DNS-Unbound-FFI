#!/usr/bin/env perl

use strict;
use warnings;

use FindBin;
use lib "$FindBin::Bin/../lib";

use DNS::Unbound::FFI;

use Data::Dumper;

use constant NS => 2;

$| = 1;

my $ub = DNS::Unbound::FFI->new();
$ub->debuglevel(1);

$ub->resolve_async('google.com', NS())->then(
    sub { print Dumper( good => shift ) },
    sub { print Dumper( bad => shift ) },
);

$ub->wait();

1;
