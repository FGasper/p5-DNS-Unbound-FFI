package DNS::Unbound::FFI;

use strict;
use warnings;

use FFI::Platypus;
use FFI::CheckLib      ();

my $ffi = FFI::Platypus->new;
$ffi->lib(FFI::CheckLib::find_lib_or_die lib => 'unbound');

use Promise::ES6;

my %async_id_callbacks;

$ffi->attach( [ 'ub_ctx_create' => '_ub_ctx_create' ], [] => 'opaque' );

$ffi->attach( ['ub_ctx_delete' => '_ub_ctx_delete'], ['opaque'] => 'void' );

$ffi->attach( ['ub_resolve_free' => '_ub_resolve_free'], ['opaque'] => 'void' );

$ffi->attach(
    [ 'ub_ctx_debuglevel' => '_ub_ctx_debuglevel' ],
    ['opaque', 'int'] => 'int',
);

$ffi->attach( ['ub_wait' => '_ub_wait'], ['opaque'], 'int');

my $async_cb_closure = $ffi->closure(\&_async_callback);

$ffi->attach(
    [ 'ub_resolve_async' => '_ub_resolve_async' ],
    [
        qw/ opaque  string  int  int  opaque /,
        '(opaque,int,opaque)->void', 'int*',
    ],
    'int',
    sub {
        use FFI::Platypus::Buffer;

        my $sub = shift;
        my ($ub_ctx, $qname_in, $qtype_in, $qclass_in) = @_;

        $qclass_in ||= 1;

        my $id = 0;

        my $id_buffer = pack 'L!';
        my $addr = unpack( 'L!', pack('P', $id_buffer));

print "sending request\n";

        my $resint = $sub->($ub_ctx, $qname_in, $qtype_in, $qclass_in, $addr, $async_cb_closure, \$id);
        print STDERR "ub_resolve_async result/id: [$resint][$id]\n";

        my ($y, $n);
        my $promise = Promise::ES6->new( sub { ($y, $n) = @_ } );

        $async_id_callbacks{$id} = [ $y, $n, \$id_buffer ];

        substr( $id_buffer, 0, length($id_buffer), pack 'L!', $id );

        return $promise;
    },
);

sub new {
    my ($class) = @_;

    my $ub = _ub_ctx_create();

    return bless { _ub => $ub }, $class;
}

sub _async_callback {
    my ($data_ptr, $err, $result_ptr) = @_;

    use Data::Dumper;
$Data::Dumper::Useqq = 1;

    my $id = unpack 'L!', buffer_to_scalar($data_ptr, length pack 'L!');

    my $cbs_ar = delete $async_id_callbacks{$id} or do {
        die "No callbacks stored for query ID $id!";
    };

    if ($err) {
        $cbs_ar->[1]->($err);
    }
    else {
        $cbs_ar->[0]->( _parse_result_ptr($result_ptr) );
    }

    _ub_resolve_free($result_ptr);

    return;
}


sub resolve_async {
    my ($self, $qname, $qtype, $qclass) = @_;

    return _ub_resolve_async(
        $self->{'_ub'}, $qname, $qtype, $qclass,
    );
}

sub debuglevel {
    my ($self, $level) = @_;

    _ub_ctx_debuglevel(
        $self->{'_ub'},
        $level,
    );

    return;
}

sub wait {
    my ($self) = @_;

    my $ub = $self->{'_ub'};

    _ub_wait($ub);

    return;
}

sub DESTROY {
    my ($self) = @_;

    _ub_ctx_delete($self->{'_ub'});

    return;
}

#----------------------------------------------------------------------

use constant PACK_TEMPLATE => q<
    p   # qname
    i!  # qtype
    i!  # qclass
    L! #P   # data
    L! #P   # len
    p   # canonname
    i! # rcode
    x![P]
    L! #P   # answer_packet
    i!  # answer_len
    i!  # havedata
    i!  # nxdomain
    i!  # secure
    i!  # bogus
    p   # why_bogus
    i!  # ttl
>;

use constant {
    UB_RESULT_LENGTH => length( pack PACK_TEMPLATE() ),
    INT_LENGTH => length( pack 'i!' ),
};

sub _parse_result_ptr {
    my ($result) = @_;

use Text::Control;
#printf STDERR "result: %d$/", Text::Control::to_hex($result);

        use FFI::Platypus::Memory;

        my $perl_result = buffer_to_scalar($result, UB_RESULT_LENGTH());
#printf STDERR "result2: %s$/", Text::Control::to_hex($perl_result);

        my (
            $qname, $qtype, $qclass,
            $data_p, $lens_p,
            $canonname, $rcode, $answer_packet, $answer_len,
            $havedata, $nxdomain, $secure, $bogus, $why_bogus,
            $ttl
        ) = unpack PACK_TEMPLATE(), $perl_result;
#print "unpacked\n";

#        $qname = _strcpy($qname);
#        $canonname = $canonname ? _strcpy($canonname) : undef;
#        $why_bogus = $why_bogus ? _strcpy($why_bogus) : undef;

        $answer_packet = buffer_to_scalar( $answer_packet, $answer_len );

        my @data;

        {
            my $int_buffer = "\0" x INT_LENGTH();
            my $ptr_buffer = "\0" x length pack 'P';

            my $str_ptr_buffer = "\0" x length pack 'P';

            while (1) {
                $int_buffer = buffer_to_scalar( $lens_p, length $int_buffer );
                $lens_p += length $int_buffer;

                my $len = unpack 'i!', $int_buffer;
                last if !$len;

                $str_ptr_buffer = buffer_to_scalar( $data_p, length $str_ptr_buffer );
                $data_p += length $str_ptr_buffer;

                my $str_ptr = unpack 'L!', $str_ptr_buffer;

                my $datum = buffer_to_scalar( $str_ptr, $len );
                push @data, $datum;
            }
        }

    my @result_parts = (
            $qname, $qtype, $qclass,
            \@data,
            $canonname, $rcode, $answer_packet,
            $havedata, $nxdomain, $secure, $bogus, $why_bogus,
            $ttl
    );

use Data::Dumper;
$Data::Dumper::Useqq = 1;
#print STDERR Dumper( @result_parts );

        return \@result_parts;
}

1;
