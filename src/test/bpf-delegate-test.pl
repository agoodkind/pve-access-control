#!/usr/bin/perl -w

use strict;
use warnings;

use PVE::AccessControl;

sub check_equal {
    my ($label, $got, $expected) = @_;

    die "unexpected result for $label\nneed '${expected}'\ngot '${got}'\n" if $got ne $expected;
    print "OK:$label:$got\n";
}

my $expected_counts = { cmds => 39, maps => 34, progs => 32, attachs => 59 };
for my $kind (@{ PVE::AccessControl::bpf_delegate_kinds() }) {
    my $tokens = PVE::AccessControl::bpf_delegate_tokens($kind);
    check_equal("token count $kind", scalar(@$tokens), $expected_counts->{$kind});
}

my $privileges = PVE::AccessControl::bpf_delegate_privileges();
check_equal('privilege count', scalar(@$privileges), 164);

my $unique = {};
for my $privilege (@$privileges) {
    $unique->{$privilege} = 1;
    die "invalid privilege name '$privilege'\n"
        if $privilege !~ /^VM\.Config\.BPFDelegate\.(Cmd|Map|Prog|Attach)\.[A-Z][A-Za-z0-9]*\z/;
    die "privilege '$privilege' is not registered\n"
        if !PVE::AccessControl::verify_privname($privilege, 1);
}
check_equal('unique privileges', scalar(keys %$unique), scalar(@$privileges));

check_equal(
    'cmd prog_load',
    PVE::AccessControl::bpf_delegate_privilege('cmds', 'prog_load'),
    'VM.Config.BPFDelegate.Cmd.ProgLoad',
);
check_equal(
    'map hash',
    PVE::AccessControl::bpf_delegate_privilege('maps', 'hash'),
    'VM.Config.BPFDelegate.Map.Hash',
);
check_equal(
    'prog sched_cls',
    PVE::AccessControl::bpf_delegate_privilege('progs', 'sched_cls'),
    'VM.Config.BPFDelegate.Prog.SchedCls',
);
check_equal(
    'attach tcx_ingress',
    PVE::AccessControl::bpf_delegate_privilege('attachs', 'tcx_ingress'),
    'VM.Config.BPFDelegate.Attach.TcxIngress',
);

for my $rejected ('any', '0x4', 'unspec', 'prog_run', 'PROG_LOAD', 'bpf_prog_load') {
    eval { PVE::AccessControl::bpf_delegate_privilege('cmds', $rejected) };
    die "name '$rejected' was accepted\n" if !$@;
}

for my $privilege (qw(VM.Guest.Exec VM.Guest.FileRead VM.Guest.FileWrite)) {
    die "privilege '$privilege' is not registered\n"
        if !PVE::AccessControl::verify_privname($privilege, 1);
    print "OK:registered:$privilege\n";
}

print "all tests passed\n";

exit(0);
