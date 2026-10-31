#!/usr/bin/perl -w

use strict;
use warnings;

use PVE::AccessControl;
use PVE::RPCEnvironment;

my $rpcenv = PVE::RPCEnvironment->init('cli');
$rpcenv->init_request(userconfig => 'host-artifacts-test.cfg');

my $AUDIT_PRIVILEGE = 'Sys.HostArtifacts.Audit';
my $MODIFY_PRIVILEGE = 'Sys.HostArtifacts.Modify';
my $SECRET_PRIVILEGE = 'Sys.HostSecrets.Modify';

sub check_equal {
    my ($label, $got, $expected) = @_;

    die "unexpected result for $label\nneed '${expected}'\ngot '${got}'\n" if $got ne $expected;
    print "OK:$label:$got\n";
}

sub has_permission {
    my ($user, $path, $privilege) = @_;

    my $permissions = $rpcenv->permissions($user, $path);
    return $permissions->{$privilege} ? 1 : 0;
}

for my $privilege ($AUDIT_PRIVILEGE, $MODIFY_PRIVILEGE, $SECRET_PRIVILEGE) {
    die "privilege '$privilege' is not registered\n"
        if !PVE::AccessControl::verify_privname($privilege, 1);
    print "OK:registered:$privilege\n";
}

check_equal('alice audit', has_permission('alice@pve', '/nodes/node1', $AUDIT_PRIVILEGE), 1);
check_equal('alice modify', has_permission('alice@pve', '/nodes/node1', $MODIFY_PRIVILEGE), 1);

check_equal('bob audit', has_permission('bob@pve', '/nodes/node1', $AUDIT_PRIVILEGE), 1);
check_equal('bob modify', has_permission('bob@pve', '/nodes/node1', $MODIFY_PRIVILEGE), 1);
check_equal('bob modify node2', has_permission('bob@pve', '/nodes/node2', $MODIFY_PRIVILEGE), 0);

check_equal(
    'bob audit token audit',
    has_permission('bob@pve!audit', '/nodes/node1', $AUDIT_PRIVILEGE),
    1,
);
check_equal(
    'bob audit token modify',
    has_permission('bob@pve!audit', '/nodes/node1', $MODIFY_PRIVILEGE),
    0,
);

check_equal('carol audit', has_permission('carol@pve', '/nodes/node1', $AUDIT_PRIVILEGE), 1);
check_equal('carol modify', has_permission('carol@pve', '/nodes/node1', $MODIFY_PRIVILEGE), 0);

check_equal('dave audit', has_permission('dave@pve', '/nodes/node1', $AUDIT_PRIVILEGE), 0);
check_equal('dave modify', has_permission('dave@pve', '/nodes/node1', $MODIFY_PRIVILEGE), 0);

check_equal('alice secret', has_permission('alice@pve', '/nodes/node1', $SECRET_PRIVILEGE), 1);
check_equal('bob secret', has_permission('bob@pve', '/nodes/node1', $SECRET_PRIVILEGE), 0);
check_equal('dave secret', has_permission('dave@pve', '/nodes/node1', $SECRET_PRIVILEGE), 0);
check_equal('erin secret', has_permission('erin@pve', '/nodes/node1', $SECRET_PRIVILEGE), 1);
check_equal('erin secret node2', has_permission('erin@pve', '/nodes/node2', $SECRET_PRIVILEGE), 0);
check_equal('erin modify', has_permission('erin@pve', '/nodes/node1', $MODIFY_PRIVILEGE), 0);

print "all tests passed\n";

exit(0);
