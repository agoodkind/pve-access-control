#!/usr/bin/perl -w

use strict;
use warnings;

use PVE::AccessControl;
use PVE::RPCEnvironment;

my $rpcenv = PVE::RPCEnvironment->init('cli');
$rpcenv->init_request(userconfig => 'hostnic-test.cfg');

my $USE_PRIVILEGE = 'Sys.HostNIC.Use';
my $CONFIG_PRIVILEGE = 'VM.Config.HostNIC';

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

for my $privilege ($USE_PRIVILEGE, $CONFIG_PRIVILEGE) {
    die "privilege '$privilege' is not registered\n"
        if !PVE::AccessControl::verify_privname($privilege, 1);
    print "OK:registered:$privilege\n";
}

for my $path (qw(/hostnic /hostnic/nic1v1 /hostnic/a.b-c_d /hostnic/123456789012345)) {
    die "path '$path' was rejected\n" if !PVE::AccessControl::check_path($path);
    print "OK:path:$path\n";
}

for my $path (
    '/hostnic/',
    '/hostnic/a/b',
    '/hostnic/1234567890123456',
    '/hostnic/a b',
    '/hostnic/a:b',
    '/hostnic/.',
    '/hostnic/..',
) {
    die "path '$path' was accepted\n" if PVE::AccessControl::check_path($path);
    print "OK:rejected path:$path\n";
}

check_equal('alice use on nic1v1', has_permission('alice@pve', '/hostnic/nic1v1', $USE_PRIVILEGE), 1);
check_equal('alice use on nic2v1', has_permission('alice@pve', '/hostnic/nic2v1', $USE_PRIVILEGE), 1);
check_equal('alice config', has_permission('alice@pve', '/vms/100', $CONFIG_PRIVILEGE), 1);

check_equal('bob use on nic1v1', has_permission('bob@pve', '/hostnic/nic1v1', $USE_PRIVILEGE), 1);
check_equal('bob use on nic2v1', has_permission('bob@pve', '/hostnic/nic2v1', $USE_PRIVILEGE), 0);
check_equal('bob config on vm 100', has_permission('bob@pve', '/vms/100', $CONFIG_PRIVILEGE), 1);
check_equal('bob config on vm 101', has_permission('bob@pve', '/vms/101', $CONFIG_PRIVILEGE), 0);
check_equal('bob use on vm 100', has_permission('bob@pve', '/vms/100', $USE_PRIVILEGE), 0);

check_equal('carol use', has_permission('carol@pve', '/hostnic/nic1v1', $USE_PRIVILEGE), 0);
check_equal('carol config', has_permission('carol@pve', '/vms/100', $CONFIG_PRIVILEGE), 0);

print "all tests passed\n";

exit(0);
