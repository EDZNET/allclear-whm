#!/usr/local/cpanel/3rdparty/bin/perl
#WHMADDON:allclear:AllClear (IP unblock)
#ACLS:all
#
# AllClear for WHM - find and unblock an IP across every firewall layer
#
# https://github.com/EDZNET/allclear-whm  (MIT licence)
#
# Search for an IP address across every firewall layer on the server and
# remove it from all of them in one go:
#
#   CSF/LFD (csf.deny + temp bans)   BitNinja (blacklist/greylist)
#   fail2ban                          cPHulk (blacklist + login history)
#   ipset (every set, incl. bitninja-local-incident, heimdall-*, chain_DENY...)
#   iptables / ip6tables (raw rules left behind by anything)
#   native nftables (rules + set elements)
#
# The managers (CSF, BitNinja, ...) are told to unblock first so they don't
# immediately put it back, then the kernel-level state (ipset, iptables, nft)
# is re-scanned and any leftovers are deleted directly.
#
# Also usable from the shell:  allclear search 1.2.3.4
#                              allclear unblock 1.2.3.4 [--ranges]
#
# Every unblock is logged to /var/log/allclear.log.

use strict;
use warnings;

use Socket qw(AF_INET AF_INET6 inet_pton inet_ntop);
use Digest::MD5 ();
use Fcntl qw(O_WRONLY O_APPEND O_CREAT);
use IPC::Open3 ();
use JSON::PP   ();
use POSIX      ();

our $VERSION = '1.3.3';

my $SELF          = 'addon_allclear.cgi';
my $LOG_FILE      = '/var/log/allclear.log';
my $CMD_TIMEOUT   = 60;
my $CSF_ALLOW_TTL = 86400;    # seconds, for the optional "temporarily allow" step

$ENV{PATH} = '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin';

# The IP of whoever is using the tool (WHM: REMOTE_ADDR, shell: SSH_CLIENT).
# Allow entries covering it can't be removed, so you can't lock yourself out.
our $ADMIN_IP;

# cPanel WHM API CLI (used for cPHulk).
my %WHMAPI = ( bin => '/usr/local/cpanel/bin/whmapi1' );
my $HULK_UNBAN = '/usr/local/cpanel/scripts/hulk-unban-ip';

exit( main() ) unless caller;

# ---------------------------------------------------------------------------
# Entry points
# ---------------------------------------------------------------------------

sub main {
    return $ENV{GATEWAY_INTERFACE} ? cgi_main() : cli_main(@ARGV);
}

sub cli_main {
    my @args = @_;
    if ( $> != 0 ) { print STDERR "Must be run as root.\n"; return 1; }
    my ( $action, $ipstr, @ids ) = grep { !/^--/ } @args;
    my %opt = map { $_ => 1 } map { /^--(.+)$/ ? $1 : () } @args;
    $ADMIN_IP = parse_ip( ( split ' ', ( $ENV{SSH_CLIENT} // '' ) )[0] );
    if ( !$action || !$ipstr || $action !~ /^(search|unblock|remove)$/ || ( $action eq 'remove' && !@ids ) ) {
        print "Usage: $0 search  <ip>\n"
          . "       $0 unblock <ip> [--ranges] [--csf-allow] [--bitninja-whitelist]\n"
          . "       $0 remove  <ip> <id> [<id> ...]   remove only these entries (ids from search), allow entries included\n"
          . "  --ranges               also delete CIDR/range entries that contain the IP\n"
          . "  --csf-allow            temporarily allow the IP in CSF for ${\ ($CSF_ALLOW_TTL/3600)}h afterwards\n"
          . "  --bitninja-whitelist   add the IP to the BitNinja whitelist afterwards\n";
        return 2;
    }
    my $ip = parse_ip($ipstr) or do { print STDERR "Not a valid IPv4/IPv6 address: $ipstr\n"; return 2; };
    my $opts = {
        ranges             => $opt{ranges}               ? 1 : 0,
        csf_allow          => $opt{'csf-allow'}          ? 1 : 0,
        bitninja_whitelist => $opt{'bitninja-whitelist'} ? 1 : 0,
    };

    if ( $action eq 'unblock' || $action eq 'remove' ) {
        my $who     = 'cli:' . ( getpwuid($<) // $< ) . ( $ADMIN_IP ? "\@$ADMIN_IP->{str}" : '' );
        my $actions = $action eq 'remove' ? remove_selected( $ip, \@ids, $who, $ADMIN_IP ) : unblock_all( $ip, $opts, $who );
        print "== Actions ==\n";
        for my $a (@$actions) {
            printf "[%s] %s\n    $ %s\n", ( $a->{ok} ? ' ok ' : 'FAIL' ), $a->{step}, $a->{cmd};
            print map { "    | $_\n" } grep { length } split /\n/, $a->{out} if length( $a->{out} // '' );
        }
        print "\n== Remaining after $action ==\n";
    }
    for my $s ( scan_all($ip) ) {
        my $status = !$s->{available} ? 'not installed' : $s->{error} ? 'ERROR' : $s->{found} ? 'FOUND' : 'clear';
        printf "%-28s %s\n", $s->{title}, $status;
        print "    ! $s->{error}\n" if $s->{error};
        for my $it ( @{ $s->{items} } ) {
            my $note = join ', ', grep { length } ( $it->{note} // '' ), ( locks_out( $it, $ip, $ADMIN_IP ) ? 'covers your own IP, protected' : '' );
            printf "    %-14s %s%s\n", ( $it->{id} ? "[$it->{id}]" : '' ), $it->{desc}, ( $note ? "  [$note]" : '' );
        }
    }
    print "\nRemove single entries with: allclear remove $ip->{str} <id> [<id> ...]\n";
    return 0;
}

sub cgi_main {
    my $whm = eval {
        unshift @INC, '/usr/local/cpanel';
        require Whostmgr::ACLS;
        require Whostmgr::HTMLInterface;
        1;
    };

    print "Content-type: text/html; charset=utf-8\r\n";
    print "X-Frame-Options: SAMEORIGIN\r\n\r\n";

    if ($whm) {
        Whostmgr::ACLS::init_acls();
        if ( !Whostmgr::ACLS::hasroot() ) {
            print "<p>Access denied: this plugin requires root (all ACLs).</p>";
            return 0;
        }
    }
    else {
        # Fail closed: without the WHM ACL modules we can't tell who is asking.
        print "<p>Access denied: could not load the WHM ACL modules.</p>";
        return 0;
    }

    $| = 1;
    $ADMIN_IP = parse_ip( $ENV{REMOTE_ADDR} );
    my $form   = read_form();
    my $action = $form->{action} // '';
    my $ipstr  = $form->{ip}     // '';
    $ipstr =~ s/^\s+|\s+$//g;
    my $ip;
    my $error;
    if ( length $ipstr ) {
        $ip = parse_ip($ipstr) or $error = "\"$ipstr\" is not a valid IPv4 or IPv6 address.";
    }
    my $opts = {
        ranges             => $form->{ranges}             ? 1 : 0,
        csf_allow          => $form->{csf_allow}          ? 1 : 0,
        bitninja_whitelist => $form->{bitninja_whitelist} ? 1 : 0,
    };

    my $hdr_ok = $whm && eval { Whostmgr::HTMLInterface::defheader( 'AllClear (IP unblock)', '', "/cgi/$SELF" ); 1 };
    print "<!DOCTYPE html><html><head><title>AllClear</title></head><body>" unless $hdr_ok;
    print page_css();
    print page_js();
    print qq{<div class="allc">};
    print brand_bar();
    print qq{<h1>AllClear <small>search and remove an IP from every firewall layer &middot; v$VERSION</small></h1>} unless $hdr_ok;

    print search_form( $ipstr, $opts );
    print qq{<div class="allc-msg allc-bad">} . h($error) . "</div>" if $error;

    if ( $ip && ( $action eq 'unblock' || $action eq 'remove' ) && ( $ENV{REQUEST_METHOD} // '' ) ne 'POST' ) {
        print qq{<div class="allc-msg allc-bad">Changes must be submitted as a POST.</div>};
    }
    elsif ( $ip && $action eq 'remove' ) {
        my $who     = ( $ENV{REMOTE_USER} // 'whm' ) . '@' . ( $ENV{REMOTE_ADDR} // '?' );
        my @ids     = map { /^sel_([0-9a-f]{12})$/ ? $1 : () } grep { $form->{$_} } keys %$form;
        my $actions = remove_selected( $ip, \@ids, $who, $ADMIN_IP );
        print render_actions($actions);
        print qq{<h2>State after removal</h2><div id="allc-wait" class="allc-loading allc-on"><span class="allc-spin"></span> Re-scanning all firewall layers&hellip;</div>};
        print safe_scan( $ip, $opts, 1 );
        print qq{<style>#allc-wait{display:none}</style>};
    }
    elsif ( $ip && $action eq 'unblock' ) {
        my $who     = ( $ENV{REMOTE_USER} // 'whm' ) . '@' . ( $ENV{REMOTE_ADDR} // '?' );
        my $actions = unblock_all( $ip, $opts, $who );
        print render_actions($actions);
        print qq{<h2>State after unblock</h2><div id="allc-wait" class="allc-loading allc-on"><span class="allc-spin"></span> Re-scanning all firewall layers&hellip;</div>};
        print safe_scan( $ip, $opts, 0 );
        print qq{<style>#allc-wait{display:none}</style>};
    }
    elsif ($ip) {
        print qq{<div id="allc-wait" class="allc-loading allc-on"><span class="allc-spin"></span> Searching all firewall layers&hellip; this can take up to a minute.</div>};
        print safe_scan( $ip, $opts, 1 );
        print qq{<style>#allc-wait{display:none}</style>};
    }

    print "</div>";
    my $ftr_ok = $hdr_ok && eval { Whostmgr::HTMLInterface::deffooter(); 1 };
    print "</body></html>" unless $ftr_ok;
    return 0;
}

# ---------------------------------------------------------------------------
# Scanning
# ---------------------------------------------------------------------------

# Every scanner returns:
#   { key, title, available, found, error, raw, items => [ { desc, note, removable, exact } ] }

sub scan_all {
    my ($ip) = @_;
    my $ipt = $ip->{fam} == 4 ? 'iptables' : 'ip6tables';
    return (
        scan_csf($ip),
        scan_bitninja($ip),
        scan_fail2ban($ip),
        scan_cphulk($ip),
        scan_ipset($ip),
        scan_iptables( $ip, $ipt ),
        scan_nft($ip),
    );
}

# Items that can be removed one by one carry `actions` (and optionally `pre`,
# manager commands run before the kernel re-scan). Each gets a short id derived
# from its section and description, so the same entry has the same id on the
# next scan. Selective removal only acts on ids found again by a fresh scan.
sub section {
    my (%s) = @_;
    $s{items} ||= [];
    for my $it ( @{ $s{items} } ) {
        next unless $it->{actions} && @{ $it->{actions} };
        $it->{id} = substr( Digest::MD5::md5_hex("$s{key}|$it->{desc}"), 0, 12 );
    }
    $s{found} = ( grep { !$_->{allow} } @{ $s{items} } ) ? 1 : 0 unless defined $s{found};
    return \%s;
}

sub scan_csf {
    my ($ip) = @_;
    my $csf = which('csf') or return section( key => 'csf', title => 'CSF / LFD', available => 0 );
    my ( $rc, $out ) = run( $csf, '-g', $ip->{str} );
    my $re = ip_regex($ip);
    my @items;
    for my $line ( split /\n/, $out ) {
        next unless $line =~ $re;
        next if $line =~ /No matches found/i;
        $line =~ s/\s+$//;
        my $allow = $line =~ /\bACCEPT\b|Temporary Allows|csf\.allow|csf\.ignore|ALLOW|whitelist/i ? 1 : 0;
        my %it = ( desc => $line, allow => $allow, note => ( $allow ? 'allow entry' : '' ) );
        if ( $line =~ /^\s*IPSET:/i ) {
            $it{note} = join ', ', grep { length } $it{note}, 'see the ipset section';
        }
        elsif ( $line =~ /csf\.ignore/i ) {
            $it{note} = 'csf.ignore entry, edit /etc/csf/csf.ignore by hand';
        }
        elsif ($allow) {
            $it{actions} = [ [ 'CSF: remove from allow list', $csf, '-ar', $ip->{str} ], [ 'CSF: remove temporary allow', $csf, '-tr', $ip->{str} ] ];
        }
        else {
            $it{actions} = [ [ 'CSF: remove permanent deny', $csf, '-dr', $ip->{str} ], [ 'CSF: remove temporary deny', $csf, '-trd', $ip->{str} ] ];
        }
        push @items, \%it;
    }
    return section(
        key       => 'csf',
        title     => 'CSF / LFD',
        available => 1,
        items     => \@items,
        raw       => $out,
        note      => 'csf -g output. csf -dr / -trd only remove exact-IP entries, CIDR lines in csf.deny must be edited by hand.',
    );
}

sub scan_bitninja {
    my ($ip) = @_;
    my $bn = which('bitninjacli') or return section( key => 'bitninja', title => 'BitNinja', available => 0 );
    # bitninjacli has no reliable "is this IP listed" query; BitNinja enforces
    # everything through its ipsets, so report those here.
    my $ipset = scan_ipset($ip);
    my @items = map { +{ %$_, removable => 0, dup => 1, actions => undef, pre => undef, id => undef, note => ( $_->{allow} ? "BitNinja whitelist, select it in the ipset section to remove" : "removed in the ipset step" ) } }
      grep { $_->{set} =~ /^(?:bitninja|heimdall)/i } @{ $ipset->{items} };
    return section(
        key       => 'bitninja',
        title     => 'BitNinja',
        available => 1,
        items     => \@items,
        note      => 'Unblock runs bitninjacli --blacklist --del and --greylist --del, then the bitninja-* ipsets are cleaned directly.',
    );
}

sub scan_fail2ban {
    my ($ip) = @_;
    my $f2b = which('fail2ban-client') or return section( key => 'fail2ban', title => 'fail2ban', available => 0 );
    my ( $rc, $out ) = run( $f2b, 'status' );
    return section( key => 'fail2ban', title => 'fail2ban', available => 1, error => 'fail2ban server not running' ) if $rc;
    my ($jails) = $out =~ /Jail list:\s*(.*)/;
    my @items;
    my $re = ip_regex($ip);
    for my $jail ( grep { length } split /[,\s]+/, ( $jails // '' ) ) {
        my ( $jrc, $jout ) = run( $f2b, 'status', $jail );
        my ($banned) = $jout =~ /Banned IP list:\s*(.*)/;
        push @items, { desc => "jail $jail", removable => 1, actions => [ [ "fail2ban: unban from jail $jail", $f2b, 'set', $jail, 'unbanip', $ip->{str} ] ] }
          if defined $banned && $banned =~ $re;
    }
    return section( key => 'fail2ban', title => 'fail2ban', available => 1, items => \@items );
}

sub scan_cphulk {
    my ($ip) = @_;
    return section( key => 'cphulk', title => 'cPHulk', available => 0 ) unless -x $WHMAPI{bin};
    my $re = ip_regex($ip);
    my @items;
    my $flush = [ 'cPHulk: flush login history / brute blocks', $WHMAPI{bin}, 'flush_cphulk_login_history_for_ips', "ip=$ip->{str}" ];
    my %calls = (
        'blacklist'              => [ [ 'read_cphulk_records', 'list_name=black' ], [ 'cPHulk: remove from blacklist', $WHMAPI{bin}, 'delete_cphulk_record', 'list_name=black', "ip=$ip->{str}" ] ],
        'whitelist'              => [ [ 'read_cphulk_records', 'list_name=white' ], [ 'cPHulk: remove from whitelist', $WHMAPI{bin}, 'delete_cphulk_record', 'list_name=white', "ip=$ip->{str}" ] ],
        'brute-force blocks'     => [ ['get_cphulk_brutes'],           $flush ],
        'excessive brute blocks' => [ ['get_cphulk_excessive_brutes'], $flush ],
        'failed logins'          => [ ['get_cphulk_failed_logins'],    $flush ],
    );
    for my $label ( sort keys %calls ) {
        my ( $call, $action ) = @{ $calls{$label} };
        my ( $rc, $out ) = run( $WHMAPI{bin}, @$call, '--output=json' );
        next if $rc;
        next unless $out =~ $re;
        my $allow = $label eq 'whitelist' ? 1 : 0;
        push @items, {
            desc      => "listed in cPHulk $label",
            removable => $allow ? 0 : 1,
            allow     => $allow,
            list      => $label,
            cphulk_flush => ( $action == $flush ? 1 : 0 ),
            note      => ( $allow ? 'allow list, skipped by Unblock everywhere' : '' ),
            actions   => [$action],
        };
    }
    return section(
        key       => 'cphulk',
        title     => 'cPHulk',
        available => 1,
        items     => \@items,
        note      => 'cPHulk firewall-level blocks also show up in the iptables section.',
    );
}

sub scan_ipset {
    my ($ip) = @_;
    my $ipset = which('ipset') or return section( key => 'ipset', title => 'ipset', available => 0 );
    my ( $rc, $out ) = run( $ipset, 'save' );
    return section( key => 'ipset', title => 'ipset', available => 1, error => first_line($out) ) if $rc;

    my ( %fam, %type, @items );
    for my $line ( split /\n/, $out ) {
        if ( $line =~ /^create (\S+) (\S+)(.*)$/ ) {
            my ( $name, $type, $rest ) = ( $1, $2, $3 );
            $type{$name} = $type;
            $fam{$name}  = $rest =~ /\bfamily inet6\b/ ? 6 : 4;
            next;
        }
        next unless $line =~ /^add (\S+) (\S+)/;
        my ( $set, $entry ) = ( $1, $2 );
        next if ( $type{$set} // '' ) eq 'list:set';
        next if ( $fam{$set} // 4 ) != $ip->{fam};
        for my $part ( split /,/, $entry ) {
            my $net = parse_net($part) or next;
            next unless net_contains( $net, $ip );
            my $timeout = $line =~ /\btimeout (\d+)/ ? $1 : undef;
            my $allow   = is_allow_name($set);
            # BitNinja's sets: tell BitNinja first so it doesn't re-add the entry.
            my @pre;
            if ( $set =~ /^(?:bitninja|heimdall)/i && ( my $bn = which('bitninjacli') ) ) {
                @pre = $allow
                  ? ( [ 'BitNinja: remove from whitelist', $bn, '--whitelist', "--del=$ip->{str}" ] )
                  : ( [ 'BitNinja: remove from blacklist', $bn, '--blacklist', "--del=$ip->{str}" ], [ 'BitNinja: remove from greylist', $bn, '--greylist', "--del=$ip->{str}" ] );
            }
            push @items, {
                set       => $set,
                entry     => $entry,
                net       => $net,
                exact     => $net->{single},
                removable => $allow ? 0 : 1,
                allow     => $allow,
                desc      => "Set:$set Match:$entry" . ( $type{$set} ? " ($type{$set})" : '' ),
                note      => join( ', ', ( $allow ? 'allow list, skipped by Unblock everywhere' : () ), ( $net->{single} ? () : 'range containing the IP' ), ( defined $timeout ? "expires in ${timeout}s" : () ) ),
                pre       => \@pre,
                actions   => [ [ "ipset: delete from $set", $ipset, 'del', $set, $entry ] ],
            };
            last;
        }
    }
    return section( key => 'ipset', title => 'ipset', available => 1, items => \@items );
}

sub scan_iptables {
    my ( $ip, $cmd ) = @_;
    my $title = $cmd;
    my $save  = which("$cmd-save") or return section( key => $cmd, title => $title, available => 0 );
    my ( $rc, $out ) = run($save);
    return section( key => $cmd, title => $title, available => 1, error => first_line($out) ) if $rc;

    my ( $table, @items );
    for my $line ( split /\n/, $out ) {
        if ( $line =~ /^\*(\S+)/ ) { $table = $1; next; }
        next unless $line =~ /^-A \S+ /;
        my @tok = shell_split($line) or next;
        shift @tok;
        my $chain = shift @tok;
        my ( $hit, $target );
        for my $i ( 0 .. $#tok ) {
            my $t = $tok[$i];
            $target = $tok[ $i + 1 ] if $t =~ /^(?:-j|--jump|-g|--goto)$/;
            next unless $t =~ /^(?:-s|--source|--src|-d|--destination|--dst|--src-range|--dst-range)$/;
            next if $i > 0 && $tok[ $i - 1 ] eq '!';
            for my $v ( split /,/, ( $tok[ $i + 1 ] // '' ) ) {
                my $net = parse_net($v) or next;
                if ( net_contains( $net, $ip ) ) { $hit = $net; last; }
            }
        }
        next unless $hit;
        # Only blocking targets count. ACCEPT/RETURN, non-terminating targets
        # (LOG, MARK, ...) and jumps to allow-named chains are left alone.
        my $passive  = !defined $target || $target =~ /^(?:LOG|NFLOG|ULOG|MARK|CONNMARK|CT|NOTRACK|TRACE|AUDIT)$/;
        my $is_block = !$passive
          && $target !~ /^(?:ACCEPT|RETURN)$/
          && !is_allow_name($target)
          && !is_allow_name($chain);
        my $bin = which($cmd);
        push @items, {
            table     => $table,
            chain     => $chain,
            args      => \@tok,
            net       => $hit,
            exact     => $hit->{single},
            removable => $is_block ? 1 : 0,
            allow     => $is_block ? 0 : 1,
            desc      => "-t $table $line",
            note      => join( ', ', ( $passive ? 'not a block or allow rule, left alone' : $is_block ? () : 'allow rule, skipped by Unblock everywhere' ), ( $hit->{single} ? () : 'range containing the IP' ) ),
            # Logging/marking rules are never offered for removal.
            actions   => ( $passive || !$bin ? undef : [ [ "$cmd: delete rule in $table/$chain", $bin, '-w', '-t', $table, '-D', $chain, @tok ] ] ),
        };
    }
    return section( key => $cmd, title => $title, available => 1, items => \@items );
}

sub iptables_is_nft {
    my $ipt = which('iptables') or return 0;
    my ( $rc, $out ) = run( $ipt, '-V' );
    return $out =~ /nf_tables/ ? 1 : 0;
}

sub scan_nft {
    my ($ip) = @_;
    my $nft = which('nft') or return section( key => 'nft', title => 'nftables (native)', available => 0 );
    my ( $rc, $out ) = run( $nft, '-j', 'list', 'ruleset' );
    return section( key => 'nft', title => 'nftables (native)', available => 1, error => first_line($out) ) if $rc;
    my $data = eval { JSON::PP->new->decode($out) }
      or return section( key => 'nft', title => 'nftables (native)', available => 1, error => 'could not parse nft JSON output' );

    # When iptables is the nf_tables backend its tables are already covered by
    # the iptables section; don't report (or delete) them twice.
    my $compat = iptables_is_nft();
    my %compat_tbl = map { $_ => 1 } qw(filter nat mangle raw security);
    my $skip = sub { my $o = shift; $compat && ( $o->{family} // '' ) =~ /^(?:ip|ip6)$/ && $compat_tbl{ $o->{table} // '' } };

    my @items;
    for my $obj ( @{ $data->{nftables} || [] } ) {
        if ( my $set = $obj->{set} ) {
            next if $skip->($set);
            for my $el ( @{ $set->{elem} || [] } ) {
                my $v = ( ref $el eq 'HASH' && $el->{elem} ) ? $el->{elem}{val} : $el;
                my $str = nft_value_str($v) // next;
                my $net = parse_net($str) or next;
                next unless net_contains( $net, $ip );
                my $allow = is_allow_name( $set->{name} );
                push @items, {
                    kind      => 'set',
                    family    => $set->{family},
                    table     => $set->{table},
                    name      => $set->{name},
                    elem      => $str,
                    net       => $net,
                    exact     => $net->{single},
                    removable => $allow ? 0 : 1,
                    allow     => $allow,
                    desc      => "set $set->{family} $set->{table} $set->{name}: $str",
                    note      => join( ', ', ( $allow ? 'allow list, skipped by Unblock everywhere' : () ), ( $net->{single} ? () : 'range containing the IP' ) ),
                    actions   => [ [ "nft: delete element from set $set->{table}/$set->{name}", $nft, 'delete', 'element', $set->{family}, $set->{table}, $set->{name}, '{', $str, '}' ] ],
                };
            }
        }
        elsif ( my $rule = $obj->{rule} ) {
            next if $skip->($rule);
            my @vals;
            nft_collect( $rule->{expr}, \@vals );
            my $hit;
            for my $v (@vals) {
                my $net = parse_net($v) or next;
                if ( net_contains( $net, $ip ) ) { $hit = $net; last; }
            }
            next unless $hit;
            my $json     = JSON::PP->new->canonical->encode( $rule->{expr} // [] );
            my $is_block = $json =~ /"(?:drop|reject)"/ && $json !~ /"accept"/;
            my $is_allow = !$is_block && $json =~ /"accept"/;
            push @items, {
                kind      => 'rule',
                family    => $rule->{family},
                table     => $rule->{table},
                chain     => $rule->{chain},
                handle    => $rule->{handle},
                net       => $hit,
                exact     => $hit->{single},
                removable => $is_block ? 1 : 0,
                allow     => $is_block ? 0 : 1,
                desc      => "rule $rule->{family} $rule->{table} $rule->{chain} handle $rule->{handle}: " . ( length $json > 300 ? substr( $json, 0, 300 ) . '...' : $json ),
                note      => join( ', ', ( $is_block ? () : $is_allow ? 'allow rule, skipped by Unblock everywhere' : 'not a drop/reject rule, left alone' ), ( $hit->{single} ? () : 'range containing the IP' ) ),
                # Only drop/reject and accept rules can be removed one by one.
                actions   => ( $is_block || $is_allow ? [ [ "nft: delete rule $rule->{table}/$rule->{chain}", $nft, 'delete', 'rule', $rule->{family}, $rule->{table}, $rule->{chain}, 'handle', $rule->{handle} ] ] : undef ),
            };
        }
    }
    return section( key => 'nft', title => 'nftables (native)', available => 1, items => \@items );
}

sub nft_value_str {
    my ($v) = @_;
    return $v unless ref $v;
    if ( ref $v eq 'HASH' ) {
        return "$v->{prefix}{addr}/$v->{prefix}{len}" if $v->{prefix} && !ref $v->{prefix}{addr};
        return "$v->{range}[0]-$v->{range}[1]"        if ref $v->{range} eq 'ARRAY' && !ref $v->{range}[0];
    }
    return;
}

sub nft_collect {
    my ( $node, $out ) = @_;
    return unless defined $node;
    if ( !ref $node ) { push @$out, $node; return; }
    if ( ref $node eq 'ARRAY' ) { nft_collect( $_, $out ) for @$node; return; }
    if ( ref $node eq 'HASH' ) {
        my $s = nft_value_str($node);
        if ( defined $s ) { push @$out, $s; return; }
        nft_collect( $_, $out ) for values %$node;
    }
}

# ---------------------------------------------------------------------------
# Unblocking
# ---------------------------------------------------------------------------

# Returns a closure that runs ( step, cmd... ), logs it and records the result
# in @$actions. Identical commands are only run once per request.
sub action_runner {
    my ( $ip, $who, $actions ) = @_;
    my %done;
    return sub {
        my ( $step, @cmd ) = @_;
        my $cmdstr = join( ' ', map { /[\s"'{}]/ ? "'$_'" : $_ } @cmd );
        return if $done{$cmdstr}++;
        my ( $rc, $out ) = run(@cmd);
        my $ok = $rc == 0 ? 1 : 0;
        # whmapi1 exits 0 even when the call is refused; the result is in the output.
        $ok = 0 if $ok && $cmd[0] eq $WHMAPI{bin} && whmapi_failed($out);
        my $a = { step => $step, cmd => $cmdstr, rc => $rc, ok => $ok, out => $out };
        push @$actions, $a;
        audit( $who, $ip->{str}, $a );
        return $a;
    };
}

# whmapi1 YAML: "metadata: result: 0" for API failures, or the legacy
# "status: 0 / statusmsg: Permission Denied: ..." when the call is refused.
sub whmapi_failed {
    my ($out) = @_;
    return 1 if ( $out // '' ) =~ /^\s*(?:result|status):\s*0\s*$/m;
    return 0;
}

# Flush cPHulk's login history (brute / excessive brute blocks) for the IP. Some
# servers refuse the API call (seen on DNSONLY), so fall back to cPanel's own
# unban script when the API doesn't do it.
sub cphulk_flush {
    my ( $do, $ip ) = @_;
    my $a = $do->( 'cPHulk: flush login history / brute blocks', $WHMAPI{bin}, 'flush_cphulk_login_history_for_ips', "ip=$ip->{str}" );
    return if !$a || $a->{ok} || !-x $HULK_UNBAN;
    $do->( 'cPHulk: unban with hulk-unban-ip (API call was refused)', $HULK_UNBAN, $ip->{str} );
}

sub kernel_scans {
    my ($ip) = @_;
    return ( scan_ipset($ip), scan_iptables( $ip, $ip->{fam} == 4 ? 'iptables' : 'ip6tables' ), scan_nft($ip) );
}

# Would removing this allow entry take away the allow for the admin's own IP?
sub locks_out {
    my ( $it, $ip, $admin ) = @_;
    return 0 unless $admin && $it->{allow};
    return net_contains( $it->{net}, $admin ) if $it->{net};
    return $ip->{str} eq $admin->{str} ? 1 : 0;
}

# Removes only the entries the user ticked. The ids are matched against a fresh
# scan, so a request can only remove entries the server itself finds for this IP.
sub remove_selected {
    my ( $ip, $ids, $who, $admin ) = @_;
    my @actions;
    my $do = action_runner( $ip, $who, \@actions );
    my %want = map { $_ => 1 } grep { /^[0-9a-f]{12}$/ } @$ids;
    return [ { step => 'Nothing selected', cmd => '-', ok => 0, rc => '-', out => '' } ] unless %want;

    audit( $who, $ip->{str}, { step => 'remove selected requested', cmd => '-', rc => 0, out => join( ',', sort keys %want ) } );

    my %found = map { $_->{id} => $_ } grep { $_->{id} } map { @{ $_->{items} } } scan_all($ip);
    my %kernel;
    for my $id ( sort keys %want ) {
        my $it = $found{$id};
        if ( !$it ) {
            push @actions, { step => "Entry $id is no longer present", cmd => '-', ok => 1, out => '' };
            next;
        }
        if ( locks_out( $it, $ip, $admin ) ) {
            my $a = { step => "Refused: removing this allow entry would drop the allow for your own IP ($admin->{str})", cmd => $it->{desc}, ok => 0, rc => '-', out => '' };
            push @actions, $a;
            audit( $who, $ip->{str}, $a );
            next;
        }
        # 1. Managers (and BitNinja's own whitelist/blacklist for its ipsets) first.
        $do->(@$_) for @{ $it->{pre} || [] };
        if    ( $it->{set} || $it->{table} ) { $kernel{$id} = 1 }
        elsif ( $it->{cphulk_flush} )        { cphulk_flush( $do, $ip ) }
        else                                 { $do->(@$_) for @{ $it->{actions} } }
    }

    # 2. Kernel entries: re-scan, then delete the selected ones that are still there.
    if (%kernel) {
        my %now = map { $_->{id} => $_ } grep { $_->{id} } map { @{ $_->{items} } } kernel_scans($ip);
        for my $id ( sort keys %kernel ) {
            if ( my $it = $now{$id} ) { $do->(@$_) for @{ $it->{actions} } }
            else { push @actions, { step => "Entry $id was already removed by its manager", cmd => '-', ok => 1, out => '' } }
        }
    }
    return \@actions;
}

sub unblock_all {
    my ( $ip, $opts, $who ) = @_;
    my @actions;
    my $do = action_runner( $ip, $who, \@actions );
    my $want = sub { my $it = shift; $it->{removable} && ( $it->{exact} || $opts->{ranges} ) };

    audit( $who, $ip->{str}, { step => 'unblock requested', cmd => '-', rc => 0, out => join( ',', grep { $opts->{$_} } sort keys %$opts ) } );

    # 1. Firewall managers first, so they don't re-add what we remove below.
    if ( my $csf = which('csf') ) {
        $do->( 'CSF: remove permanent deny', $csf, '-dr',  $ip->{str} );
        $do->( 'CSF: remove temporary deny', $csf, '-trd', $ip->{str} );
    }
    if ( my $bn = which('bitninjacli') ) {
        $do->( 'BitNinja: remove from blacklist', $bn, '--blacklist', "--del=$ip->{str}" );
        $do->( 'BitNinja: remove from greylist',  $bn, '--greylist',  "--del=$ip->{str}" );
    }
    if ( my $f2b = which('fail2ban-client') ) {
        my $s = scan_fail2ban($ip);
        $do->( 'fail2ban: unban from all jails', $f2b, 'unban', $ip->{str} ) if $s->{found};
    }
    if ( -x $WHMAPI{bin} ) {
        my $s = scan_cphulk($ip);
        if ( grep { ( $_->{list} // '' ) eq 'blacklist' } @{ $s->{items} } ) {
            $do->( 'cPHulk: remove from blacklist', $WHMAPI{bin}, 'delete_cphulk_record', 'list_name=black', "ip=$ip->{str}" );
        }
        cphulk_flush( $do, $ip ) if $s->{found};
    }

    # 2. Kernel state, freshly re-scanned after the managers have had their go.
    for my $s ( kernel_scans($ip) ) {
        for my $it ( grep { $want->($_) } @{ $s->{items} } ) {
            $do->(@$_) for @{ $it->{actions} || [] };
        }
    }

    # 3. Optional: stop it being re-blocked straight away.
    if ( $opts->{csf_allow} && ( my $csf = which('csf') ) ) {
        $do->( "CSF: temporary allow for ${\ ($CSF_ALLOW_TTL/3600)}h", $csf, '-ta', $ip->{str}, $CSF_ALLOW_TTL, "Unblocked via AllClear by $who" );
    }
    if ( $opts->{bitninja_whitelist} && ( my $bn = which('bitninjacli') ) ) {
        $do->( 'BitNinja: add to whitelist', $bn, '--whitelist', "--add=$ip->{str}" );
    }

    push @actions, { step => 'Nothing to do: no firewall tools found', cmd => '-', ok => 1, out => '' } unless @actions;
    return \@actions;
}

# ---------------------------------------------------------------------------
# IP / network helpers
# ---------------------------------------------------------------------------

sub parse_ip {
    my ($s) = @_;
    return unless defined $s;
    $s =~ s/^\s+|\s+$//g;
    if ( $s =~ /^\d{1,3}(?:\.\d{1,3}){3}$/ ) {
        my $p = inet_pton( AF_INET, $s );
        return { fam => 4, bin => $p, str => inet_ntop( AF_INET, $p ) } if defined $p;
    }
    elsif ( $s =~ /:/ && $s =~ /^[0-9A-Fa-f:.]+$/ ) {
        my $p = inet_pton( AF_INET6, $s );
        return { fam => 6, bin => $p, str => inet_ntop( AF_INET6, $p ) } if defined $p;
    }
    return;
}

# "addr", "addr/len" or "lo-hi" -> { fam, lo, hi, single }
sub parse_net {
    my ($s) = @_;
    return unless defined $s && length $s;
    if ( $s =~ m{^([^/]+)/(\d{1,3})$} ) {
        # scalar: parse_ip returns an empty list on failure, which would slide the
        # prefix length into $ip ("Can't use string ("1") as a HASH ref").
        my ( $ip, $len ) = ( scalar parse_ip($1), $2 );
        return unless $ip;
        my $max = $ip->{fam} == 4 ? 32 : 128;
        return if $len > $max;
        my $bits = substr( unpack( 'B*', $ip->{bin} ), 0, $len );
        return {
            fam    => $ip->{fam},
            lo     => pack( 'B*', $bits . ( '0' x ( $max - $len ) ) ),
            hi     => pack( 'B*', $bits . ( '1' x ( $max - $len ) ) ),
            single => $len == $max ? 1 : 0,
        };
    }
    if ( $s =~ /^([^-]+)-([^-]+)$/ ) {
        my ( $lo, $hi ) = ( scalar parse_ip($1), scalar parse_ip($2) );
        return unless $lo && $hi && $lo->{fam} == $hi->{fam};
        return { fam => $lo->{fam}, lo => $lo->{bin}, hi => $hi->{bin}, single => ( $lo->{bin} eq $hi->{bin} ? 1 : 0 ) };
    }
    my $ip = parse_ip($s) or return;
    return { fam => $ip->{fam}, lo => $ip->{bin}, hi => $ip->{bin}, single => 1 };
}

sub net_contains {
    my ( $net, $ip ) = @_;
    return $net->{fam} == $ip->{fam} && $ip->{bin} ge $net->{lo} && $ip->{bin} le $net->{hi};
}

# Set / chain names that look like allow lists. Entries in these are never deleted.
sub is_allow_name {
    my ($name) = @_;
    return ( $name // '' ) =~ /white|allow|trust|ignore|accept/i ? 1 : 0;
}

# Matches the IP as a whole token (so 1.2.3.4 doesn't match 11.2.3.45).
sub ip_regex {
    my ($ip) = @_;
    my $q = quotemeta $ip->{str};
    return $ip->{fam} == 4 ? qr/(?<![\d.])$q(?![\d])(?!\.\d)/ : qr/(?<![0-9A-Fa-f:])$q(?![0-9A-Fa-f:])/i;
}

# ---------------------------------------------------------------------------
# Process / misc helpers
# ---------------------------------------------------------------------------

sub which {
    my ($name) = @_;
    for my $d ( split /:/, $ENV{PATH} ) {
        return "$d/$name" if -f "$d/$name" && -x _;
    }
    return;
}

# Runs a command without a shell; returns (exit code, stdout+stderr).
sub run {
    my (@cmd) = @_;
    my ( $in, $out, $pid );
    my $buf = '';
    my $rc  = eval {
        local $SIG{ALRM} = sub { die "timeout\n" };
        alarm $CMD_TIMEOUT;
        $pid = IPC::Open3::open3( $in, $out, undef, @cmd );
        close $in;
        local $/;
        $buf = <$out> // '';
        waitpid( $pid, 0 );
        alarm 0;
        $? >> 8;
    };
    if ( !defined $rc ) {
        my $err = $@ || 'unknown error';
        alarm 0;
        if ( $pid && $err eq "timeout\n" ) { kill 'KILL', $pid; waitpid( $pid, 0 ); }
        chomp $err;
        return ( 255, $buf . "[$err]" );
    }
    return ( $rc, $buf );
}

sub shell_split {
    my ($s) = @_;
    my ( @out, $cur );
    while ( length $s ) {
        if ( $s =~ s/^\s+// ) { push @out, $cur if defined $cur; undef $cur; next; }
        if ( $s =~ s/^"((?:[^"\\]|\\.)*)"// ) { ( my $q = $1 ) =~ s/\\(.)/$1/g; $cur = ( $cur // '' ) . $q; next; }
        if ( $s =~ s/^'([^']*)'// )           { $cur = ( $cur // '' ) . $1; next; }
        if ( $s =~ s/^\\(.)// )               { $cur = ( $cur // '' ) . $1; next; }
        if ( $s =~ s/^([^\s"'\\]+)// )        { $cur = ( $cur // '' ) . $1; next; }
        return;    # unbalanced quoting
    }
    push @out, $cur if defined $cur;
    return @out;
}

sub first_line { my $s = shift // ''; ( $s =~ /^\s*(.*)/ )[0] // '' }

sub audit {
    my ( $who, $ip, $a ) = @_;
    sysopen( my $fh, $LOG_FILE, O_WRONLY | O_APPEND | O_CREAT, 0600 ) or return;
    my $out = $a->{out} // '';
    $out =~ s/\s+/ /g;
    $out = substr( $out, 0, 500 );
    printf {$fh} "%s %s ip=%s step=\"%s\" rc=%s cmd=%s out=%s\n", POSIX::strftime( '%Y-%m-%d %H:%M:%S', localtime ), $who, $ip, $a->{step}, $a->{rc} // '-', $a->{cmd}, $out;
    close $fh;
}

sub read_form {
    my %f;
    my @src = ( $ENV{QUERY_STRING} // '' );
    if ( ( $ENV{REQUEST_METHOD} // '' ) eq 'POST' ) {
        my $len = $ENV{CONTENT_LENGTH} // 0;
        $len = 65536 if $len > 65536;
        my $body = '';
        read( STDIN, $body, $len ) if $len > 0;
        push @src, $body;
    }
    for my $s (@src) {
        for my $pair ( split /[&;]/, $s ) {
            my ( $k, $v ) = split /=/, $pair, 2;
            next unless defined $k && length $k;
            for ( $k, $v ) { $_ //= ''; tr/+/ /; s/%([0-9A-Fa-f]{2})/chr hex $1/ge; }
            $f{$k} = $v;
        }
    }
    return \%f;
}

# ---------------------------------------------------------------------------
# HTML
# ---------------------------------------------------------------------------

sub h {
    my $s = shift // '';
    $s =~ s/&/&amp;/g;
    $s =~ s/</&lt;/g;
    $s =~ s/>/&gt;/g;
    $s =~ s/"/&quot;/g;
    $s =~ s/'/&#39;/g;
    return $s;
}

sub checkbox {
    my ( $name, $on, $label ) = @_;
    return qq{<label class="allc-opt"><input type="checkbox" name="$name" value="1"} . ( $on ? ' checked' : '' ) . qq{> $label</label>};
}

sub option_boxes {
    my ($opts) = @_;
    return checkbox( 'ranges', $opts->{ranges}, 'Also delete CIDR / range entries that <em>contain</em> the IP (unblocks the whole range)' )
      . checkbox( 'csf_allow', $opts->{csf_allow}, "Afterwards, temporarily allow in CSF for ${\ ($CSF_ALLOW_TTL/3600)}h (stops LFD re-blocking straight away)" )
      . checkbox( 'bitninja_whitelist', $opts->{bitninja_whitelist}, 'Afterwards, add to the BitNinja whitelist (permanent)' );
}

sub search_form {
    my ( $ipstr, $opts ) = @_;
    return qq{<form method="get" action="$SELF" class="allc-search">}
      . qq{<input type="hidden" name="action" value="search">}
      . qq{<input type="text" name="ip" value="} . h($ipstr) . qq{" placeholder="IPv4 or IPv6 address, e.g. 203.0.113.17" autofocus size="40">}
      . qq{ <button type="submit">Search all firewalls</button>}
      . qq{<span class="allc-loading"><span class="allc-spin"></span> Searching all firewall layers&hellip; this can take up to a minute.</span></form>};
}

sub render_scan {
    my ( $ip, $sections, $opts, $offer_unblock ) = @_;
    my ( $total, $allows ) = ( 0, 0 );
    my $html = '';
    my $selectable = 0;
    for my $s (@$sections) {
        my $blocks = grep { !$_->{allow} } @{ $s->{items} };
        my $allow  = grep { $_->{allow} } @{ $s->{items} };
        $total  += grep { !$_->{dup} && !$_->{allow} } @{ $s->{items} };
        $allows += grep { !$_->{dup} && $_->{allow} } @{ $s->{items} };
        my ( $cls, $status ) =
            !$s->{available} ? ( 'na',   'not installed' )
          : $s->{error}      ? ( 'bad',  'error' )
          : $blocks          ? ( 'warn', "$blocks block" . ( $blocks == 1 ? '' : 's' ) . ( $allow ? ", $allow allow" : '' ) )
          : $allow           ? ( 'allow', "allowed ($allow)" )
          :                    ( 'ok',   'clear' );
        $html .= qq{<div class="allc-sec"><div class="allc-sec-h"><strong>} . h( $s->{title} ) . qq{</strong> <span class="allc-badge allc-$cls">$status</span></div>};
        $html .= qq{<div class="allc-err">} . h( $s->{error} ) . "</div>" if $s->{error};
        if ( @{ $s->{items} } ) {
            $html .= "<ul>";
            for my $it ( @{ $s->{items} } ) {
                my $note = $it->{note} // '';
                my $box  = '';
                if ( $it->{id} ) {
                    if ( locks_out( $it, $ip, $ADMIN_IP ) ) {
                        $box  = qq{<input type="checkbox" disabled title="Covers your own IP">};
                        $note = join ', ', grep { length } $note, "covers your own IP ($ADMIN_IP->{str}), can't be removed here";
                    }
                    else {
                        $selectable++;
                        my $cls = $it->{allow} ? 'allc-cb allc-cb-allow' : 'allc-cb';
                        $box = qq{<input type="checkbox" name="sel_$it->{id}" value="1" class="$cls">};
                    }
                }
                $html .= ( $it->{id} ? "<li>" : qq{<li class="allc-nobox">} ) . ( $box ? qq{<label class="allc-item">$box } : '' ) . "<code>" . h( $it->{desc} ) . "</code>" . ( $box ? '</label>' : '' );
                $html .= qq{ <span class="allc-note">} . h($note) . "</span>" if length $note;
                $html .= "</li>";
            }
            $html .= "</ul>";
        }
        $html .= qq{<div class="allc-hint">} . h( $s->{note} ) . "</div>" if $s->{note} && $s->{available} && $s->{found};
        $html .= "</div>";
    }

    my $head = $total
      ? qq{<div class="allc-msg allc-warn"><strong>} . h( $ip->{str} ) . "</strong> is blocked by $total firewall entr" . ( $total == 1 ? 'y' : 'ies' ) . ".</div>"
      : qq{<div class="allc-msg allc-good"><strong>} . h( $ip->{str} ) . "</strong> is not blocked anywhere"
      . ( $allows ? " (it has $allows allow / whitelist entr" . ( $allows == 1 ? 'y' : 'ies' ) . ", left alone)" : '' ) . ".</div>";

    my $form = '';
    if ($offer_unblock) {
        $form = qq{<form method="post" action="$SELF" class="allc-unblock">}
          . qq{<input type="hidden" name="action" value="unblock">}
          . qq{<input type="hidden" name="ip" value="} . h( $ip->{str} ) . qq{">}
          . option_boxes($opts)
          . qq{<button type="submit" class="allc-go">Unblock } . h( $ip->{str} ) . qq{ everywhere</button>}
          . qq{<span class="allc-loading"><span class="allc-spin"></span> Unblocking and re-scanning&hellip; please wait.</span>}
          . qq{<div class="allc-hint">Runs the CSF / BitNinja / fail2ban / cPHulk unblock commands even if nothing is listed above, then re-scans and deletes any leftover ipset, iptables and nftables entries. Allow (ACCEPT) rules are never touched.</div>}
          . "</form>";
    }

    # Per-entry removal: the sections become one form with a checkbox per entry.
    if ($selectable) {
        $html = qq{<form method="post" action="$SELF" class="allc-select">}
          . qq{<input type="hidden" name="action" value="remove">}
          . qq{<input type="hidden" name="ip" value="} . h( $ip->{str} ) . qq{">}
          . qq{<div class="allc-hint">Tick entries to remove just those, including allow / whitelist entries.</div>}
          . $html
          . qq{<div class="allc-selbar"><button type="submit" class="allc-sel">Remove selected entries</button>}
          . qq{<span class="allc-loading"><span class="allc-spin"></span> Removing selected entries&hellip; please wait.</span>}
          . qq{<div class="allc-hint">Only the ticked entries are removed, in the same safe order as a full unblock. Removing an <strong>allow</strong> entry takes away that trust, so the IP may be blocked again. Allow entries that cover your own IP can't be removed here.</div></div>}
          . "</form>";
    }
    return $head . $form . $html;
}

# Scan + render, but show any failure on the page instead of a blank screen.
sub safe_scan {
    my ( $ip, $opts, $offer ) = @_;
    my $html = eval { my @sections = scan_all($ip); render_scan( $ip, \@sections, $opts, $offer ) };
    return $html if defined $html;
    my $err = $@ || 'unknown error';
    return qq{<div class="allc-msg allc-bad">Scan failed: } . h($err) . qq{<br>Run <code>allclear search } . h( $ip->{str} ) . qq{</code> as root for details.</div>};
}

sub render_actions {
    my ($actions) = @_;
    my $html = "<h2>Actions</h2><table class=\"allc-tbl\"><tr><th></th><th>Step</th><th>Command / output</th></tr>";
    for my $a (@$actions) {
        $html .= "<tr><td>" . ( $a->{ok} ? '<span class="allc-badge allc-ok">ok</span>' : '<span class="allc-badge allc-bad">rc ' . h( $a->{rc} ) . '</span>' ) . "</td>";
        $html .= "<td>" . h( $a->{step} ) . "</td><td><code>" . h( $a->{cmd} ) . "</code>";
        $html .= "<pre>" . h( $a->{out} ) . "</pre>" if ( $a->{out} // '' ) =~ /\S/;
        $html .= "</td></tr>";
    }
    return $html . "</table>";
}

# "AllClear vX by edznet.dev" strip. The logo is inline SVG so the plugin stays a single file.
sub brand_bar {
    return qq{<div class="allc-brand"><span>AllClear v$VERSION &middot; open source on <a href="https://github.com/EDZNET/allclear-whm" target="_blank" rel="noopener">GitHub</a></span>}
      . qq{<a href="https://edznet.dev" target="_blank" rel="noopener" title="Made by edznet.dev"><span>by</span> } . EDZNET_DEV_LOGO() . qq{<b>edznet.dev</b></a></div>};
}

use constant EDZNET_DEV_LOGO => q{<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100" width="16" height="16" aria-hidden="true"><rect width="100" height="100" rx="16" fill="#0a1322"/><g fill="none" stroke="#F3EEE3" stroke-width="15"><path d="M76 31.5H33.5A2 2 0 0 0 31.5 33.5V53.5A15 15 0 0 0 46.5 68.5H76"/><path d="M46.5 50H74"/></g></svg>};

# Show the spinner and lock the buttons once a form is submitted, so a slow scan
# doesn't look like a dead page and an unblock can't be submitted twice.
sub page_js {
    return <<'JS';
<script>
// "Remove selected" is only enabled while something is ticked.
function allcSync() {
    var f = document.querySelector('.allc-select');
    if (!f) return;
    f.querySelector('button.allc-sel').disabled = !f.querySelector('.allc-cb:checked');
}
document.addEventListener('change', function (e) {
    if (e.target.classList && e.target.classList.contains('allc-cb')) allcSync();
});
document.addEventListener('DOMContentLoaded', allcSync);
document.addEventListener('submit', function (e) {
    var f = e.target;
    if (!f.closest || !f.closest('.allc')) return;
    var allows = f.querySelectorAll('.allc-cb-allow:checked').length;
    if (allows && !window.confirm('Remove ' + allows + ' allow / whitelist entr' + (allows == 1 ? 'y' : 'ies') + '? The IP may be blocked again afterwards.')) {
        e.preventDefault();
        return;
    }
    var l = f.querySelector('.allc-loading');
    if (l) l.className += ' allc-on';
    var b = document.querySelectorAll('.allc button');
    setTimeout(function () { for (var i = 0; i < b.length; i++) b[i].disabled = true; }, 0);
});
</script>
JS
}

sub page_css {
    return <<'CSS';
<style>
.allc{font-family:-apple-system,Segoe UI,Roboto,sans-serif;max-width:1100px;margin:10px 0;color:#222}
.allc-brand{display:flex;justify-content:space-between;align-items:center;font-size:12px;color:#777;border-bottom:1px solid #eee;padding:0 0 6px;margin:0 0 10px}.allc-brand a{color:#1e6fd9;text-decoration:none}.allc-brand a[title]{display:inline-flex;align-items:center;gap:5px}.allc-brand svg{display:block}.allc-brand b{color:#0a1322;font-weight:600}
.allc h1 small{font-size:13px;color:#777;font-weight:normal}
.allc-search input[type=text]{padding:7px 9px;font-size:15px;border:1px solid #bbb;border-radius:4px}
.allc button{padding:7px 14px;font-size:14px;border:0;border-radius:4px;background:#1e6fd9;color:#fff;cursor:pointer}
.allc button[disabled]{opacity:.6;cursor:wait}
.allc button.allc-sel{background:#8e44ad;margin-top:4px}.allc button.allc-sel[disabled]{cursor:not-allowed;opacity:.45}
.allc-item{font-weight:normal;cursor:pointer}.allc-item input{margin:0 6px 0 0;vertical-align:middle}
.allc-select .allc-sec ul{list-style:none;margin-left:0}.allc-select li.allc-nobox{padding-left:22px}
.allc-selbar{margin:10px 0 16px;padding:12px;border:1px solid #ddd;border-radius:4px;background:#fafafa}
.allc-loading{display:none;align-items:center;gap:8px;margin:8px 0 0 10px;font-size:13px;color:#555}.allc-loading.allc-on{display:inline-flex}
.allc-spin{width:14px;height:14px;border:2px solid #cfd8e3;border-top-color:#1e6fd9;border-radius:50%;animation:allc-spin .8s linear infinite}
@keyframes allc-spin{to{transform:rotate(360deg)}}
.allc button.allc-go{background:#c0392b;margin-top:8px}
.allc-msg{margin:14px 0;padding:10px 12px;border-radius:4px}
.allc-good{background:#e7f6ec;border:1px solid #9fd8b0}.allc-warn{background:#fff6e0;border:1px solid #f0cf7a}.allc-bad{background:#fdecea;border:1px solid #f1a9a0}
.allc-unblock{margin:0 0 16px;padding:12px;border:1px solid #ddd;border-radius:4px;background:#fafafa}
.allc-opt{display:block;margin:3px 0;font-weight:normal}
.allc-sec{border:1px solid #e2e2e2;border-radius:4px;margin:8px 0;padding:8px 12px}
.allc-sec ul{margin:6px 0 2px 18px;padding:0}.allc-sec li{margin:3px 0}
.allc code{font-size:12px;word-break:break-all}
.allc pre{white-space:pre-wrap;font-size:12px;background:#f4f4f4;padding:6px;margin:4px 0 0;max-height:200px;overflow:auto}
.allc-badge{display:inline-block;padding:1px 7px;border-radius:10px;font-size:12px;color:#fff}
.allc-ok{background:#2e9d50}.allc-allow{background:#2471a3}.allc-warn.allc-badge,.allc-badge.allc-warn{background:#d68910}.allc-na{background:#aaa}.allc-badge.allc-bad{background:#c0392b}
.allc-note{font-size:12px;color:#a35d00}.allc-hint{font-size:12px;color:#777;margin-top:4px}.allc-err{color:#c0392b;font-size:13px}
.allc-tbl{border-collapse:collapse;width:100%}.allc-tbl td,.allc-tbl th{border-bottom:1px solid #eee;padding:6px;text-align:left;vertical-align:top}
</style>
CSS
}
