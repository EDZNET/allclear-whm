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

our $VERSION = '1.3.0';

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
        my $a = { step => $step, cmd => $cmdstr, rc => $rc, ok => ( $rc == 0 ? 1 : 0 ), out => $out };
        push @$actions, $a;
        audit( $who, $ip->{str}, $a );
        return $a;
    };
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
        if ( $it->{set} || $it->{table} ) { $kernel{$id} = 1 }
        else                               { $do->(@$_) for @{ $it->{actions} } }
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
        $do->( 'cPHulk: flush login history / brute blocks', $WHMAPI{bin}, 'flush_cphulk_login_history_for_ips', "ip=$ip->{str}" )
          if $s->{found};
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
        my ( $ip, $len ) = ( parse_ip($1), $2 );
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
        my ( $lo, $hi ) = ( parse_ip($1), parse_ip($2) );
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

# "AllClear vX by EDZNET" strip. The logo is embedded so the plugin stays a single file.
sub brand_bar {
    return qq{<div class="allc-brand"><span>AllClear v$VERSION &middot; open source on <a href="https://github.com/EDZNET/allclear-whm" target="_blank" rel="noopener">GitHub</a></span>}
      . qq{<a href="https://edznet.io" target="_blank" rel="noopener" title="Made by EDZNET"><span>by</span> <img src="data:image/png;base64,} . EDZNET_LOGO() . qq{" alt="EDZNET" height="16"></a></div>};
}

use constant EDZNET_LOGO => 'iVBORw0KGgoAAAANSUhEUgAAAUsAAAA1CAYAAADI6MmbAAAACXBIWXMAAAsTAAALEwEAmpwYAAAGp2lUWHRYTUw6Y29tLmFkb2JlLnhtcAAAAAAAPD94cGFja2V0IGJlZ2luPSLvu78iIGlkPSJXNU0wTXBDZWhpSHpyZVN6TlRjemtjOWQiPz4gPHg6eG1wbWV0YSB4bWxuczp4PSJhZG9iZTpuczptZXRhLyIgeDp4bXB0az0iQWRvYmUgWE1QIENvcmUgNi4wLWMwMDMgNzkuMTY0NTI3LCAyMDIwLzEwLzE1LTE3OjQ4OjMyICAgICAgICAiPiA8cmRmOlJERiB4bWxuczpyZGY9Imh0dHA6Ly93d3cudzMub3JnLzE5OTkvMDIvMjItcmRmLXN5bnRheC1ucyMiPiA8cmRmOkRlc2NyaXB0aW9uIHJkZjphYm91dD0iIiB4bWxuczp4bXA9Imh0dHA6Ly9ucy5hZG9iZS5jb20veGFwLzEuMC8iIHhtbG5zOmRjPSJodHRwOi8vcHVybC5vcmcvZGMvZWxlbWVudHMvMS4xLyIgeG1sbnM6cGhvdG9zaG9wPSJodHRwOi8vbnMuYWRvYmUuY29tL3Bob3Rvc2hvcC8xLjAvIiB4bWxuczp4bXBNTT0iaHR0cDovL25zLmFkb2JlLmNvbS94YXAvMS4wL21tLyIgeG1sbnM6c3RFdnQ9Imh0dHA6Ly9ucy5hZG9iZS5jb20veGFwLzEuMC9zVHlwZS9SZXNvdXJjZUV2ZW50IyIgeG1wOkNyZWF0b3JUb29sPSJBZG9iZSBQaG90b3Nob3AgMjIuMSAoV2luZG93cykiIHhtcDpDcmVhdGVEYXRlPSIyMDIyLTA0LTA3VDE5OjIxOjQ0KzAyOjAwIiB4bXA6TW9kaWZ5RGF0ZT0iMjAyMi0wNC0xMFQxODoxMCswMjowMCIgeG1wOk1ldGFkYXRhRGF0ZT0iMjAyMi0wNC0xMFQxODoxMCswMjowMCIgZGM6Zm9ybWF0PSJpbWFnZS9wbmciIHBob3Rvc2hvcDpDb2xvck1vZGU9IjMiIHBob3Rvc2hvcDpJQ0NQcm9maWxlPSJzUkdCIElFQzYxOTY2LTIuMSIgeG1wTU06SW5zdGFuY2VJRD0ieG1wLmlpZDo4NGRjMWE5ZC1mOWNhLWYzNDYtYjY5Ni0zZmI1MGJjZmE4ZTMiIHhtcE1NOkRvY3VtZW50SUQ9InhtcC5kaWQ6MDY0N2U5MmMtNDI5ZC0zYjRlLWIwMTMtODQ4MGRhNjZjN2NmIiB4bXBNTTpPcmlnaW5hbERvY3VtZW50SUQ9InhtcC5kaWQ6MDY0N2U5MmMtNDI5ZC0zYjRlLWIwMTMtODQ4MGRhNjZjN2NmIj4gPHhtcE1NOkhpc3Rvcnk+IDxyZGY6U2VxPiA8cmRmOmxpIHN0RXZ0OmFjdGlvbj0iY3JlYXRlZCIgc3RFdnQ6aW5zdGFuY2VJRD0ieG1wLmlpZDowNjQ3ZTkyYy00MjlkLTNiNGUtYjAxMy04NDgwZGE2NmM3Y2YiIHN0RXZ0OndoZW49IjIwMjItMDQtMDdUMTk6MjE6NDQrMDI6MDAiIHN0RXZ0OnNvZnR3YXJlQWdlbnQ9IkFkb2JlIFBob3Rvc2hvcCAyMi4xIChXaW5kb3dzKSIvPiA8cmRmOmxpIHN0RXZ0OmFjdGlvbj0ic2F2ZWQiIHN0RXZ0Omluc3RhbmNlSUQ9InhtcC5paWQ6NGI3MTIyODUtOGIyZi00ZTRmLTg2MDQtYjMyN2I4YTRlNWU4IiBzdEV2dDp3aGVuPSIyMDIyLTA0LTEwVDE2OjIxOjI1KzAyOjAwIiBzdEV2dDpzb2Z0d2FyZUFnZW50PSJBZG9iZSBQaG90b3Nob3AgMjIuMSAoV2luZG93cykiIHN0RXZ0OmNoYW5nZWQ9Ii8iLz4gPHJkZjpsaSBzdEV2dDphY3Rpb249InNhdmVkIiBzdEV2dDppbnN0YW5jZUlEPSJ4bXAuaWlkOjg0ZGMxYTlkLWY5Y2EtZjM0Ni1iNjk2LTNmYjUwYmNmYThlMyIgc3RFdnQ6d2hlbj0iMjAyMi0wNC0xMFQxODoxMCswMjowMCIgc3RFdnQ6c29mdHdhcmVBZ2VudD0iQWRvYmUgUGhvdG9zaG9wIDIyLjEgKFdpbmRvd3MpIiBzdEV2dDpjaGFuZ2VkPSIvIi8+IDwvcmRmOlNlcT4gPC94bXBNTTpIaXN0b3J5PiA8L3JkZjpEZXNjcmlwdGlvbj4gPC9yZGY6UkRGPiA8L3g6eG1wbWV0YT4gPD94cGFja2V0IGVuZD0iciI/PqdwWQEAABcoSURBVHic7Z15kCVFncd/mVn3u/vuOaDnapAB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';

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
.allc-brand{display:flex;justify-content:space-between;align-items:center;font-size:12px;color:#777;border-bottom:1px solid #eee;padding:0 0 6px;margin:0 0 10px}.allc-brand a{color:#1e6fd9;text-decoration:none}.allc-brand img{vertical-align:middle;height:16px;width:auto}
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
