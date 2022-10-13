#!/bin/bash
### This script will proxy/noproxy anything running in specific cgroup
### need cgroup2 support, and iptables cgroup2 path match support
###
### script usage:
###     cgroup-tproxy.sh [--help|--config|stop]
### options:
###     --config=FILE   load config from file
###            --help   show help info
###              stop   clean then stop. Variables may change when stopping, which should be avoid
###                     so always stop first in the last context before start new context
###
### available variables with default value:
###     cgroup_noproxy="/noproxy.slice"
###     cgroup_proxy="/proxy.slice"
###     port=12345
###     enable_dns=true
###     enable_udp=true
###     enable_tcp=true
###     enable_ipv4=true
###     enable_ipv6=true
###     enable_gateway=false
###     table=10007
###     fwmark=0x9973
###     cgroup_mount_point=$(findmnt -t cgroup2 -n -o TARGET | head -n 1)
###
### semicolon to seperate multi cgroup:
###     cgroup_noproxy="/noproxy1.slice:/noproxy2.slice"
###     cgroup_proxy="/proxy1.slice:/proxy2.slice"

print_help() {
    sed -rn 's/^### ?//;T;p' "$0"
}

## init firewalld direct.xml
direct_xml_path="/etc/firewalld/direct.xml"
[ -e $direct_xml_path ] || {
    echo -e '<?xml version="1.0" encoding="utf-8"?>\n<direct/>' >$direct_xml_path
    chmod 0644 $direct_xml_path
}

direct_xml_add_chain() {
    xmlstarlet ed -L \
        -s "/direct" -t elem -n "chain" \
        -s "/direct/chain[last()]" -t attr -n "ipv" -v "$1" \
        -s "/direct/chain[last()]" -t attr -n "table" -v "$2" \
        -s "/direct/chain[last()]" -t attr -n "chain" -v "$3" \
        $direct_xml_path
}

direct_xml_add_rule() {
    local ipv=$1 && shift
    local table=$1 && shift
    local chain=$1 && shift
    local priority=$1 && shift
    local rule=$@
    xmlstarlet ed -L \
        -s "/direct" -t elem -n "rule" -v "$rule" \
        -s "/direct/rule[last()]" -t attr -n "ipv" -v "$ipv" \
        -s "/direct/rule[last()]" -t attr -n "table" -v "$table" \
        -s "/direct/rule[last()]" -t attr -n "chain" -v "$chain" \
        -s "/direct/rule[last()]" -t attr -n "priority" -v "$priority" \
        $direct_xml_path
}

[ ! $(id -u) -eq 0 ] && {
    echo >&2 "firewalld: need root to load firewalld"
    exit -1
}

## any process in this cgroup will be proxied
if [ -z ${cgroup_proxy+x} ]; then
    cgroup_proxy="/proxy.slice"
else
    IFS=':' read -r -a cgroup_proxy <<< "$cgroup_proxy"
fi

## any process in this cgroup will not be proxied
if [ -z ${cgroup_noproxy+x} ]; then
    cgroup_noproxy="/noproxy.slice"
else
    IFS=':' read -r -a cgroup_noproxy <<< "$cgroup_noproxy"
fi

## tproxy listening port
[ -z ${port+x} ] && port=12345
[ -z ${dns_port+x} ] && dns_port=1053

## controll options
[ -z ${enable_dns+x} ]  && enable_dns=true
[ -z ${enable_dns_redirect+x} ]  && enable_dns_redirect=true
[ -z ${enable_udp+x} ]  && enable_udp=true
[ -z ${enable_tcp+x} ]  && enable_tcp=true
[ -z ${enable_ipv4+x} ] && enable_ipv4=true
[ -z ${enable_ipv6+x} ] && enable_ipv6=true
[ -z ${enable_gateway+x} ] && enable_gateway=false

## mark/route things
[ -z ${table+x} ]           && table=10007
[ -z ${fwmark+x} ]          && fwmark=0x9973
[ -z ${table_reroute+x} ]   && table_reroute=$table
[ -z ${table_tproxy+x} ]    && table_tproxy=$table
[ -z ${fwmark_reroute+x} ]  && fwmark_reroute=$fwmark
[ -z ${fwmark_tproxy+x} ]   && fwmark_tproxy=$fwmark

## cgroup mount point things
[ -z ${cgroup_mount_point+x} ] && cgroup_mount_point=$(findmnt -t cgroup2 -n -o TARGET | head -n 1)


stop() {
    [ $(xmlstarlet sel -t -v "count(/direct/*[@chain='TPROXY_ENT' or @chain='TPROXY_PRE' or @chain='TPROXY_MARK' or @chain='TPROXY_OUT' or @chain='DNS_OUT'])" $direct_xml_path) -eq 0 ] && {
        return
    }
    echo "firewalld: cleaning direct rules"
    xmlstarlet ed -L \
        -d "/direct/*[@chain='TPROXY_ENT' or @chain='TPROXY_PRE' or @chain='TPROXY_MARK' or @chain='TPROXY_OUT' or @chain='DNS_OUT']" \
        -d "/direct/rule[text()='-j TPROXY_PRE' or text()='-j TPROXY_OUT' or text()='-j DNS_OUT']" \
        -d "/direct/rule[text()='-m owner ! --socket-exists -j MASQUERADE']" \
        -d "/direct/rule[text()='-m owner ! --socket-exists -s fc00::/7 -j MASQUERADE']" \
        -d "/direct/rule[text()='-p udp --dport 53 -j REDIRECT --to-ports $dns_port']" \
        -d "/direct/*[@chain='DIVERT']" \
        -d "/direct/rule[text()='-p udp --dport 53 -j DNS_OUT']" \
        -d "/direct/rule[text()='-p tcp -m socket -j DIVERT']" \
        $direct_xml_path
    firewall-cmd --reload || :

    ip rule delete fwmark $fwmark_tproxy lookup $table_tproxy
    ip route flush table $table_tproxy

    [ $table_tproxy == $table_reroute ] || ip rule delete fwmark $fwmark_reroute lookup $table_reroute
    [ $table_tproxy == $table_reroute ] || ip route flush table $table_reroute

    ip -6 rule delete fwmark $fwmark_tproxy lookup $table_tproxy
    ip -6 route flush table $table_tproxy
    [ $table_tproxy == $table_reroute ] || ip -6 rule delete fwmark $fwmark_reroute lookup $table_reroute
    [ $table_tproxy == $table_reroute ] || ip -6 route flush table $table_reroute

    ## unmount cgroup2
    [ "$(findmnt -M $cgroup_mount_point -n -o FSTYPE)" = "cgroup2" ] && umount $cgroup_mount_point
}

## parse parameter
for i in "$@"; do
    case $i in
    stop)
        stop
        exit 0
        ;;
    --config=*)
        config=${i#*=}
        source $config
        ;;
    --help)
        print_help
        exit 0
        ;;
    *)
        print_help
        exit 0
        ;;
    esac
done


## check cgroup_mount_point, create and mount if necessary
[ -z $cgroup_mount_point ] && {
    echo >&2 "firewalld: no cgroup2 mount point available"
    exit -1
}

[ ! -d $cgroup_mount_point ] && mkdir -p $cgroup_mount_point
[ "$(findmnt -M $cgroup_mount_point -n -o FSTYPE)" != "cgroup2" ] && mount -t cgroup2 none $cgroup_mount_point
[ "$(findmnt -M $cgroup_mount_point -n -o FSTYPE)" != "cgroup2" ] && {
    echo >&2 "firewalld: mount $cgroup_mount_point failed"
    exit -1
}

## only create the first one in arrary
test -d $cgroup_mount_point$cgroup_proxy || mkdir $cgroup_mount_point$cgroup_proxy || exit -1
test -d $cgroup_mount_point$cgroup_noproxy || mkdir $cgroup_mount_point$cgroup_noproxy || exit -1

## filter cgroup that not exist
_cgroup_noproxy=()
for cg in ${cgroup_noproxy[@]}; do
    test -d $cgroup_mount_point$cg && _cgroup_noproxy+=($cg) || { echo >&2 "firewalld: $cg not exist, ignore"; }
done
unset cgroup_noproxy && cgroup_noproxy=${_cgroup_noproxy[@]}

## filter cgroup that not exist
_cgroup_proxy=()
for cg in ${cgroup_proxy[@]}; do
    test -d $cgroup_mount_point$cg && _cgroup_proxy+=($cg) || { echo >&2 "firewalld: $cg not exist, ignore"; }
done
unset cgroup_proxy && cgroup_proxy=${_cgroup_proxy[@]}


## ipv4 #########################################################################
## mangle divert
# create
direct_xml_add_chain ipv4 mangle DIVERT
direct_xml_add_rule ipv4 mangle DIVERT 0 -j MARK --set-mark $fwmark_tproxy
direct_xml_add_rule ipv4 mangle DIVERT 0 -j ACCEPT
# hook
direct_xml_add_rule ipv4 mangle PREROUTING 0 -p tcp -m socket -j DIVERT

## mangle prerouting
ip rule add fwmark $fwmark_tproxy table $table_tproxy
ip route add local default dev lo table $table_tproxy
# core
direct_xml_add_chain ipv4 mangle TPROXY_ENT
direct_xml_add_rule ipv4 mangle TPROXY_ENT 1 -m socket -j MARK --set-mark $fwmark_tproxy
direct_xml_add_rule ipv4 mangle TPROXY_ENT 1 -m socket -j ACCEPT
direct_xml_add_rule ipv4 mangle TPROXY_ENT 1 -p tcp -j TPROXY --on-ip 127.0.0.1 --on-port $port --tproxy-mark $fwmark_tproxy
direct_xml_add_rule ipv4 mangle TPROXY_ENT 1 -p udp -j TPROXY --on-ip 127.0.0.1 --on-port $port --tproxy-mark $fwmark_tproxy
# filter
direct_xml_add_chain ipv4 mangle TPROXY_PRE
direct_xml_add_rule ipv4 mangle TPROXY_PRE 1 -m addrtype --dst-type LOCAL -j RETURN
direct_xml_add_rule ipv4 mangle TPROXY_PRE 1 -m addrtype ! --dst-type UNICAST -j RETURN
$enable_gateway || direct_xml_add_rule ipv4 mangle TPROXY_PRE 1 -m addrtype ! --src-type LOCAL -j RETURN
$enable_dns && direct_xml_add_rule ipv4 mangle TPROXY_PRE 1 -p udp --dport 53 -j TPROXY_ENT
$enable_udp && direct_xml_add_rule ipv4 mangle TPROXY_PRE 1 -p udp -j TPROXY_ENT
$enable_tcp && direct_xml_add_rule ipv4 mangle TPROXY_PRE 1 -p tcp -j TPROXY_ENT
# hook
direct_xml_add_rule ipv4 mangle PREROUTING 1 -j TPROXY_PRE

## mangle output
if [ $fwmark_reroute != $fwmark_tproxy ]; then
    ip rule add fwmark $fwmark_reroute table $table_reroute
    ip route add local default dev lo table $table_reroute
fi
# filter
direct_xml_add_chain ipv4 mangle TPROXY_MARK
direct_xml_add_rule ipv4 mangle TPROXY_MARK 1 -m addrtype ! --dst-type UNICAST -j RETURN
$enable_dns && direct_xml_add_rule ipv4 mangle TPROXY_MARK 1 -p udp --dport 53 -j MARK --set-mark $fwmark_reroute
$enable_udp && direct_xml_add_rule ipv4 mangle TPROXY_MARK 1 -p udp -j MARK --set-mark $fwmark_reroute
$enable_tcp && direct_xml_add_rule ipv4 mangle TPROXY_MARK 1 -p tcp -j MARK --set-mark $fwmark_reroute
# cgroup
direct_xml_add_chain ipv4 mangle TPROXY_OUT
direct_xml_add_rule ipv4 mangle TPROXY_OUT 1 -m conntrack --ctdir REPLY -j RETURN
for cg in ${cgroup_noproxy[@]}; do
    direct_xml_add_rule ipv4 mangle TPROXY_OUT 1 -m cgroup --path $cg -j RETURN
done
for cg in ${cgroup_proxy[@]}; do
    direct_xml_add_rule ipv4 mangle TPROXY_OUT 1 -m cgroup --path $cg -j TPROXY_MARK
done
# hook
$enable_ipv4 && direct_xml_add_rule ipv4 mangle OUTPUT 1 -j TPROXY_OUT
echo "firewalld: creating direct configuration - ipv4 enabled"

## ipv6 #########################################################################
## mangle divert
# create
direct_xml_add_chain ipv6 mangle DIVERT
direct_xml_add_rule ipv6 mangle DIVERT 0 -j MARK --set-mark $fwmark_tproxy
direct_xml_add_rule ipv6 mangle DIVERT 0 -j ACCEPT
# hook
direct_xml_add_rule ipv6 mangle PREROUTING 0 -p tcp -m socket -j DIVERT
## mangle prerouting
ip -6 rule add fwmark $fwmark_tproxy table $table_tproxy
ip -6 route add local default dev lo table $table_tproxy
# core
direct_xml_add_chain ipv6 mangle TPROXY_ENT
direct_xml_add_rule ipv6 mangle TPROXY_ENT 1 -m socket -j MARK --set-mark $fwmark_tproxy
direct_xml_add_rule ipv6 mangle TPROXY_ENT 1 -m socket -j ACCEPT
direct_xml_add_rule ipv6 mangle TPROXY_ENT 1 -p tcp -j TPROXY --on-ip ::1 --on-port $port --tproxy-mark $fwmark_tproxy
direct_xml_add_rule ipv6 mangle TPROXY_ENT 1 -p udp -j TPROXY --on-ip ::1 --on-port $port --tproxy-mark $fwmark_tproxy
# filter
direct_xml_add_chain ipv6 mangle TPROXY_PRE
direct_xml_add_rule ipv6 mangle TPROXY_PRE 1 -m addrtype --dst-type LOCAL -j RETURN
direct_xml_add_rule ipv6 mangle TPROXY_PRE 1 -m addrtype ! --dst-type UNICAST -j RETURN
$enable_gateway || direct_xml_add_rule ipv6 mangle TPROXY_PRE 1 -m addrtype ! --src-type LOCAL -j RETURN
$enable_dns && direct_xml_add_rule ipv6 mangle TPROXY_PRE 1 -p udp --dport 53 -j TPROXY_ENT
$enable_udp && direct_xml_add_rule ipv6 mangle TPROXY_PRE 1 -p udp -j TPROXY_ENT
$enable_tcp && direct_xml_add_rule ipv6 mangle TPROXY_PRE 1 -p tcp -j TPROXY_ENT
# hook
direct_xml_add_rule ipv6 mangle PREROUTING 1 -j TPROXY_PRE

## mangle output
if [ $fwmark_reroute != $fwmark_tproxy ]; then
    ip -6 rule add fwmark $fwmark_reroute table $table_reroute
    ip -6 route add local default dev lo table $table_reroute
fi
# filter
direct_xml_add_chain ipv6 mangle TPROXY_MARK
direct_xml_add_rule ipv6 mangle TPROXY_MARK 1 -m addrtype ! --dst-type UNICAST -j RETURN
$enable_dns && direct_xml_add_rule ipv6 mangle TPROXY_MARK 1 -p udp --dport 53 -j MARK --set-mark $fwmark_reroute
$enable_udp && direct_xml_add_rule ipv6 mangle TPROXY_MARK 1 -p udp -j MARK --set-mark $fwmark_reroute
$enable_tcp && direct_xml_add_rule ipv6 mangle TPROXY_MARK 1 -p tcp -j MARK --set-mark $fwmark_reroute
# cgroup
direct_xml_add_chain ipv6 mangle TPROXY_OUT
direct_xml_add_rule ipv6 mangle TPROXY_OUT 1 -m conntrack --ctdir REPLY -j RETURN
for cg in ${cgroup_noproxy[@]}; do
    direct_xml_add_rule ipv6 mangle TPROXY_OUT 1 -m cgroup --path $cg -j RETURN
done
for cg in ${cgroup_proxy[@]}; do
    direct_xml_add_rule ipv6 mangle TPROXY_OUT 1 -m cgroup --path $cg -j TPROXY_MARK
done
# hook
$enable_ipv6 && direct_xml_add_rule ipv6 mangle OUTPUT 1 -j TPROXY_OUT
echo "firewalld: creating direct configuration - ipv6 enabled"

## dns redirect ###################################################################
if $enable_dns_redirect; then
    direct_xml_add_rule ipv4 nat PREROUTING 1 -p udp --dport 53 -j REDIRECT --to-ports $dns_port
    direct_xml_add_rule ipv6 nat PREROUTING 1 -p udp --dport 53 -j REDIRECT --to-ports $dns_port

    direct_xml_add_chain ipv4 nat DNS_OUT
    for cg in ${cgroup_noproxy[@]}; do
        direct_xml_add_rule ipv4 nat DNS_OUT 1 -m cgroup --path $cg -j RETURN
    done
    for cg in ${cgroup_proxy[@]}; do
        direct_xml_add_rule ipv4 nat DNS_OUT 1 -p udp -m cgroup --path $cg -j REDIRECT --to-ports $dns_port
    done
    direct_xml_add_rule ipv4 nat OUTPUT 1 -p udp --dport 53 -j DNS_OUT

    direct_xml_add_chain ipv6 nat DNS_OUT
    for cg in ${cgroup_noproxy[@]}; do
        direct_xml_add_rule ipv6 nat DNS_OUT 1 -m cgroup --path $cg -j RETURN
    done
    for cg in ${cgroup_proxy[@]}; do
        direct_xml_add_rule ipv6 nat DNS_OUT 1 -p udp -m cgroup --path $cg -j REDIRECT --to-ports $dns_port
    done
    direct_xml_add_rule ipv6 nat OUTPUT 1 -p udp --dport 53 -j DNS_OUT
fi

## forward #######################################################################
if $enable_gateway; then
    direct_xml_add_rule ipv4 nat POSTROUTING 1 -m owner ! --socket-exists -j MASQUERADE
    direct_xml_add_rule ipv6 nat POSTROUTING 1 -m owner ! --socket-exists -s fc00::/7 -j MASQUERADE # only masquerade ipv6 private address
    sysctl -w net.ipv4.ip_forward=1
    sysctl -w net.ipv6.conf.all.forwarding=1
    echo "firewalld: creating direct configuration - gateway enabled"
fi

## load direct.xml
firewall-cmd --reload || :

## message for user
cat <<DOC
firewalld: noproxy cgroup: ${cgroup_noproxy[@]}
firewalld: proxied cgroup: ${cgroup_proxy[@]}
DOC
