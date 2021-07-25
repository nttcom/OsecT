#!/usr/bin/awk -f
function ltrim(s) { sub(/^[ \t\r\n]+/, "", s); return s }
function rtrim(s) { sub(/[ \t\r\n]+$/, "", s); return s }
function trim(s) { return rtrim(ltrim(s)); }
BEGIN {
    FS = "|"
    OFS = "\t"
    ADJUST_TIMEZON = 32400 # Specify the time in seconds to adjust the time zone

    DENY_PROTOCOL[0] = 1 # ICMP
    DENY_PROTOCOL[1] = 6 # TCP
    DENY_PROTOCOL[2] = 17 # UDP
    DENY_PROTOCOL[3] = 58 # ICMPv6

    PROTO_DICT[0] = "hopopt"
    PROTO_DICT[1] = "icmp"
    PROTO_DICT[2] = "igmp"
    PROTO_DICT[3] = "ggp"
    PROTO_DICT[4] = "ipv4"
    PROTO_DICT[5] = "st"
    PROTO_DICT[6] = "tcp"
    PROTO_DICT[7] = "cbt"
    PROTO_DICT[8] = "egp"
    PROTO_DICT[9] = "igp"
    PROTO_DICT[10] = "bbn-rcc-mon"
    PROTO_DICT[11] = "nvp-ii"
    PROTO_DICT[12] = "pup"
    PROTO_DICT[13] = "argus (deprecated)"
    PROTO_DICT[14] = "emcon"
    PROTO_DICT[15] = "xnet"
    PROTO_DICT[16] = "chaos"
    PROTO_DICT[17] = "udp"
    PROTO_DICT[18] = "mux"
    PROTO_DICT[19] = "dcn-meas"
    PROTO_DICT[20] = "hmp"
    PROTO_DICT[21] = "prm"
    PROTO_DICT[22] = "xns-idp"
    PROTO_DICT[23] = "trunk-1"
    PROTO_DICT[24] = "trunk-2"
    PROTO_DICT[25] = "leaf-1"
    PROTO_DICT[26] = "leaf-2"
    PROTO_DICT[27] = "rdp"
    PROTO_DICT[28] = "irtp"
    PROTO_DICT[29] = "iso-tp4"
    PROTO_DICT[30] = "netblt"
    PROTO_DICT[31] = "mfe-nsp"
    PROTO_DICT[32] = "merit-inp"
    PROTO_DICT[33] = "dccp"
    PROTO_DICT[34] = "3pc"
    PROTO_DICT[35] = "idpr"
    PROTO_DICT[36] = "xtp"
    PROTO_DICT[37] = "ddp"
    PROTO_DICT[38] = "idpr-cmtp"
    PROTO_DICT[39] = "tp++"
    PROTO_DICT[40] = "il"
    PROTO_DICT[41] = "ipv6"
    PROTO_DICT[42] = "sdrp"
    PROTO_DICT[43] = "ipv6-route"
    PROTO_DICT[44] = "ipv6-frag"
    PROTO_DICT[45] = "idrp"
    PROTO_DICT[46] = "rsvp"
    PROTO_DICT[47] = "gre"
    PROTO_DICT[48] = "dsr"
    PROTO_DICT[49] = "bna"
    PROTO_DICT[50] = "esp"
    PROTO_DICT[51] = "ah"
    PROTO_DICT[52] = "i-nlsp"
    PROTO_DICT[53] = "swipe (deprecated)"
    PROTO_DICT[54] = "narp"
    PROTO_DICT[55] = "mobile"
    PROTO_DICT[56] = "tlsp"
    PROTO_DICT[57] = "skip"
    PROTO_DICT[58] = "ipv6-icmp"
    PROTO_DICT[59] = "ipv6-nonxt"
    PROTO_DICT[60] = "ipv6-opts"
    PROTO_DICT[61] = ""
    PROTO_DICT[62] = "cftp"
    PROTO_DICT[63] = ""
    PROTO_DICT[64] = "sat-expak"
    PROTO_DICT[65] = "kryptolan"
    PROTO_DICT[66] = "rvd"
    PROTO_DICT[67] = "ippc"
    PROTO_DICT[68] = ""
    PROTO_DICT[69] = "sat-mon"
    PROTO_DICT[70] = "visa"
    PROTO_DICT[71] = "ipcv"
    PROTO_DICT[72] = "cpnx"
    PROTO_DICT[73] = "cphb"
    PROTO_DICT[74] = "wsn"
    PROTO_DICT[75] = "pvp"
    PROTO_DICT[76] = "br-sat-mon"
    PROTO_DICT[77] = "sun-nd"
    PROTO_DICT[78] = "wb-mon"
    PROTO_DICT[79] = "wb-expak"
    PROTO_DICT[80] = "iso-ip"
    PROTO_DICT[81] = "vmtp"
    PROTO_DICT[82] = "secure-vmtp"
    PROTO_DICT[83] = "vines"
    PROTO_DICT[84] = "ttp"
    PROTO_DICT[84] = "iptm"
    PROTO_DICT[85] = "nsfnet-igp"
    PROTO_DICT[86] = "dgp"
    PROTO_DICT[87] = "tcf"
    PROTO_DICT[88] = "eigrp"
    PROTO_DICT[89] = "ospfigp"
    PROTO_DICT[90] = "sprite-rpc"
    PROTO_DICT[91] = "larp"
    PROTO_DICT[92] = "mtp"
    PROTO_DICT[93] = "ax.25"
    PROTO_DICT[94] = "ipip"
    PROTO_DICT[95] = "micp (deprecated)"
    PROTO_DICT[96] = "scc-sp"
    PROTO_DICT[97] = "etherip"
    PROTO_DICT[98] = "encap"
    PROTO_DICT[99] = ""
    PROTO_DICT[100] = "gmtp"
    PROTO_DICT[101] = "ifmp"
    PROTO_DICT[102] = "pnni"
    PROTO_DICT[103] = "pim"
    PROTO_DICT[104] = "aris"
    PROTO_DICT[105] = "scps"
    PROTO_DICT[106] = "qnx"
    PROTO_DICT[107] = "a/n"
    PROTO_DICT[108] = "ipcomp"
    PROTO_DICT[109] = "snp"
    PROTO_DICT[110] = "compaq-peer"
    PROTO_DICT[111] = "ipx-in-ip"
    PROTO_DICT[112] = "vrrp"
    PROTO_DICT[113] = "pgm"
    PROTO_DICT[114] = ""
    PROTO_DICT[115] = "l2tp"
    PROTO_DICT[116] = "ddx"
    PROTO_DICT[117] = "iatp"
    PROTO_DICT[118] = "stp"
    PROTO_DICT[119] = "srp"
    PROTO_DICT[120] = "uti"
    PROTO_DICT[121] = "smp"
    PROTO_DICT[122] = "sm (deprecated)"
    PROTO_DICT[123] = "ptp"
    PROTO_DICT[124] = "isis over ipv4"
    PROTO_DICT[125] = "fire"
    PROTO_DICT[126] = "crtp"
    PROTO_DICT[127] = "crudp"
    PROTO_DICT[128] = "sscopmce"
    PROTO_DICT[129] = "iplt"
    PROTO_DICT[130] = "sps"
    PROTO_DICT[131] = "pipe"
    PROTO_DICT[132] = "sctp"
    PROTO_DICT[133] = "fc"
    PROTO_DICT[134] = "rsvp-e2e-ignore"
    PROTO_DICT[135] = "mobility header"
    PROTO_DICT[136] = "udplite"
    PROTO_DICT[137] = "mpls-in-ip"
    PROTO_DICT[138] = "manet"
    PROTO_DICT[139] = "hip"
    PROTO_DICT[140] = "shim6"
    PROTO_DICT[141] = "wesp"
    PROTO_DICT[142] = "rohc"
    PROTO_DICT[143] = "ethernet"
    # PROTO_DICT[144-252] = ""
    PROTO_DICT[253] = ""
    PROTO_DICT[254] = ""
    PROTO_DICT[255] = "reserved"

    print("#ts", "start-time", "end-time", "duration", "rtt", "proto", "sip", "sp", "dip", "dp", "srcMacAddress", "destMacAddress", "iflags", "uflags", "riflags", "ruflags", "isn", "risn", "tag", "rtag", "pkt", "oct", "rpkt", "roct", "end-reason")
}
{

    if (NR == 1){
        next;
    }
	if (NF != 24) {
		next;
	}

	start_time = $1
	end_time = $2
	duration = $3
	rtt = $4
	proto = $5
	sip = $6
	sp = $7
	dip = $8
	dp = $9
	srcMacAddress = $10
	destMacAddress = $11
	iflags = $12
	uflags = $13
	riflags = $14
	ruflags = $15
	isn = $16
	risn = $17
	tag = $18
	rtag = $19
	pkt = $20
	oct = $21
	rpkt = $22
	roct = $23
	end_reason = $24
	proto_str = ""

    len = length(DENY_PROTOCOL)
    for (i = 0; i <= len; i++ ) {
	 	if(DENY_PROTOCOL[i] == proto) {
	 	    next;
	 	}
    }
    # PROTO_DICT[144-252] = ""
    if(proto >= 144 && proto <= 252) {
        proto_str = ""
    } else {
        proto_str = PROTO_DICT[trim(proto)]
    }


    split(trim(start_time), date_time_millisecond, ".")
    split(date_time_millisecond[1], date_time, " ")
    split(date_time[1], date, "-")
    split(date_time[2], time, ":")

    date_time_str = date[1] " " date[2] " " date[3] " " time[1] " " time[2] " " time[3]

	print(mktime(date_time_str) + ADJUST_TIMEZON "." date_time_millisecond[2], trim(start_time), trim(end_time), trim(duration),
	trim(rtt), proto_str, trim(sip), trim(sp), trim(dip),
	trim(dp), trim(srcMacAddress), trim(destMacAddress), trim(iflags), trim(uflags), trim(riflags), trim(ruflags),
	trim(isn), trim(risn), trim(tag), trim(rtag), trim(pkt), trim(oct), trim(rpkt), trim(roct), trim(end_reason))
}


END {

}

