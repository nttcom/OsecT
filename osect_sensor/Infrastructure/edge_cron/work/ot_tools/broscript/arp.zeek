@load base/frameworks/notice

module ARP;

export {
	redef enum Log::ID += { LOG };

	type Info: record {
		ts:		time		&optional &log;
		orig_mac:	string		&log &optional;
		orig_ip:	addr		&log &optional;
		resp_mac:	string		&log &optional;
		resp_ip:	addr		&log &optional;
		# unsolicited:	bool		&log &default=F;
		# no_resp:	bool		&log &default=F;
		who_has:	addr		&log &optional;
		# is_at:	string		&log &optional;
		pkts:       	int		&log &optional;
	};

	global log_arp: event(rec: Info);

    type AggregationData: record {
		orig_mac:	string  &log &optional;
		orig_ip:	addr    &log &optional;
		resp_mac:	string  &log &optional;
		resp_ip:	addr    &log &optional;
		# unsolicited:bool    &log &optional;
		# no_resp:	bool    &log &optional;
		who_has:	addr	&log &optional;
		# is_at:		string	&log &optional;
	};

	type Ts_num: record {
		ts_s:			time &log;
		num: 			int &log;
		ts_e: 			time &log &optional;
	};

	function insert_log(res_aggregationData: table[AggregationData] of Ts_num, idx: AggregationData): interval
	{
	local info_insert: Info = [];
	info_insert$ts = res_aggregationData[idx]$ts_s;
	if ( idx?$orig_mac ){
		info_insert$orig_mac = idx$orig_mac;
	}
	if ( idx?$orig_ip ){
		info_insert$orig_ip = idx$orig_ip;
	}
	if ( idx?$resp_mac ){
		info_insert$resp_mac = idx$resp_mac;
	}
	if ( idx?$resp_ip ){
		info_insert$resp_ip = idx$resp_ip;
	}
	# if ( idx?$unsolicited ){
	# 	info_insert$unsolicited = idx$unsolicited;
	# }
	# if ( idx?$no_resp ){
	# 	info_insert$no_resp = idx$no_resp;
	# }
	if ( idx?$who_has ){
		info_insert$who_has = idx$who_has;
	}
	# if ( idx?$is_at ){
	# 	info_insert$is_at = idx$is_at;
	# }
	# if ( res_aggregationData[idx]?$ts_e ){
	# 	info_insert$ts_end = res_aggregationData[idx]$ts_e;
	# }
	if ( res_aggregationData[idx]?$num ){
		info_insert$pkts = res_aggregationData[idx]$num;
	}
	# print res_aggregationData;
	# print info;
	Log::write(ARP::LOG, info_insert);
	# res_aggregationData = {};
	return 0secs;
	}

	global res_aggregationData: table[AggregationData] of Ts_num &create_expire=60sec &expire_func=insert_log;
}

function create_aggregationData(info: Info): AggregationData
	{
	local aggregationData: AggregationData;
	if ( info?$orig_mac ){
		aggregationData$orig_mac = info$orig_mac;
	}
	if ( info?$orig_ip ){
		aggregationData$orig_ip = info$orig_ip;
	}
	if ( info?$resp_mac ){
		aggregationData$resp_mac = info$resp_mac;
	}
	if ( info?$resp_ip ){
		aggregationData$resp_ip = info$resp_ip;
	}
	# if ( info?$unsolicited ){
	# 	aggregationData$unsolicited = info$unsolicited;
	# }
	# if ( info?$no_resp ){
	# 	aggregationData$no_resp = info$no_resp;
	# }
	if ( info?$who_has ){
		aggregationData$who_has = info$who_has;
	}
	# if ( info?$is_at ){
	# 	aggregationData$is_at = info$is_at;
	# }

	return aggregationData;
	}

function insert_res_aggregationData(aggregationData: AggregationData, info: Info): string
	{
		if (aggregationData in res_aggregationData){
			res_aggregationData[aggregationData]$num = res_aggregationData[aggregationData]$num + 1;
			res_aggregationData[aggregationData]$ts_e = info$ts;
		} else {
			res_aggregationData[aggregationData] = [$ts_s = info$ts, $num = 1, $ts_e = info$ts];
		}

		return "done";
	}

const broadcast_mac_addrs = { "00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff", };
const broadcast_addrs = { 0.0.0.0, 255.255.255.255, };

event zeek_init() &priority=5
        {
        Log::create_stream(ARP::LOG, [$columns=Info, $ev=log_arp]);
        }

# function log_request(rec: Info)
# 	{
# 	Log::write(ARP::LOG, rec);
# 	}

event arp_request(mac_src: string, mac_dst: string, SPA: addr, SHA: string, TPA: addr, THA: string)
	{
	local request: Info;
	local aggregationData: AggregationData;
	request$ts = network_time();
	request$orig_mac = mac_src;
	request$orig_ip = SPA;
	request$resp_ip = TPA;
	request$who_has = TPA;
	# log_request(request);
	aggregationData = create_aggregationData(request);
	insert_res_aggregationData(aggregationData, request);
	}

event arp_reply(mac_src: string, mac_dst: string, SPA: addr, SHA: string, TPA: addr, THA: string)
	{
	local request: Info;
	local aggregationData: AggregationData;
	request$ts = network_time();
	request$orig_mac = mac_dst;
	request$resp_mac = mac_src;
	request$orig_ip = TPA;
	request$resp_ip = SPA;
	# log_request(request);
	aggregationData = create_aggregationData(request);
	insert_res_aggregationData(aggregationData, request);
	}
