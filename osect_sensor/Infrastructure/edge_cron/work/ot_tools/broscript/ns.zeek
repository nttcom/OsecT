@load base/frameworks/notice

module NS;

export {
	redef enum Log::ID += { LOG };

	type Info: record {
		ts:		time			&log &optional;
		orig_mac:	string		&log &optional;
		resp_mac:	string		&log &optional;
		orig_ip:	addr		&log &optional;
		resp_ip:	addr		&log &optional;
		who_has:	addr		&log &optional;
		pkts:       int		&log &optional;
	};

	global log_neighbor: event(rec: Info);

	type AggregationData: record {
		orig_mac:	string		&log &optional;
		resp_mac:	string		&log &optional;
		orig_ip:	addr		&log &optional;
		resp_ip:	addr		&log &optional;
		who_has:	addr		&log &optional;
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
    if ( idx?$resp_mac ){
		info_insert$resp_mac = idx$resp_mac;
	}
	if ( idx?$orig_ip ){
		info_insert$orig_ip = idx$orig_ip;
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
	Log::write(NS::LOG, info_insert);
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
    if ( info?$resp_mac ){
		aggregationData$resp_mac = info$resp_mac;
	}
	if ( info?$orig_ip ){
		aggregationData$orig_ip = info$orig_ip;
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

event zeek_init() &priority=5
	{
	Log::create_stream(NS::LOG, [$columns=Info, $ev=log_neighbor]);
	}

# function log_request(rec: Info)
#         {
#         Log::write(NS::LOG, rec);
#         }

event icmp_neighbor_solicitation(c: connection, info: icmp_info, tgt: addr, options: icmp6_nd_options)
	{
	local request: Info;
	local aggregationData: AggregationData;

	if ( c$id$orig_p == 135/icmp )
		{
			request$ts = network_time();
			request$orig_mac = c$orig$l2_addr;
			request$orig_ip = c$id$orig_h;
			request$resp_ip = tgt;
			request$who_has = tgt;
			aggregationData = create_aggregationData(request);
			insert_res_aggregationData(aggregationData, request);
			# log_request(request);
		}
	else if ( c$id$resp_p == 135/icmp )
		{
			request$ts = network_time();
			request$orig_mac = c$resp$l2_addr;
			request$orig_ip = c$id$resp_h; 
			request$resp_ip = tgt;
			request$who_has = tgt;
			aggregationData = create_aggregationData(request);
			insert_res_aggregationData(aggregationData, request);
			# log_request(request);
		}
	}

event icmp_neighbor_advertisement(c: connection, info: icmp_info, router: bool, solicited: bool, override: bool, tgt: addr, options: icmp6_nd_options)
	{
	local request: Info;
	local aggregationData: AggregationData;
	local multicast_subnet: subnet = [ff00::]/8;

	if ( c$id$resp_p == 136/icmp )
		{
			request$ts = network_time();
			request$orig_mac = c$orig$l2_addr;
			request$resp_mac = c$resp$l2_addr;
			request$orig_ip = c$id$orig_h;
			request$resp_ip = tgt;
			aggregationData = create_aggregationData(request);
			insert_res_aggregationData(aggregationData, request);
			# log_request(request);
		}

	else if (( c$id$orig_p == 136/icmp ) && ( c$id$resp_h !in multicast_subnet ))
		{
			request$ts = network_time();
			request$orig_mac = c$resp$l2_addr;
			request$resp_mac = c$orig$l2_addr;
			request$orig_ip = c$id$resp_h;
			request$resp_ip = tgt;
			aggregationData = create_aggregationData(request);
			insert_res_aggregationData(aggregationData, request);
			# log_request(request);
        	}
	}

# # 集約 local debug用
# event zeek_done()
# 	{
# 	print "zeek_done()";
# 	print res_aggregationData;
# 	for ( i in res_aggregationData ){
# 		# print i;
#         # print res_aggregationData[i];
#         local info: Info = [];
#         info$ts = res_aggregationData[i]$ts_s;
#         if ( i?$orig_mac ){
#             info$orig_mac = i$orig_mac;
#         }
#         if ( i?$resp_mac ){
#             info$resp_mac = i$resp_mac;
#         }
#         if ( i?$orig_ip ){
#             info$orig_ip = i$orig_ip;
#         }
#         if ( i?$resp_ip ){
#             info$resp_ip = i$resp_ip;
#         }
#         # if ( i?$unsolicited ){
#         #     info$unsolicited = i$unsolicited;
#         # }
#         # if ( i?$no_resp ){
#         #     info$no_resp = i$no_resp;
#         # }
#         if ( i?$who_has ){
#             info$who_has = i$who_has;
#         }
#         if ( res_aggregationData[i]?$num ){
# 			info$pkts = res_aggregationData[i]$num;
# 		}
#         # if ( i?$is_at ){
#         #     info$is_at = i$is_at;
#         # }
#         Log::write(NS::LOG, info);
#     }
# 	}