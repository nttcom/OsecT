module MYDHCP;

export {
	redef enum Log::ID += { LOG };

	type Info: record {
		ts:		time &log &optional;
		SrcIP:		addr &log &optional;
		SrcMAC: 	string &log &optional;
		Hostname: 	string &log &optional;
		ParameterList: 	vector of count &log &optional;
		ClassId: 	string &log &optional;

		# Set to block number of final piece of data once received.
		final_block: count &optional;

		# Set to true once logged.
		done: bool &default=F;
	};

	## Event that can be handled to access the mydhcp logging record.
	global log_mydhcp: event(rec: Info);

	global res_endCode: table[string] of string = { ["\x00\x00"] = "nomal", 
	                                    ["\xCF\x80"] = "stop",
										};

	type AggregationData: record {
		SrcIP:		addr &log &optional;
		SrcMAC: 	string &log &optional;
		Hostname: 	string &log &optional;
		ParameterList: 	vector of count &log &optional;
		ClassId: 	string &log &optional;
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
	if ( idx?$SrcIP ){
		info_insert$SrcIP = idx$SrcIP;
	}
	if ( idx?$SrcMAC ){
		info_insert$SrcMAC = idx$SrcMAC;
	}
	if ( idx?$Hostname ){
		info_insert$Hostname = idx$Hostname;
	}
	if ( idx?$ParameterList ){
		info_insert$ParameterList = idx$ParameterList;
	}
	if ( idx?$ClassId ){
		info_insert$ClassId = idx$ClassId;
	}
	# if ( res_aggregationData[idx]?$ts_e ){
	# 	info_insert$ts_end = res_aggregationData[idx]$ts_e;
	# }
	# if ( res_aggregationData[idx]?$num ){
	# 	info_insert$number = res_aggregationData[idx]$num;
	# }
	# print res_aggregationData;
	# print info;
	Log::write(MYDHCP::LOG, info_insert);
	# res_aggregationData = {};
	return 0secs;
	}

	global res_aggregationData: table[AggregationData] of Ts_num &create_expire=60sec &expire_func=insert_log;
}

function create_aggregationData(info: Info): AggregationData
	{
	local aggregationData: AggregationData;
	if ( info?$SrcIP ){
		aggregationData$SrcIP = info$SrcIP;
	}
	if ( info?$SrcMAC ){
		aggregationData$SrcMAC = info$SrcMAC;
	}
	if ( info?$Hostname ){
		aggregationData$Hostname = info$Hostname;
	}
	if ( info?$ParameterList ){
		aggregationData$ParameterList = info$ParameterList;
	}
	if ( info?$ClassId ){
		aggregationData$ClassId = info$ClassId;
	}

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

# Maps a partial data connection ID to the request's Info record.
global expected_data_conns: table[addr, port, addr] of Info;

redef record connection += {
	mydhcp: Info &optional;
};

event zeek_init() &priority=5
	{
	Log::create_stream(MYDHCP::LOG, [$columns = Info, $ev = log_mydhcp, $path="mydhcp"]);
	}

event MYDHCP::message(
	c: connection, is_orig: bool, msg: DHCP::Msg, options: DHCP::Options
	)
	{

	local info: Info;
	local aggregationData: AggregationData;

	info$ts = network_time();
	info$SrcIP = c$id$orig_h;
	info$SrcMAC = c$orig$l2_addr;
	if ( options?$host_name ){
		info$Hostname = options$host_name;
	}
	if ( options?$param_list ){
		info$ParameterList = options$param_list;
	}
	if ( options?$vendor_class ){
		info$ClassId = options$vendor_class;
	}
	# Log::write(MYDHCP::LOG, info);
	aggregationData = create_aggregationData(info);
	insert_res_aggregationData(aggregationData, info);

	c$mydhcp = info;
	# if ( options?$host_name ){
	# 	print fmt("Zeek saw from %s %s to %s: %s options: %s msg:%s", c$start_time, c$id$orig_h, c$id$resp_h, c$orig$l2_addr, options, msg);
	# } else {
	# 	print fmt("Zeek saw from %s %s to %s: %s options: no", c$start_time, c$id$orig_h, c$id$resp_h, c$orig$l2_addr);
	# }
	}

# 集約 local debug用
event zeek_done()
	{
	print "zeek_done()";
	print res_aggregationData;
	for ( i in res_aggregationData ){
		# print i;
        # print res_aggregationData[i];
		local info: Info = [];
		info$ts = res_aggregationData[i]$ts_s;
        if ( i?$SrcIP ){
			info$SrcIP = i$SrcIP;
		}
		if ( i?$SrcMAC ){
			info$SrcMAC = i$SrcMAC;
		}
		if ( i?$Hostname ){
			info$Hostname = i$Hostname;
		}
		if ( i?$ParameterList ){
			info$ParameterList = i$ParameterList;
		}
		if ( i?$ClassId ){
			info$ClassId = i$ClassId;
		}
		# if ( res_aggregationData[i]?$ts_e ){
		# 	info$ts_end = res_aggregationData[i]$ts_e;
		# }
		# if ( res_aggregationData[i]?$num ){
		# 	info$pkts = res_aggregationData[i]$num;
		# }
		# print res_aggregationData;
		# print info;
		Log::write(MYDHCP::LOG, info);
    }
	}
