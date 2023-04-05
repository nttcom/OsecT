module SSDP;

export {
	redef enum Log::ID += { LOG };
	redef ignore_checksums = T;

	type Info: record {
		ts:		time &log &optional;
		SrcIP:	addr &log &optional;
		SrcMAC: string &log &optional;
		Method: string &log &optional;
		SERVER_or_USER_AGENT: string &log &optional;

		# Set to block number of final piece of data once received.
		final_block: count &optional;

		# Set to true once logged.
		done: bool &default=F;
	};

	## Event that can be handled to access the ssdp logging record.
	global log_ssdp: event(rec: Info);

	type AggregationData: record {
		SrcIP:	addr &log &optional;
		SrcMAC: string &log &optional;
		Method: string &log &optional;
		SERVER_or_USER_AGENT: string &log &optional;
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
	if ( idx?$Method ){
		info_insert$Method = idx$Method;
	}
	if ( idx?$SERVER_or_USER_AGENT ){
		info_insert$SERVER_or_USER_AGENT = idx$SERVER_or_USER_AGENT;
	}
	# if ( res_aggregationData[idx]?$ts_e ){
	# 	info_insert$ts_end = res_aggregationData[idx]$ts_e;
	# }
	# if ( res_aggregationData[idx]?$num ){
	# 	info_insert$pkts = res_aggregationData[idx]$num;
	# }
	# print res_aggregationData;
	# print info;
	Log::write(SSDP::LOG, info_insert);
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
	if ( info?$Method ){
		aggregationData$Method = info$Method;
	}
	if ( info?$SERVER_or_USER_AGENT ){
		aggregationData$SERVER_or_USER_AGENT = info$SERVER_or_USER_AGENT;
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
	ssdp: Info &optional;
};

event zeek_init() &priority=5
	{
	Log::create_stream(SSDP::LOG, [$columns = Info, $ev = log_ssdp, $path="ssdp"]);
	}

type Line: record {
	v: vector of string;
};

function split_s(s: string): vector of string
{	
	local res1 = "";
	local res2 = "";
	local flag = F;
	for (i in s) {
		if (flag == T) {
			res1 = res1 + i;
		} else {
			res2 = res2 + i;
		}
		if (i == " ") {
			flag = T;
		}
    }
	local res3: vector of string = { res2, res1 };
	return res3;
}

event SSDP::message(c: connection, method: string, line: Line)
	{
	# print fmt("%s %s %s %s %s %s %s", network_time(), c$id$orig_h, c$id$resp_h, c$orig$l2_addr, name_type, additional_records_ttl, queries_name);

	local info: Info;
	local aggregationData: AggregationData;
	local res: vector of string;

	info$ts = network_time();
	info$SrcIP = c$id$orig_h;
	info$SrcMAC = c$orig$l2_addr;
	if (method == "NOTIFY * HTTP/1.1") {
		info$Method = "NOTIFY";
		for (i in line$v) {
			res = split_s(line$v[i]);
			if (to_upper(res[0]) == "SERVER: ") {
				info$SERVER_or_USER_AGENT = res[1];
			}
		}
	} else if (method == "M-SEARCH * HTTP/1.1") {
		info$Method = "M-SEARCH Request";
		for (i in line$v) {
			res = split_s(line$v[i]);
			if (to_upper(res[0]) == "USER-AGENT: ") {
				info$SERVER_or_USER_AGENT = res[1];
			}
		}
	} else if (method == "HTTP/1.1 200 OK") {
		info$Method = "M-SEARCH Response";
		for (i in line$v) {
			res = split_s(line$v[i]);
			if (to_upper(res[0]) == "SERVER: ") {
				info$SERVER_or_USER_AGENT = res[1];
			}
		}
	}

	# info$SERVER_or_USER_AGENT = line.v;
	# Log::write(SSDP::LOG, info);
	aggregationData = create_aggregationData(info);
	insert_res_aggregationData(aggregationData, info);
	c$ssdp = info;
	# print fmt("%s %s %s %s %s %s %s", network_time(), c$id$orig_h, c$id$resp_h, c$orig$l2_addr, name_type, half_to_full(queries_name[1:-1]), additional_records_ttl);
	}

# 集約 local debug用
event zeek_done()
	{
	# print "zeek_done()";
	# print res_aggregationData;
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
		if ( i?$Method ){
			info$Method = i$Method;
		}
		if ( i?$SERVER_or_USER_AGENT ){
			info$SERVER_or_USER_AGENT = i$SERVER_or_USER_AGENT;
		}
		# if ( res_aggregationData[i]?$ts_e ){
		# 	info$ts_end = res_aggregationData[i]$ts_e;
		# }
		# if ( res_aggregationData[i]?$num ){
		# 	info$pkts = res_aggregationData[i]$num;
		# }
		# print res_aggregationData;
		# print info;
		Log::write(SSDP::LOG, info);
    }
	}
