module NBNS;

export {
	redef enum Log::ID += { LOG };

	type Info: record {
		ts:		time &log &optional;
		SrcIP:	addr &log &optional;
		SrcMAC: string &log &optional;
		Name: string &log &optional;
		TTL: count &log &optional;
		ServiceType: string &log &optional;

		# Set to block number of final piece of data once received.
		final_block: count &optional;

		# Set to true once logged.
		done: bool &default=F;
	};

	## Event that can be handled to access the nbns logging record.
	global log_nbns: event(rec: Info);

	global res_serviceType: table[string] of string = { ["00"] = "Workstation", 
	                                    ["03"] = "Messenger", 
										["06"] = "RAS Server", 
										["1f"] = "NetDDE", 
										["20"] = "Server", 
										["21"] = "RAS Client", 
										["be"] = "Network Monitor Agent", 
										["bf"] = "Network Monitor Application", 
										["1d"] = "Master Browser", 
										["1b"] = "Domain Master Browser", 
										["1c"] = "Domain Controllers", 
										["1e"] = "Browser Service Elections", 
										["01"] = "Master Browser", 
										};
	
	type AggregationData: record {
		SrcIP:	addr &log &optional;
		SrcMAC: string &log &optional;
		Name: string &log &optional;
		TTL: count &log &optional;
		ServiceType: string &log &optional;
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
	if ( idx?$Name ){
		info_insert$Name = idx$Name;
	}
	if ( idx?$TTL ){
		info_insert$TTL = idx$TTL;
	}
	if ( idx?$ServiceType ){
		info_insert$ServiceType = idx$ServiceType;
	}
	# if ( res_aggregationData[idx]?$ts_e ){
	# 	info_insert$ts_end = res_aggregationData[idx]$ts_e;
	# }
	# if ( res_aggregationData[idx]?$num ){
	# 	info_insert$pkts = res_aggregationData[idx]$num;
	# }
	# print res_aggregationData;
	# print info;
	Log::write(NBNS::LOG, info_insert);
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
	if ( info?$Name ){
		aggregationData$Name = info$Name;
	}
	if ( info?$TTL ){
		aggregationData$TTL = info$TTL;
	}
	if ( info?$ServiceType ){
		aggregationData$ServiceType = info$ServiceType;
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
	nbns: Info &optional;
};

function del_space(s: string): string
	{
	local res = "";
	for ( i in  s ) {
		if (i != " ") {
			res = res + i;
		}
	}
	return res;
	}

function half_to_full(queries_name: string): string
{	
	local i = 0;
	local tmp1 = 0;
	local tmp2 = 0;
	local tmp3 = "";
	local res: vector of string = {};
	local res_return = "";

	while ( i < 32 )
	{	
		tmp1 = (bytestring_to_count(queries_name[i]) - 0x41) * 16;
		tmp2 = (bytestring_to_count(queries_name[i + 1]) - 0x41) & 0xf;
		tmp3 = fmt("%x", tmp1 | tmp2);
		if (|tmp3| == 1){
			res[|res|] = hexstr_to_bytestring("0" + tmp3);
		} else {
			res[|res|] = hexstr_to_bytestring(tmp3);
		}
		i = i + 2;
	}
	for ( i in  res) 
	{	
		res_return = res_return + res[i];
	}
	return res_return;
}

event zeek_init() &priority=5
	{
	Log::create_stream(NBNS::LOG, [$columns = Info, $ev = log_nbns, $path="nbns"]);
	}

event NBNS::message(c: connection, name_type: int, additional_records_ttl: count, queries_name: string)
	{
	# print fmt("%s %s %s %s %s %s %s", network_time(), c$id$orig_h, c$id$resp_h, c$orig$l2_addr, name_type, additional_records_ttl, queries_name);
	if (name_type == 0){
		local info: Info;
		local aggregationData: AggregationData;
		local tmp: string;

		info$ts = network_time();
		info$SrcIP = c$id$orig_h;
		info$SrcMAC = c$orig$l2_addr;
		info$TTL = additional_records_ttl;
		info$Name = del_space(half_to_full(queries_name[1:-1])[:-2]);
		tmp = bytestring_to_hexstr(half_to_full(queries_name[1:-1])[-1]);
		if (tmp in res_serviceType) {
			info$ServiceType = res_serviceType[tmp];
		} else {
			info$ServiceType = "Unknown";
		}

		# Log::write(NBNS::LOG, info);
		aggregationData = create_aggregationData(info);
		insert_res_aggregationData(aggregationData, info);
		c$nbns = info;
		# print fmt("%s %s %s %s %s %s %s", network_time(), c$id$orig_h, c$id$resp_h, c$orig$l2_addr, name_type, half_to_full(queries_name[1:-1]), additional_records_ttl);
	}
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
		if ( i?$Name ){
			info$Name = i$Name;
		}
		if ( i?$TTL ){
			info$TTL = i$TTL;
		}
		if ( i?$ServiceType ){
			info$ServiceType = i$ServiceType;
		}
		# if ( res_aggregationData[i]?$ts_e ){
		# 	info$ts_end = res_aggregationData[i]$ts_e;
		# }
		# if ( res_aggregationData[i]?$num ){
		# 	info$pkts = res_aggregationData[i]$num;
		# }
		# print res_aggregationData;
		# print info;
		Log::write(NBNS::LOG, info);
    }
	}