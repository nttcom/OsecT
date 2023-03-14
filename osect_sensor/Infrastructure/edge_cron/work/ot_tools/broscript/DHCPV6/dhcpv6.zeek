module DHCPV6;

export {
	redef enum Log::ID += { LOG };

	type Info: record {
		ts:		time &log &optional;
		SrcIP:	addr &log &optional;
		SrcMAC: string &log &optional;
		Hostname: string &log &optional;
		FingerPrint: vector of count &log &optional;
		EnterpriseNumber: count &log &optional;
		VendorClass: string &log &optional;

		# Set to block number of final piece of data once received.
		final_block: count &optional;

		# Set to true once logged.
		done: bool &default=F;
	};

	## Event that can be handled to access the dhcpv6 logging record.
	global log_dhcpv6: event(rec: Info);

	global res_endCode: table[string] of string = { ["\x00\x00"] = "nomal", 
	                                    ["\xCF\x80"] = "stop",
										};
	
	type AggregationData: record {
		SrcIP:	addr &log &optional;
		SrcMAC: string &log &optional;
		Hostname: string &log &optional;
		FingerPrint: vector of count &log &optional;
		EnterpriseNumber: count &log &optional;
		VendorClass: string &log &optional;
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
	if ( idx?$FingerPrint ){
		info_insert$FingerPrint = idx$FingerPrint;
	}
	if ( idx?$EnterpriseNumber ){
		info_insert$EnterpriseNumber = idx$EnterpriseNumber;
	}
	if ( idx?$VendorClass ){
		info_insert$VendorClass = idx$VendorClass;
	}
	# if ( res_aggregationData[idx]?$ts_e ){
	# 	info_insert$ts_end = res_aggregationData[idx]$ts_e;
	# }
	# if ( res_aggregationData[idx]?$num ){
	# 	info_insert$pkts = res_aggregationData[idx]$num;
	# }
	# print res_aggregationData;
	# print info;
	Log::write(DHCPV6::LOG, info_insert);
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
	if ( info?$FingerPrint ){
		aggregationData$FingerPrint = info$FingerPrint;
	}
	if ( info?$EnterpriseNumber ){
		aggregationData$EnterpriseNumber = info$EnterpriseNumber;
	}
	if ( info?$VendorClass ){
		aggregationData$VendorClass = info$VendorClass;
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
	dhcpv6: Info &optional;
};

function add_head(c1: count, v1: vector of count): vector of count
{
	local y: vector of count = { c1 };
	for ( i in  v1) 
	{
		y[|y|] = v1[i];
	}
	return y;
}

function del_hex(s: string): string
{
	local res = "";
	for ( c in s )
		{
		if ( c == "\x05" || c == "\x00" )
			{
			next;
			}
		else
			{
			res = res + c;
			}
		}
	return res;
}

event zeek_init() &priority=5
	{
	Log::create_stream(DHCPV6::LOG, [$columns = Info, $ev = log_dhcpv6, $path="dhcpv6"]);
	}

type Options: record {
	host_name: string;
	vendor: string;
	enterprise: count;
	rq_code: vector of count;
};

event DHCPV6::message(c: connection, is_orig: bool, options: Options)
	{
	local info: Info;
	local aggregationData: AggregationData;

	info$ts = network_time();
	info$SrcIP = c$id$orig_h;
	info$SrcMAC = c$orig$l2_addr;
	if ( options$host_name != "" ){
		info$Hostname = del_hex(options$host_name);
	}
	if ( options$enterprise != 0 ){
		info$EnterpriseNumber = options$enterprise;
	}
	if ( options$enterprise != 0 && |options$rq_code| != 0){
		info$FingerPrint = add_head(options$enterprise, options$rq_code);
	} else if (options$enterprise == 0 && |options$rq_code| != 0) {
		info$FingerPrint = options$rq_code;
	} else if (options$enterprise != 0 && |options$rq_code| == 0) {
		info$FingerPrint = add_head(options$enterprise, options$rq_code);
	}
	if ( options$vendor != "" ){
		info$VendorClass = options$vendor;
	}

	# Log::write(DHCPV6::LOG, info);
	aggregationData = create_aggregationData(info);
	insert_res_aggregationData(aggregationData, info);
	c$dhcpv6 = info;
	# print fmt("Zeek saw from %s %s to %s: %s options: %s", c$start_time, c$id$orig_h, c$id$resp_h, c$orig$l2_addr, options$host_name);
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
		if ( i?$FingerPrint ){
			info$FingerPrint = i$FingerPrint;
		}
		if ( i?$EnterpriseNumber ){
			info$EnterpriseNumber = i$EnterpriseNumber;
		}
		if ( i?$VendorClass ){
			info$VendorClass = i$VendorClass;
		}
		# if ( res_aggregationData[i]?$ts_e ){
		# 	info$ts_end = res_aggregationData[i]$ts_e;
		# }
		# if ( res_aggregationData[i]?$num ){
		# 	info$pkts = res_aggregationData[i]$num;
		# }
		# print res_aggregationData;
		# print info;
		Log::write(DHCPV6::LOG, info);
    }
	}
