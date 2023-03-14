module CIFS;

export {
	redef enum Log::ID += { LOG };

	type Info: record {
		ts:		time &log &optional;
		SrcIP:	addr &log &optional;
		SrcMAC: string &log &optional;
		ServerName: string &log &optional;
		OSVersion: string &log &optional;
		ServerType: string &log &optional;
		BrowserVersion: string &log &optional;
		Signature: string &log &optional;
		HostComment: string &log &optional;


		# Set to block number of final piece of data once received.
		final_block: count &optional;

		# Set to true once logged.
		done: bool &default=F;
	};

	## Event that can be handled to access the cifs logging record.
	global log_cifs: event(rec: Info);

	global res_endCode: table[string] of string = { ["\x00\x00"] = "nomal", 
	                                    ["\xCF\x80"] = "stop",
										};

	type AggregationData: record {
		SrcIP:	addr &log &optional;
		SrcMAC: string &log &optional;
		ServerName: string &log &optional;
		OSVersion: string &log &optional;
		ServerType: string &log &optional;
		BrowserVersion: string &log &optional;
		Signature: string &log &optional;
		HostComment: string &log &optional;
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
	if ( idx?$ServerName ){
		info_insert$ServerName = idx$ServerName;
	}
	if ( idx?$OSVersion ){
		info_insert$OSVersion = idx$OSVersion;
	}
	if ( idx?$ServerType ){
		info_insert$ServerType = idx$ServerType;
	}
	if ( idx?$BrowserVersion ){
		info_insert$BrowserVersion = idx$BrowserVersion;
	}
	if ( idx?$Signature ){
		info_insert$Signature = idx$Signature;
	}
	if ( idx?$HostComment ){
		info_insert$HostComment = idx$HostComment;
	}
	# if ( res_aggregationData[idx]?$ts_e ){
	# 	info_insert$ts_end = res_aggregationData[idx]$ts_e;
	# }
	# if ( res_aggregationData[idx]?$num ){
	# 	info_insert$pkts = res_aggregationData[idx]$num;
	# }
	# print res_aggregationData;
	# print info;
	Log::write(CIFS::LOG, info_insert);
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
	if ( info?$ServerName ){
		aggregationData$ServerName = info$ServerName;
	}
	if ( info?$OSVersion ){
		aggregationData$OSVersion = info$OSVersion;
	}
	if ( info?$ServerType ){
		aggregationData$ServerType = info$ServerType;
	}
	if ( info?$BrowserVersion ){
		aggregationData$BrowserVersion = info$BrowserVersion;
	}
	if ( info?$Signature ){
		aggregationData$Signature = info$Signature;
	}
	if ( info?$HostComment ){
		aggregationData$HostComment = info$HostComment;
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
	cifs: Info &optional;
};

event zeek_init() &priority=5
	{
	Log::create_stream(CIFS::LOG, [$columns = Info, $ev = log_cifs, $path="cifs"]);
	}

function find_string(s: string): string
	{
	local x = "\x00";
	local res = "";

	for ( c in s )
		{
		if ( c == x )
			{
			break;
			}
		else
			{
			res = res + c;
			}
		}
	if ( res == "" )
		{
		return "";
		}

	return res;
	}

function uint16_to_hex(num: int): string
	{
	local hex_list: table[count] of string = { [0] = "0", [1] = "1", [2] = "2", [3] = "3", [4] = "4", [5] = "5", [6] = "6", 
    [7] = "7", [8] = "8", [9] = "9", [10] = "a", [11] = "b", [12] = "c", 
    [13] = "d", [14] = "e", [15] = "f", };

	local left = 0;
	local right = 0;
	
    right = int_to_count(num) % 16;
    left = int_to_count(num) / 16;
    
    local res = hex_list[left] +  hex_list[right];
    return cat(res);
	}

function del_0(s: string): string
	{
	local i = 0;
	for ( c in s )
		{
		if ( c == "0" )
			{
			i = 1 + i;
			next;
			}
		else
			{
			break;
			}
		}
	return s[i:];
	}

event CIFS::hostAnnouncement(
	c: connection, serverName: string, osversion_1: int, osversion_2: int,
	serverType_1: int, serverType_2: int, serverType_3: int, serverType_4: int,
	browserVersion_1: int, browserVersion_2: int, signature_1: string, signature_2: string, 
	hostComment: string
	)
	{

	local info: Info;
	local aggregationData: AggregationData;

	info$ts = network_time();
	info$SrcIP = c$id$orig_h;
	info$SrcMAC = c$orig$l2_addr;
	info$ServerName = find_string(serverName);
	info$OSVersion = cat(osversion_1) + "." + cat(osversion_2);
	info$ServerType = "0x" + del_0(uint16_to_hex(serverType_4) + uint16_to_hex(serverType_3) + uint16_to_hex(serverType_2) + uint16_to_hex(serverType_1));
	info$BrowserVersion = cat(browserVersion_1) + "." + cat(browserVersion_2);
	info$Signature = "0x" + string_to_ascii_hex(signature_2) + string_to_ascii_hex(signature_1);
	info$HostComment = find_string(hostComment);

	# Log::write(CIFS::LOG,info);
	aggregationData = create_aggregationData(info);
	insert_res_aggregationData(aggregationData, info);
	c$cifs = info;
	# print fmt("Zeek saw from %s %s to %s: %s host", c$start_time, c$id$orig_h, c$id$resp_h, c$orig$l2_addr);
	}

event CIFS::localMatserAnnouncement(
	c: connection, serverName: string, osversion_1: int, osversion_2: int,
	serverType_1: int, serverType_2: int, serverType_3: int, serverType_4: int,
	browserVersion_1: int, browserVersion_2: int, signature_1: string, signature_2: string, 
	hostComment: string
									)
	{

	local info: Info;
	local aggregationData: AggregationData;

	info$ts = network_time();
	info$SrcIP = c$id$orig_h;
	info$SrcMAC = c$orig$l2_addr;
	info$ServerName = find_string(serverName);
	info$OSVersion = cat(osversion_1) + "." + cat(osversion_2);
	info$ServerType = "0x" + del_0(uint16_to_hex(serverType_4) + uint16_to_hex(serverType_3) + uint16_to_hex(serverType_2) + uint16_to_hex(serverType_1));
	info$BrowserVersion = cat(browserVersion_1) + "." + cat(browserVersion_2);
	info$Signature = "0x" + string_to_ascii_hex(signature_2) + string_to_ascii_hex(signature_1);
	info$HostComment = find_string(hostComment);

	# Log::write(CIFS::LOG,info);
	aggregationData = create_aggregationData(info);
	insert_res_aggregationData(aggregationData, info);
	c$cifs = info;
	# print fmt("Zeek saw from %s %s to %s: %s %s local", c$start_time, c$id$orig_h, c$id$resp_h, c$orig$l2_addr, network_time());
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
		if ( i?$ServerName ){
			info$ServerName = i$ServerName;
		}
		if ( i?$OSVersion ){
			info$OSVersion = i$OSVersion;
		}
		if ( i?$ServerType ){
			info$ServerType = i$ServerType;
		}
		if ( i?$BrowserVersion ){
			info$BrowserVersion = i$BrowserVersion;
		}
		if ( i?$Signature ){
			info$Signature = i$Signature;
		}
		if ( i?$HostComment ){
			info$HostComment = i$HostComment;
		}
		# if ( res_aggregationData[i]?$ts_e ){
		# 	info$ts_end = res_aggregationData[i]$ts_e;
		# }
		# if ( res_aggregationData[i]?$num ){
		# 	info$pkts = res_aggregationData[i]$num;
		# }
		# print res_aggregationData;
		# print info;
		Log::write(CIFS::LOG, info);
    }
	}
