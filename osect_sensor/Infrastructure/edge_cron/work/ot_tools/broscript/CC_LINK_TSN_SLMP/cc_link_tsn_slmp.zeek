module CCLINK_IE_TSN_SLMP;

export {
	redef enum Log::ID += { LOG_TSN_SLMP };

	type Info: record {
		ts:		time &log &optional;
		uid:	        string &log &optional;
		id:		conn_id &log &optional;
		service:	string &log &optional;
		flame_type: 	string &log &optional;
		pdu_type:       string &log &optional;
		cmd:		string &log &optional;
		number:		int &log &optional;
		ts_end:		time &log &optional;
	};

	global log_tsn_slmp: event(rec: Info);

	type AggregationData: record {
		uid:	        string &log &optional;
		id:		conn_id &log &optional;
		service:	string &log &optional;
		flame_type: 	string &log &optional;
		pdu_type:       string &log &optional;
		cmd:		string &log &optional;
	};

	type Ts_num: record {
		ts_s:		time &log;
		num: 		int &log;
		ts_e: 		time &log &optional;
	};

	function insert_log(res_aggregationData: table[AggregationData] of Ts_num, idx: AggregationData): interval
	{
	local info_insert: Info = [];
	info_insert$ts = res_aggregationData[idx]$ts_s;
	info_insert$uid = idx$uid;
	info_insert$id = idx$id;
	info_insert$service = idx$service;
	info_insert$flame_type = idx$flame_type;
	info_insert$pdu_type = idx$pdu_type;
	info_insert$cmd = idx$cmd;
	if ( res_aggregationData[idx]?$ts_e ){
		info_insert$ts_end = res_aggregationData[idx]$ts_e;
	}
	if ( res_aggregationData[idx]?$num ){
		info_insert$number = res_aggregationData[idx]$num;
	}

	Log::write(LOG_TSN_SLMP, info_insert);

	return 0secs;
	}

	global res_aggregationData: table[AggregationData] of Ts_num &create_expire=60sec &expire_func=insert_log;
}

global expected_data_conns: table[addr, port, addr] of Info;

redef record connection += {
	CCLINK_IE_TSN_SLMP: Info &optional;
};

event zeek_init() &priority=5
{
	Log::create_stream(CCLINK_IE_TSN_SLMP::LOG_TSN_SLMP, [$columns = Info, $ev = log_tsn_slmp, $path="cclink-ie-tsn-slmp"]);
}


function create_aggregationData(info: Info): AggregationData
{
	local aggregationData: AggregationData;
	aggregationData$uid= info$uid;
	aggregationData$id = info$id;
	aggregationData$service = info$service;
	aggregationData$flame_type = info$flame_type;
	aggregationData$pdu_type = info$pdu_type;
	aggregationData$cmd = info$cmd;

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


event tsn_slmp::reqLMT(c: connection, command: string, subcommand: string)
{
	local info: Info;
	local aggregationData: AggregationData;
	info$ts = network_time();
	info$uid = c$uid;
	info$id  = c$id;
	info$service = "cclink_ie_tsn";
	info$flame_type = "ip";
	info$pdu_type = "";
	info$cmd = "";
	if (command == "\x90\x0e" && subcommand == "\x00\x00") {
		info$pdu_type = "slmp-networkConfigMain";
		info$cmd = "ReqNetworkConfigMain";
		aggregationData = create_aggregationData(info);
		insert_res_aggregationData(aggregationData, info);
		c$CCLINK_IE_TSN_SLMP = info;
	}
	else if (command == "\x90\x0e" && subcommand == "\x01\x00") {
		info$pdu_type = "slmp-networkConfigTslt";
		info$cmd = "ReqNetworkConfigTslt";
		aggregationData = create_aggregationData(info);
		insert_res_aggregationData(aggregationData, info);
		c$CCLINK_IE_TSN_SLMP = info;
	}
	else if (command == "\x94\x0e" && subcommand == "\x00\x00") {
		info$pdu_type = "slmp-notification";
		info$cmd = "ReqNotification";
		aggregationData = create_aggregationData(info);
		insert_res_aggregationData(aggregationData, info);
		c$CCLINK_IE_TSN_SLMP = info;
	}
	else if (command == "\x91\x0e"  && subcommand == "\x00\x00") {
		info$pdu_type = "slmp-masterConfig";
		info$cmd = "ReqMasterConfig";
		aggregationData = create_aggregationData(info);
		insert_res_aggregationData(aggregationData, info);
		c$CCLINK_IE_TSN_SLMP = info;
	}
	else if (command == "\x92\x0e"  && subcommand == "\x00\x00") {
		info$pdu_type = "slmp-slaveConfig";
		info$cmd = "ReqSlaveConfig";
		aggregationData = create_aggregationData(info);
		insert_res_aggregationData(aggregationData, info);
		c$CCLINK_IE_TSN_SLMP = info;
	}
	else if (command == "\x93\x0e"  && subcommand == "\x00\x00") {
		info$pdu_type = "slmp-cyclicConfigMain";
		info$cmd = "ReqCyclicConfigMain";
		aggregationData = create_aggregationData(info);
		insert_res_aggregationData(aggregationData, info);
		c$CCLINK_IE_TSN_SLMP = info;
	}
	else if (command == "\x93\x0e"  && subcommand == "\x01\x00") {
		info$pdu_type = "slmp-cyclicConfigTrnSubPayload";
		info$cmd = "ReqCyclicConfigTrnSubPayload";
		aggregationData = create_aggregationData(info);
		insert_res_aggregationData(aggregationData, info);
		c$CCLINK_IE_TSN_SLMP = info;
	}
	else if (command == "\x93\x0e"  && subcommand == "\x02\x00") {
		info$pdu_type = "slmp-cyclicConfigRcvSubPayload";
		info$cmd = "ReqCyclicConfigRcvSubPayload";
		aggregationData = create_aggregationData(info);
		insert_res_aggregationData(aggregationData, info);
		c$CCLINK_IE_TSN_SLMP = info;
	}
	else if (command == "\x93\x0e"  && subcommand == "\x03\x00") {
		info$pdu_type = "slmp-cyclicConfigRcvSrcInfo";
		info$cmd = "ReqCyclicConfigRcvSrcInfo";
		aggregationData = create_aggregationData(info);
		insert_res_aggregationData(aggregationData, info);
		c$CCLINK_IE_TSN_SLMP = info;
	}	
}


event tsn_slmp::resLMT(c: connection, command: string, subcommand: string)
{
	local info: Info;
	local aggregationData: AggregationData;
	info$ts = network_time();
	info$uid = c$uid;
	info$id  = c$id;
	info$service = "cclink_ie_tsn";
	info$flame_type = "ip";
	info$pdu_type = "";
	info$cmd = "";
	if (command == "\x90\x0e" && subcommand == "\x00\x00") {
		info$pdu_type = "slmp-networkConfigMain";
		info$cmd = "ResNetworkConfigMain";
		aggregationData = create_aggregationData(info);
		insert_res_aggregationData(aggregationData, info);
		c$CCLINK_IE_TSN_SLMP = info;
	}
	else if (command == "\x90\x0e" && subcommand == "\x01\x00") {
		info$pdu_type = "slmp-networkConfigTslt";
		info$cmd = "ResNetworkConfigTslt";
		aggregationData = create_aggregationData(info);
		insert_res_aggregationData(aggregationData, info);
		c$CCLINK_IE_TSN_SLMP = info;
	}
	else if (command == "\x94\x0e" && subcommand == "\x00\x00") {
		info$pdu_type = "slmp-notification";
		info$cmd = "ResNotification";
		aggregationData = create_aggregationData(info);
		insert_res_aggregationData(aggregationData, info);
		c$CCLINK_IE_TSN_SLMP = info;
	}
	else if ( command == "\x91\x0e"  && subcommand == "\x00\x00") {
		info$pdu_type = "slmp-masterConfig";
		info$cmd = "ResMasterConfig";
		aggregationData = create_aggregationData(info);
		insert_res_aggregationData(aggregationData, info);
		c$CCLINK_IE_TSN_SLMP = info;
	}
	else if ( command == "\x92\x0e"  && subcommand == "\x00\x00") {
		info$pdu_type = "slmp-slaveConfig";
		info$cmd = "ResSlaveConfig";
		aggregationData = create_aggregationData(info);
		insert_res_aggregationData(aggregationData, info);
		c$CCLINK_IE_TSN_SLMP = info;
	}
}


#local debug
event zeek_done()
{
	for ( i in res_aggregationData )
	{
		local info: Info = [];
		info$ts = res_aggregationData[i]$ts_s;
		info$uid = i$uid;
		info$id = i$id;
		info$service = i$service;
		info$flame_type = i$flame_type;
		info$pdu_type = i$pdu_type;
		info$cmd = i$cmd;
		if ( res_aggregationData[i]?$ts_e ){
			info$ts_end = res_aggregationData[i]$ts_e;
		}
		if ( res_aggregationData[i]?$num ){
			info$number = res_aggregationData[i]$num;
		}

		Log::write(CCLINK_IE_TSN_SLMP::LOG_TSN_SLMP, info);
	}
}
