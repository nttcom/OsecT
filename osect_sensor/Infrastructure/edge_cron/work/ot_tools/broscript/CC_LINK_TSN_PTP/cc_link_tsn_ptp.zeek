module PacketAnalyzer::SPICY_RAWLAYER;
module TSN_PTP;

export {
	redef enum Log::ID += { LOG };

	type Info: record {
		ts:			time &log &optional;
		src_mac:		string &log &optional;
		dst_mac:		string &log &optional;
		service:		string &log &optional;
		flame_type: 		string &log &optional;
		pdu_type:               string &log &optional;
		number:			int &log &optional;
		ts_end:			time &log &optional;
	};

	type AggregationData: record {
		src_mac:		string &log &optional;
		dst_mac:		string &log &optional;
		service:		string &log &optional;
		flame_type: 		string &log &optional;
		pdu_type:               string &log &optional;
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
	info_insert$src_mac = idx$src_mac;
	info_insert$dst_mac = idx$dst_mac;
	info_insert$service = idx$service;
	info_insert$flame_type = idx$flame_type;
	info_insert$pdu_type = idx$pdu_type;
	if ( res_aggregationData[idx]?$ts_e ){
		info_insert$ts_end = res_aggregationData[idx]$ts_e;
	}
	if ( res_aggregationData[idx]?$num ){
		info_insert$number = res_aggregationData[idx]$num;
	}
	Log::write(TSN_PTP::LOG, info_insert);

	return 0secs;
	}

	global res_aggregationData: table[AggregationData] of Ts_num &create_expire=60sec &expire_func=insert_log;
}

event zeek_init() &priority=5
	{
	Log::create_stream(TSN_PTP::LOG, [$columns = Info, $path="cclink-ie-tsn-ptp"]);
	}

event zeek_init()
	{
	if ( ! PacketAnalyzer::try_register_packet_analyzer_by_name("Ethernet", 0x88f7, "spicy::TSN_PTP") )
		print "cannot register raw layer analyzer";
	}

function create_aggregationData(info: Info): AggregationData
	{
	local aggregationData: AggregationData;
	aggregationData$src_mac = info$src_mac;
	aggregationData$dst_mac = info$dst_mac;
	aggregationData$service = info$service;
	aggregationData$flame_type = info$flame_type;
	aggregationData$pdu_type = info$pdu_type;

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


event raw::ptpSync(p: raw_pkt_hdr)
	{
	local info: Info;
	local aggregationData: AggregationData;
	info$ts = network_time();
	info$src_mac = p$l2$src;
	info$dst_mac = p$l2$dst;
	info$service = "cclink_ie_tsn";
	info$flame_type = "ptp";
	info$pdu_type = "ptpSync";
		
	aggregationData = create_aggregationData(info);
	insert_res_aggregationData(aggregationData, info);
	}


event raw::ptpPdelayReq(p: raw_pkt_hdr)
	{
	local info: Info;
	local aggregationData: AggregationData;
	info$ts = network_time();
	info$src_mac = p$l2$src;
	info$dst_mac = p$l2$dst;
	info$service = "cclink_ie_tsn";
	info$flame_type = "ptp";
	info$pdu_type = "ptpPdelayReq";
		
	aggregationData = create_aggregationData(info);
	insert_res_aggregationData(aggregationData, info);
	}


event raw::ptpPdelayResp(p: raw_pkt_hdr)
	{
	local info: Info;
	local aggregationData: AggregationData;
	info$ts = network_time();
	info$src_mac = p$l2$src;
	info$dst_mac = p$l2$dst;
	info$service = "cclink_ie_tsn";
	info$flame_type = "ptp";
	info$pdu_type = "ptpPdelayResp";
		
	aggregationData = create_aggregationData(info);
	insert_res_aggregationData(aggregationData, info);
	}


event raw::ptpFollowUp(p: raw_pkt_hdr)
	{
	local info: Info;
	local aggregationData: AggregationData;
	info$ts = network_time();
	info$src_mac = p$l2$src;
	info$dst_mac = p$l2$dst;
	info$service = "cclink_ie_tsn";
	info$flame_type = "ptp";
	info$pdu_type = "ptpFollowUp";
		
	aggregationData = create_aggregationData(info);
	insert_res_aggregationData(aggregationData, info);
	}


event raw::ptpPdelayRespFollowUp(p: raw_pkt_hdr)
	{
	local info: Info;
	local aggregationData: AggregationData;
	info$ts = network_time();
	info$src_mac = p$l2$src;
	info$dst_mac = p$l2$dst;
	info$service = "cclink_ie_tsn";
	info$flame_type = "ptp";
	info$pdu_type = "ptpPdelayRespFollowUp";

	aggregationData = create_aggregationData(info);
	insert_res_aggregationData(aggregationData, info);
	}


event raw::ptpAnnounce(p: raw_pkt_hdr)
	{
	local info: Info;
	local aggregationData: AggregationData;
	info$ts = network_time();
	info$src_mac = p$l2$src;
	info$dst_mac = p$l2$dst;
	info$service = "cclink_ie_tsn";
	info$flame_type = "ptp";
	info$pdu_type = "ptpAnnounce";
		
	aggregationData = create_aggregationData(info);
	insert_res_aggregationData(aggregationData, info);
	}


event raw::ptpdelayReq(p: raw_pkt_hdr)
	{
	local info: Info;
	local aggregationData: AggregationData;
	info$ts = network_time();
	info$src_mac = p$l2$src;
	info$dst_mac = p$l2$dst;
	info$service = "cclink_ie_tsn";
	info$flame_type = "ptp";
	info$pdu_type = "ptpdelayReq";
		
	aggregationData = create_aggregationData(info);
	insert_res_aggregationData(aggregationData, info);
	}


event raw::ptpdelayResp(p: raw_pkt_hdr)
	{
	local info: Info;
	local aggregationData: AggregationData;
	info$ts = network_time();
	info$src_mac = p$l2$src;
	info$dst_mac = p$l2$dst;
	info$service = "cclink_ie_tsn";
	info$flame_type = "ptp";
	info$pdu_type = "ptpdelayResp";
		
	aggregationData = create_aggregationData(info);
	insert_res_aggregationData(aggregationData, info);
	}


#local debug
event zeek_done()
{
	for ( i in res_aggregationData )
	{
		local info: Info = [];
		info$ts = res_aggregationData[i]$ts_s;
		info$src_mac = i$src_mac;
		info$dst_mac = i$dst_mac;
		info$service = i$service;
		info$flame_type = i$flame_type;
		info$pdu_type = i$pdu_type;
		if ( res_aggregationData[i]?$ts_e ){
			info$ts_end = res_aggregationData[i]$ts_e;
		}
		if ( res_aggregationData[i]?$num ){
			info$number = res_aggregationData[i]$num;
		}

		Log::write(TSN_PTP::LOG, info);
	}
}
