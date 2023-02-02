module cclink_ie_field_basic;

export {
	redef enum Log::ID += { LOG };

	type Info: record {
		## Timestamp for when the request happened.
		ts:		time &log &optional;
		## Unique ID for the connection.
		uid:	string &log &optional;
		## The connection's 4-tuple of endpoint addresses/ports.
		id:		conn_id &log &optional;
		pdu:	string &log &optional;
		cmd:    string &log &optional;
		# ## cclink_ie_field_basic data.
		# dl:	int &log;
		# ## cclink_ie_field_basic REQ data.
		# command:	string &log;
		# ## cclink_ie_field_basic REQ data.
		# subCommand:	string &log;
		# ## cclink_ie_field_basic REQ data.
		# reqData_protocolVer:	string &log;
		# ## cclink_ie_field_basic REQ data.	
		# reqData_masterNoticeInfo_protocolVer1:	string &log;
		# ## cclink_ie_field_basic REQ data.	
		# reqData_cyclicInfoRQ_masterID:	string &log;
		# ## cclink_ie_field_basic REQ data.	
		# reqData_cyclicInfoRQ_groupNo:	string &log;
		# ## cclink_ie_field_basic REQ data.	
		# reqData_cyclicInfoRQ_parameterNo:	string &log;
		# ## cclink_ie_field_basic REQ data.	
		# reqData_cyclicInfoRQ_slaveTotalOccupiedStationCount:	int &log;
		# ## cclink_ie_field_basic REQ data.	
		# reqData_cyclicInfoRQ_cyclicTransmissionState:	string &log;
		# ## cclink_ie_field_basic REQ data.	
		# reqData_cyclicInfoRQ_slaveNo_slaveID:	string &log;
		# ## cclink_ie_field_basic RES data.	
		# resData_protocolVer:	string &log;
		# ## cclink_ie_field_basic RES data.	
		# resData_endCode:	string &log;
		# ## cclink_ie_field_basic RES data.	
		# resData_offsetAddrInfo_cyclicInfoOffsetAddr:	string &log;
		# ## cclink_ie_field_basic RES data.	
		# resData_slaveNoticeInfo_protocolVer1:	string &log;
		# ## cclink_ie_field_basic RES data.	
		# resData_cyclicInfo_slaveID:	string &log;
		# ## cclink_ie_field_basic RES data.	
		# resData_cyclicInfo_groupNo:	string &log;
		number:			int &log &optional;
		ts_end:			time &log &optional;

		# Set to block number of final piece of data once received.
		final_block: count &optional;

		# Set to true once logged.
		done: bool &default=F;
	};

	## Event that can be handled to access the cclink_ie_field_basic logging record.
	global log_cclink_ie_field_basic: event(rec: Info);

	global res_endCode: table[string] of string = { ["\x00\x00"] = "nomal", 
	                                    ["\xCF\x80"] = "stop",};
	
	global res_cmd: table[string] of string = { ["p\x0e"] = "cyclic",};

	type AggregationData: record {
		uid:	string &log &optional;
		id:		conn_id &log &optional;
		pdu:	string &log &optional;
		cmd:    string &log &optional;
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
	info_insert$uid = idx$uid;
	info_insert$id = idx$id;
	info_insert$pdu = idx$pdu;
	if ( idx?$cmd ){
		info_insert$cmd = idx$cmd;
	}
	if ( res_aggregationData[idx]?$ts_e ){
		info_insert$ts_end = res_aggregationData[idx]$ts_e;
	}
	if ( res_aggregationData[idx]?$num ){
		info_insert$number = res_aggregationData[idx]$num;
	}
	# print res_aggregationData;
	# print info;
	Log::write(cclink_ie_field_basic::LOG, info_insert);
	# res_aggregationData = {};
	return 0secs;
	}

	global res_aggregationData: table[AggregationData] of Ts_num &create_expire=60sec &expire_func=insert_log;
}

# Maps a partial data connection ID to the request's Info record.
global expected_data_conns: table[addr, port, addr] of Info;

redef record connection += {
	cclink_ie_field_basic: Info &optional;
};

event zeek_init() &priority=5
	{
	Log::create_stream(cclink_ie_field_basic::LOG, [$columns = Info, $ev = log_cclink_ie_field_basic, $path="cclink-ief-basic"]);
	}

function create_aggregationData(info: Info): AggregationData
	{
	local aggregationData: AggregationData;
	aggregationData$uid = info$uid;
	aggregationData$id = info$id;
	aggregationData$pdu = info$pdu;
	if ( info?$cmd ){
		aggregationData$cmd = info$cmd;
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

event cclink_ie_field_basic::cyclicDataReq(c: connection, dl: int, command: string, subCommand: string,
							reqData_protocolVer: string,
							reqData_offsetAddrInfo_cyclicInfoOffsetAddr: string,
							reqData_masterNoticeInfo_protocolVer1: string,
							reqData_cyclicInfoRQ_masterID: string , reqData_cyclicInfoRQ_groupNo: string , reqData_cyclicInfoRQ_parameterNo: string , reqData_cyclicInfoRQ_slaveTotalOccupiedStationCount: int , reqData_cyclicInfoRQ_cyclicTransmissionState: string, reqData_cyclicInfoRQ_slaveNo_slaveID: string
							)
	{

	local info: Info;
	local aggregationData: AggregationData;
	info$ts  = network_time();
	info$uid = c$uid;
	info$id  = c$id;
	info$pdu = "cyclicDataReq";
	if (command in res_cmd){
		info$cmd = res_cmd[command];
	} else {
		info$cmd = "unknown_ct_" + command;
	}

	aggregationData = create_aggregationData(info);
	insert_res_aggregationData(aggregationData, info);

	# Log::write(cclink_ie_field_basic::LOG, info);
	# info$dl = dl;
	# info$command = command;
	# info$subCommand = subCommand;
	# info$reqData_protocolVer = reqData_protocolVer;
	# info$reqData_masterNoticeInfo_protocolVer1 = reqData_masterNoticeInfo_protocolVer1;
	# info$reqData_cyclicInfoRQ_masterID = reqData_cyclicInfoRQ_masterID;
	# info$reqData_cyclicInfoRQ_groupNo = reqData_cyclicInfoRQ_groupNo;
	# info$reqData_cyclicInfoRQ_parameterNo = reqData_cyclicInfoRQ_parameterNo;
	# info$reqData_cyclicInfoRQ_slaveTotalOccupiedStationCount = reqData_cyclicInfoRQ_slaveTotalOccupiedStationCount;
	# info$reqData_cyclicInfoRQ_cyclicTransmissionState = reqData_cyclicInfoRQ_cyclicTransmissionState;
	# info$reqData_cyclicInfoRQ_slaveNo_slaveID = reqData_cyclicInfoRQ_slaveNo_slaveID;
	c$cclink_ie_field_basic = info;
	# print fmt("Zeek saw from %s %s to %s: dl:%s command:%s subCommanda:%s %s", c$start_time, c$id$orig_h, c$id$resp_h, dl, command, subCommand, reqData_protocolVer);
	}

event cclink_ie_field_basic::cyclicDataRes(c: connection, dl: int,
							resData_protocolVer: string, 
							resData_endCode: string, 
							resData_offsetAddrInfo_cyclicInfoOffsetAddr: string,
							resData_slaveNoticeInfo_protocolVer1: string,
							resData_cyclicInfo_slaveID: string, resData_cyclicInfo_groupNo: string
							)
	{

	local info: Info;
	local aggregationData: AggregationData;
	info$ts  = network_time();
	info$uid = c$uid;
	info$id  = c$id;
	info$pdu = "cyclicDataRes";

	aggregationData = create_aggregationData(info);
	insert_res_aggregationData(aggregationData, info);

	# Log::write(cclink_ie_field_basic::LOG, info);
	# info$dl = dl;
	# info$resData_protocolVer = resData_protocolVer;
	# info$resData_endCode = res_endCode[resData_endCode];
	# info$resData_offsetAddrInfo_cyclicInfoOffsetAddr = resData_offsetAddrInfo_cyclicInfoOffsetAddr;
	# info$resData_slaveNoticeInfo_protocolVer1 = resData_slaveNoticeInfo_protocolVer1;
	# info$resData_cyclicInfo_slaveID = resData_cyclicInfo_slaveID;
	# info$resData_cyclicInfo_groupNo = resData_cyclicInfo_groupNo;
	c$cclink_ie_field_basic = info;
	# print fmt("Zeek saw from %s %s to %s: dl:%s", c$start_time, c$id$orig_h, c$id$resp_h, dl);
	}

# # 集約 local debug用
# event zeek_done()
# 	{
# 	# print "zeek_done()";
# 	print res_aggregationData;
# 	for ( i in res_aggregationData ){
# 		# print i;
# 		local info: Info = [];
# 		info$ts = res_aggregationData[i]$ts_s;
# 		info$uid = i$uid;
# 		info$id = i$id;
# 		info$pdu = i$pdu;
# 		if ( i?$cmd ){
# 			info$cmd = i$cmd;
# 		}
# 		if ( res_aggregationData[i]?$ts_e ){
# 			info$ts_end = res_aggregationData[i]$ts_e;
# 		}
# 		if ( res_aggregationData[i]?$num ){
# 			info$number = res_aggregationData[i]$num;
# 		}
# 		# print res_aggregationData;
# 		# print info;
# 		Log::write(cclink_ie_field_basic::LOG, info);
# 	}
# 	# res_aggregationData = {};
# 	# print res_aggregationData;
# 	}
