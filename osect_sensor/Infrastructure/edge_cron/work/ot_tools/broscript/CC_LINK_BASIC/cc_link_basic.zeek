module cclink_ie_field_basic;

export {
	redef enum Log::ID += { LOG };

	type Info: record {
		## Timestamp for when the request happened.
		ts:		time &log;
		## Unique ID for the connection.
		uid:	string &log;
		## The connection's 4-tuple of endpoint addresses/ports.
		id:		conn_id &log;
		pdu:	string &log;
		cmd:    string &log;
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
}

# Maps a partial data connection ID to the request's Info record.
global expected_data_conns: table[addr, port, addr] of Info;

redef record connection += {
	cclink_ie_field_basic: Info &optional;
};

event zeek_init() &priority=5
	{
	Log::create_stream(cclink_ie_field_basic::LOG, [$columns = Info, $ev = log_cclink_ie_field_basic, $path="cclink_ie_field_basic"]);
	}

function log_pending(c: connection)
	{
	if ( ! c?$cclink_ie_field_basic || c$cclink_ie_field_basic$done )
		return;

	Log::write(cclink_ie_field_basic::LOG, c$cclink_ie_field_basic);
	c$cclink_ie_field_basic$done = T;
	}

# function schedule_tftp_analyzer(id: conn_id) 
# 	{
# 	Analyzer::schedule_analyzer(0.0.0.0, id$orig_h, id$orig_p, Analyzer::get_tag("spicy_cclink_ie_field_basic"), 20min);
# 	Analyzer::schedule_analyzer(0.0.0.0, id$resp_h, id$orig_p, Analyzer::get_tag("spicy_cclink_ie_field_basic"), 20min);
# 	}

event cclink_ie_field_basic::cyclicDataReq(c: connection, dl: int, command: string, subCommand: string,
							reqData_protocolVer: string,
							reqData_offsetAddrInfo_cyclicInfoOffsetAddr: string,
							reqData_masterNoticeInfo_protocolVer1: string,
							reqData_cyclicInfoRQ_masterID: string , reqData_cyclicInfoRQ_groupNo: string , reqData_cyclicInfoRQ_parameterNo: string , reqData_cyclicInfoRQ_slaveTotalOccupiedStationCount: int , reqData_cyclicInfoRQ_cyclicTransmissionState: string, reqData_cyclicInfoRQ_slaveNo_slaveID: string
							)
	{
	log_pending(c);

	local info: Info;
	info$ts  = network_time();
	info$uid = c$uid;
	info$id  = c$id;
	info$pdu = "cyclicDataReq";
	if (command in res_cmd){
		info$cmd = res_cmd[command];
	} else {
		info$cmd = "unknown_ct_" + command;
	}
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
	# schedule_tftp_analyzer(c$id);
	}

event cclink_ie_field_basic::cyclicDataRes(c: connection, dl: int,
							resData_protocolVer: string, 
							resData_endCode: string, 
							resData_offsetAddrInfo_cyclicInfoOffsetAddr: string,
							resData_slaveNoticeInfo_protocolVer1: string,
							resData_cyclicInfo_slaveID: string, resData_cyclicInfo_groupNo: string
							)
	{
	log_pending(c);

	local info: Info;
	info$ts  = network_time();
	info$uid = c$uid;
	info$id  = c$id;
	info$pdu = "cyclicDataRes";
	# info$dl = dl;
	# info$resData_protocolVer = resData_protocolVer;
	# info$resData_endCode = res_endCode[resData_endCode];
	# info$resData_offsetAddrInfo_cyclicInfoOffsetAddr = resData_offsetAddrInfo_cyclicInfoOffsetAddr;
	# info$resData_slaveNoticeInfo_protocolVer1 = resData_slaveNoticeInfo_protocolVer1;
	# info$resData_cyclicInfo_slaveID = resData_cyclicInfo_slaveID;
	# info$resData_cyclicInfo_groupNo = resData_cyclicInfo_groupNo;
	c$cclink_ie_field_basic = info;
	# print fmt("Zeek saw from %s %s to %s: dl:%s", c$start_time, c$id$orig_h, c$id$resp_h, dl);
	# schedule_tftp_analyzer(c$id);
	}
