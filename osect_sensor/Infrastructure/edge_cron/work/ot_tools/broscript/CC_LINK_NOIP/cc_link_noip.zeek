module PacketAnalyzer::SPICY_RAWLAYER;
module NO_IP;

export {
	redef enum Log::ID += { LOG_NOIP,
	                        LOG_TSN };

	type Info_NOIP: record {
		ts:		         time &log &optional;
		src_mac:		 string &log &optional;
		dst_mac:		 string &log &optional;
		service:		 string &log &optional;
		pdu_type: 		 string &log &optional;
		cmd:			 string &log &optional;
		node_type:		 string &log &optional;
		node_id:		 int &log &optional;
		connection_info:         string &log &optional;
		src_node_number:         string &log &optional;
		number:			 int &log &optional;
		ts_end:			 time &log &optional;
	};

	type Info_TSN: record {
		ts:			time &log &optional;
		src_mac:		string &log &optional;
		dst_mac:		string &log &optional;
		service:		string &log &optional;
		flame_type: 		string &log &optional;
		pdu_type:               string &log &optional;
		node_type:		string &log &optional;
		device_type:            string &log &optional;
		function_name:          string &log &optional;
		number:			int &log &optional;
		ts_end:			time &log &optional;
	};

	global res_nodetype_control: table[string] of string = { ["\x00"] = "management node", 
	                                                         ["\x02"] = "normal node",
								 ["!"] = "master node in the Node-to-node test",};
	
	global res_nodetype_field: table[string] of string = { ["0"] = "master node", 
							       ["2"] = "local node",
							       ["3"] = "intelligent device node",
							       ["4"] = "remote device node",
							       ["5"] = "remote I/O node",};

	global res_nodetype_tsn: table[string] of string = { ["\x00"] = "master station", 
	                                                     ["\x80"] = "master station",
							     ["\x01"] = "slave station",
							     ["\x81"] = "slave station",
							     ["\x02"] = "managed switch",
							     ["\x82"] = "managed switch",
							     ["\x03"] = "use prohibited",
							     ["\x83"] = "use prohibited",
							     ["\x04"] = "sub-master station",
							     ["\x84"] = "sub-master station",};

	global res_ct_1: table[string] of string = { ["0"] = "slmpTransmitRequest", 
	                                             ["\xb0"] = "slmpTransmitResponse",};

	global res_ct_2_field: table[string] of string = { ["\x04"] = "getMemoryAccessInfo", 
	                                                   ["\x08"] = "run",
							   ["\x09"] = "stop",
							   ["\x10"] = "readMemory",
							   ["\x12"] = "writeMemory",
							   ["\x20"] = "messageTransfer",};
	
	global res_ct_2_control: table[string] of string = { ["\x04"] = "getMemoryAccessInfo", 
	                                                     ["\x08"] = "run",
							     ["\x09"] = "stop",
							     ["\x10"] = "readMemory",
							     ["\x12"] = "writeMemory",};

	global res_command_7: table[string] of string = { ["\x01"] = "deliverNodeInformation", 
	                                                  ["\x03"] = "getStatisticalInformation",
							  ["\x04"] = "acquiresDetailedNodeInformation",
							  ["\x0a"] = "acquiresOptionalInformation",};
	
	global res_command_8: table[string] of string = { ["\x01"] = "communicationCycleSetting", 
	                                                  ["\x02"] = "objectRead",
							  ["\x03"] = "objectWrite",};
	
	global res_subCommand: table[string] of string = { ["\x80"] = "Response", 
	                                                   ["\x00"] = "Request",};
	
        global res_devicetype: table[string] of string = { ["\x00\x00"] = "not applicable", 
							   ["\x00\x01"] = "PLC",
							   ["\x00\x02"] = "personal computer",
							   ["\x00\x03"] = "digital I/O",
						           ["\x00\x04"] = "analog I/O",
							   ["\x00\x05"] = "positioning controller",
							   ["\x00\x06"] = "temperature controller",
							   ["\x00\x07"] = "HMI",
							   ["\x00\x08"] = "ID",
						           ["\x00\x09"] = "serial conversion module",
							   ["\x00\x1d"] = "cc-link to cc-link/LT bridge",
							   ["\x00\x1f"] = "service converter module",
							   ["\x00\x20"] = "inverter",
							   ["\x00\x21"] = "servo",
							   ["\x00\x22"] = "CNC",
							   ["\x00\x23"] = "robot",
							   ["\x00\x24"] = "power distribution control device",
							   ["\x00\x30"] = "sensor",
							   ["\x00\x31"] = "actuator",
							   ["\x00\x32"] = "barcode reader",
							   ["\x00\x33"] = "indicator (weight)",
							   ["\x00\x34"] = "high-speed counter",
							   ["\x00\x35"] = "switch",
							   ["\x00\x36"] = "service analyzer",
							   ["\x00\x37"] = "space transmission module",
							   ["\x00\x38"] = "transport control module",
							   ["\x00\x39"] = "power supply control module",
							   ["\x00\x3b"] = "gas detectorr",
							   ["\x00\x3c"] = "solenoid valve",
							   ["\x00\x3d"] = "robot (general-purpose)",
							   ["\x00\x3e"] = "printer control module",
							   ["\x00\x3f"] = "motor control module",
							   ["\x00\x40"] = "vacuum pump",
							   ["\x00\x41"] = "multi-axis controller",
							   ["\x00\x42"] = "general-purpose VME board",
							   ["\x00\x43"] = "mass flow power supply module",
							   ["\x00\x44"] = "mass flow controller",
							   ["\x00\x45"] = "received power distribution device",
							   ["\x00\x46"] = "control center",
							   ["\x00\x47"] = "welding control module",
							   ["\x00\x48"] = "indicator (general-purpose)",
							   ["\x00\x49"] = "PID control module",
							   ["\x00\x4a"] = "vacuum meter",
						           ["\x00\x4b"] = "wireless module",
							   ["\x00\x4c"] = "digital/analog I/O",
							   ["\x00\x4d"] = "vacuum valve",
							   ["\x00\x4e"] = "tension controller",
							   ["\x00\x4f"] = "measuring machiner",
							   ["\x00\x7f"] = "generic Device",};

	type AggregationData_NOIP: record {
		src_mac:		 string &log &optional;
		dst_mac:		 string &log &optional;
		service:		 string &log &optional;
		pdu_type: 		 string &log &optional;
		cmd:			 string &log &optional;
		node_type:		 string &log &optional;
		node_id:		 int &log &optional;
		connection_info:         string &log &optional;
		src_node_number:         string &log &optional;
	};

	type AggregationData_TSN: record {
		src_mac:		string &log &optional;
		dst_mac:		string &log &optional;
		service:		string &log &optional;
		flame_type: 		string &log &optional;
		pdu_type:               string &log &optional;
		node_type:		string &log &optional;
		device_type:            string &log &optional;
		function_name:          string &log &optional;
	};

	type Ts_num: record {
		ts_s:			time &log;
		num: 			int &log;
		ts_e: 			time &log &optional;
	};

	function insert_log_noip(res_aggregationData_noip: table[AggregationData_NOIP] of Ts_num, idx: AggregationData_NOIP): interval
	{
	local info_insert_noip: Info_NOIP = [];
	info_insert_noip$ts = res_aggregationData_noip[idx]$ts_s;
	info_insert_noip$src_mac = idx$src_mac;
	info_insert_noip$dst_mac = idx$dst_mac;
	info_insert_noip$service = idx$service;
	info_insert_noip$pdu_type = idx$pdu_type;
	if ( idx?$cmd ){
		info_insert_noip$cmd = idx$cmd;
	}
	if ( idx?$node_type ){
		info_insert_noip$node_type = idx$node_type;
	}
	if ( idx?$node_id ){
		info_insert_noip$node_id = idx$node_id;
	}
	if ( idx?$connection_info ){
		info_insert_noip$connection_info = idx$connection_info;
	}
	if ( idx?$src_node_number ){
		info_insert_noip$src_node_number = idx$src_node_number;
	}
	if ( res_aggregationData_noip[idx]?$ts_e ){
		info_insert_noip$ts_end = res_aggregationData_noip[idx]$ts_e;
	}
	if ( res_aggregationData_noip[idx]?$num ){
		info_insert_noip$number = res_aggregationData_noip[idx]$num;
	}

	Log::write(NO_IP::LOG_NOIP, info_insert_noip);
	return 0secs;
	}

	global res_aggregationData_noip: table[AggregationData_NOIP] of Ts_num &create_expire=60sec &expire_func=insert_log_noip;

	function insert_log_tsn(res_aggregationData_tsn: table[AggregationData_TSN] of Ts_num, idx: AggregationData_TSN): interval
	{
	local info_insert_tsn: Info_TSN = [];
	info_insert_tsn$ts = res_aggregationData_tsn[idx]$ts_s;
	info_insert_tsn$src_mac = idx$src_mac;
	info_insert_tsn$dst_mac = idx$dst_mac;
	info_insert_tsn$service = idx$service;
	info_insert_tsn$flame_type = idx$flame_type;
	info_insert_tsn$pdu_type = idx$pdu_type;
	if ( idx?$node_type ){
		info_insert_tsn$node_type = idx$node_type;
	}
	if ( idx?$device_type ){
		info_insert_tsn$device_type = idx$device_type;
	}
	if ( idx?$function_name ){
		info_insert_tsn$function_name = idx$function_name;
	}
	if ( res_aggregationData_tsn[idx]?$ts_e ){
		info_insert_tsn$ts_end = res_aggregationData_tsn[idx]$ts_e;
	}
	if ( res_aggregationData_tsn[idx]?$num ){
		info_insert_tsn$number = res_aggregationData_tsn[idx]$num;
	}
	Log::write(NO_IP::LOG_TSN, info_insert_tsn);

	return 0secs;
	}

	global res_aggregationData_tsn: table[AggregationData_TSN] of Ts_num &create_expire=60sec &expire_func=insert_log_tsn;
}

event zeek_init() &priority=5
	{
	Log::create_stream(NO_IP::LOG_NOIP, [$columns = Info_NOIP, $path="cclink-ie"]);
	Log::create_stream(NO_IP::LOG_TSN, [$columns = Info_TSN, $path="cclink-ie-tsn"]);
	}

event zeek_init()
	{
	if ( ! PacketAnalyzer::try_register_packet_analyzer_by_name("Ethernet", 0x890f, "spicy::NO_IP") )
		print "cannot register raw layer analyzer";
	}

function create_aggregationData_noip(info_noip: Info_NOIP): AggregationData_NOIP
	{
	local aggregationData_noip: AggregationData_NOIP;
	aggregationData_noip$src_mac = info_noip$src_mac;
	aggregationData_noip$dst_mac = info_noip$dst_mac;
	aggregationData_noip$pdu_type = info_noip$pdu_type;
	if ( info_noip?$cmd ){
		aggregationData_noip$cmd = info_noip$cmd;
	}
	if ( info_noip?$node_type ){
		aggregationData_noip$node_type = info_noip$node_type;
	}
	if ( info_noip?$node_id ){
		aggregationData_noip$node_id = info_noip$node_id;
	}
	if ( info_noip?$connection_info ){
		aggregationData_noip$connection_info = info_noip$connection_info;
	}
	if ( info_noip?$src_node_number ){
		aggregationData_noip$src_node_number = info_noip$src_node_number;
	}
	aggregationData_noip$service = info_noip$service;

	return aggregationData_noip;
	}

function create_aggregationData_tsn(info_tsn: Info_TSN): AggregationData_TSN
	{
	local aggregationData_tsn: AggregationData_TSN;
	aggregationData_tsn$src_mac = info_tsn$src_mac;
	aggregationData_tsn$dst_mac = info_tsn$dst_mac;
	aggregationData_tsn$service = info_tsn$service;
	aggregationData_tsn$flame_type = info_tsn$flame_type;
	aggregationData_tsn$pdu_type = info_tsn$pdu_type;
	if ( info_tsn?$node_type ){
		aggregationData_tsn$node_type = info_tsn$node_type;
	}
	if ( info_tsn?$device_type ){
		aggregationData_tsn$device_type = info_tsn$device_type;
	}
	if ( info_tsn?$function_name ){
		aggregationData_tsn$function_name = info_tsn$function_name;
	}

	return aggregationData_tsn;
	}

function insert_res_aggregationData_noip(aggregationData_noip: AggregationData_NOIP, info_noip: Info_NOIP): string
	{
		if (aggregationData_noip in res_aggregationData_noip){
			res_aggregationData_noip[aggregationData_noip]$num = res_aggregationData_noip[aggregationData_noip]$num + 1;
			res_aggregationData_noip[aggregationData_noip]$ts_e = info_noip$ts;
		} else {
			res_aggregationData_noip[aggregationData_noip] = [$ts_s = info_noip$ts, $num = 1, $ts_e = info_noip$ts];
		}

		return "done";
	}

function insert_res_aggregationData_tsn(aggregationData_tsn: AggregationData_TSN, info_tsn: Info_TSN): string
	{
		if (aggregationData_tsn in res_aggregationData_tsn){
			res_aggregationData_tsn[aggregationData_tsn]$num = res_aggregationData_tsn[aggregationData_tsn]$num + 1;
			res_aggregationData_tsn[aggregationData_tsn]$ts_e = info_tsn$ts;
		} else {
			res_aggregationData_tsn[aggregationData_tsn] = [$ts_s = info_tsn$ts, $num = 1, $ts_e = info_tsn$ts];
		}

		return "done";
	}


# field 伝送制御フレーム
# -----------------------------------
event raw::tokenM(p: raw_pkt_hdr, dataType: string, serviceVerType: string, srcNodeNumber: string, nodeId: int)
{
	local info_noip: Info_NOIP;
	local aggregationData_noip: AggregationData_NOIP;
	info_noip$ts = network_time();
	info_noip$src_mac = p$l2$src;
	info_noip$dst_mac = p$l2$dst;
	info_noip$pdu_type = "tokenM";
	if ( serviceVerType == "\x00" )
	{	
		info_noip$service="cclink_ie_control";
		info_noip$src_node_number="0x" + string_to_ascii_hex(srcNodeNumber);
		info_noip$node_id=nodeId;
	}
	else if ( serviceVerType == "\x01" )
	{	
		info_noip$service="cclink_ie_field";
		info_noip$src_node_number="0x" + string_to_ascii_hex(srcNodeNumber);
		info_noip$node_id=nodeId;
	} else {
		info_noip$service="unknownserviceVerType" + serviceVerType;
	}
		
	aggregationData_noip = create_aggregationData_noip(info_noip);
	insert_res_aggregationData_noip(aggregationData_noip, info_noip);
}

event raw::persuasion(p: raw_pkt_hdr, dataType: string, serviceVerType: string, srcNodeNumber: string, nodetype: string)
{
	local info_noip: Info_NOIP;
	local aggregationData_noip: AggregationData_NOIP;
	info_noip$ts = network_time();
	info_noip$src_mac = p$l2$src;
	info_noip$dst_mac = p$l2$dst;
	info_noip$pdu_type = "persuasion";
	if ( serviceVerType == "\x00" )
	{	
		info_noip$src_node_number="0x" + string_to_ascii_hex(srcNodeNumber);
		if (nodetype in res_nodetype_control){
			info_noip$node_type = res_nodetype_control[nodetype];
		} else {
			info_noip$node_type = "unknownNodetype" + nodetype;
		}
		info_noip$service = "cclink_ie_control";
	}
	else if ( serviceVerType == "\x01" )
	{	
		info_noip$src_node_number="0x" + string_to_ascii_hex(srcNodeNumber);
		if (nodetype in res_nodetype_field){
			info_noip$node_type = res_nodetype_field[nodetype];
		} else {
			info_noip$node_type = "unknownNodetype" + nodetype;
		}
		info_noip$service = "cclink_ie_field";
	} else {
		info_noip$service = "unknownserviceVerType" + serviceVerType;
	}
			
	aggregationData_noip = create_aggregationData_noip(info_noip);
	insert_res_aggregationData_noip(aggregationData_noip, info_noip);
}

event raw::testData(p: raw_pkt_hdr, dataType: string, serviceVerType: string, srcNodeNumber: string, nodetype: string)
{
	if ( serviceVerType == "\x00" )
	{	
		local info_noip_1: Info_NOIP;
		local aggregationData_noip_1: AggregationData_NOIP;
		info_noip_1$ts = network_time();
		info_noip_1$src_mac = p$l2$src;
		info_noip_1$dst_mac = p$l2$dst;
		info_noip_1$pdu_type = "testData";
		info_noip_1$src_node_number = "0x" + string_to_ascii_hex(srcNodeNumber);
		if (nodetype in res_nodetype_control){
			info_noip_1$node_type = res_nodetype_control[nodetype];
		} else {
			info_noip_1$node_type = "unknownNodetype" + nodetype;
		}
		info_noip_1$service = "cclink_ie_control";
		aggregationData_noip_1 = create_aggregationData_noip(info_noip_1);
		insert_res_aggregationData_noip(aggregationData_noip_1, info_noip_1);
	}
	else if ( serviceVerType == "\x01" )
	{	
		local info_noip_2: Info_NOIP;
		local aggregationData_noip_2: AggregationData_NOIP;
		info_noip_2$ts = network_time();
		info_noip_2$src_mac = p$l2$src;
		info_noip_2$dst_mac = p$l2$dst;
		info_noip_2$pdu_type = "testData";
		info_noip_2$src_node_number = "0x" + string_to_ascii_hex(srcNodeNumber);
		if (nodetype in res_nodetype_field){
			info_noip_2$node_type = res_nodetype_field[nodetype];
		} else {
			info_noip_2$node_type = "unknownNodetype" + nodetype;
		}
		info_noip_2$service = "cclink_ie_field";
		aggregationData_noip_2 = create_aggregationData_noip(info_noip_2);
		insert_res_aggregationData_noip(aggregationData_noip_2, info_noip_2);
	} 
	else if ( serviceVerType == "\x02" )
	{	
		local info_tsn_1: Info_TSN;
		local aggregationData_tsn_1: AggregationData_TSN;
		info_tsn_1$ts = network_time();
		info_tsn_1$src_mac = p$l2$src;
		info_tsn_1$dst_mac = p$l2$dst;
		info_tsn_1$service = "cclink_ie_tsn";
		info_tsn_1$flame_type = "acyclic";
		info_tsn_1$pdu_type = "acyclicTestData";
		info_tsn_1$node_type = "master station";
		aggregationData_tsn_1 = create_aggregationData_tsn(info_tsn_1);
		insert_res_aggregationData_tsn(aggregationData_tsn_1, info_tsn_1);
	}
	else if ( serviceVerType == "\x03" )
	{	
		local info_tsn_2: Info_TSN;
		local aggregationData_tsn_2: AggregationData_TSN;
		info_tsn_2$ts = network_time();
		info_tsn_2$src_mac = p$l2$src;
		info_tsn_2$dst_mac = p$l2$dst;
		info_tsn_2$service = "cclink_ie_tsn&field";
		info_tsn_2$flame_type = "acyclic";
		info_tsn_2$pdu_type = "acyclicTestData";
		info_tsn_2$node_type = "master station";
		aggregationData_tsn_2 = create_aggregationData_tsn(info_tsn_2);
		insert_res_aggregationData_tsn(aggregationData_tsn_2, info_tsn_2);
	}
}


event raw::testDataAck(p: raw_pkt_hdr, dataType: string, serviceVerType: string, srcNodeNumber: string, nodetype: string)
{
	if ( serviceVerType == "\x00" )
	{	
		local info_noip_1: Info_NOIP;
		local aggregationData_noip_1: AggregationData_NOIP;
		info_noip_1$ts = network_time();
		info_noip_1$src_mac = p$l2$src;
		info_noip_1$dst_mac = p$l2$dst;
		info_noip_1$pdu_type = "testDataAck";
		info_noip_1$src_node_number="0x" + string_to_ascii_hex(srcNodeNumber);
		if (nodetype in res_nodetype_control){
			info_noip_1$node_type = res_nodetype_control[nodetype];
		} else {
			info_noip_1$node_type = "unknownNodetype" + nodetype;
		}
		info_noip_1$service = "cclink_ie_control";
		aggregationData_noip_1 = create_aggregationData_noip(info_noip_1);
		insert_res_aggregationData_noip(aggregationData_noip_1, info_noip_1);
	}
	else if ( serviceVerType == "\x01" )
	{	
		local info_noip_2: Info_NOIP;
		local aggregationData_noip_2: AggregationData_NOIP;
		info_noip_2$ts = network_time();
		info_noip_2$src_mac = p$l2$src;
		info_noip_2$dst_mac = p$l2$dst;
		info_noip_2$pdu_type = "testDataAck";
		info_noip_2$src_node_number="0x" + string_to_ascii_hex(srcNodeNumber);
		if (nodetype in res_nodetype_field){
			info_noip_2$node_type = res_nodetype_field[nodetype];
		} else {
			info_noip_2$node_type = "unknownNodetype" + nodetype;
		}
		info_noip_2$service = "cclink_ie_field";
		aggregationData_noip_2 = create_aggregationData_noip(info_noip_2);
		insert_res_aggregationData_noip(aggregationData_noip_2, info_noip_2);
	} 
	else if ( serviceVerType == "\x02" )
	{	
		local info_tsn_1: Info_TSN;
		local aggregationData_tsn_1: AggregationData_TSN;
		info_tsn_1$ts = network_time();
		info_tsn_1$src_mac = p$l2$src;
		info_tsn_1$dst_mac = p$l2$dst;
		info_tsn_1$service = "cclink_ie_tsn";
		info_tsn_1$flame_type = "acyclic";
		info_tsn_1$pdu_type = "acyclicTestDataAck";
		info_tsn_1$node_type = "master station";
		aggregationData_tsn_1 = create_aggregationData_tsn(info_tsn_1);
		insert_res_aggregationData_tsn(aggregationData_tsn_1, info_tsn_1);

	}
	else if ( serviceVerType == "\x03" )
	{	
		local info_tsn_2: Info_TSN;
		local aggregationData_tsn_2: AggregationData_TSN;
		info_tsn_2$ts = network_time();
		info_tsn_2$src_mac = p$l2$src;
		info_tsn_2$dst_mac = p$l2$dst;
		info_tsn_2$service = "cclink_ie_tsn&field";
		info_tsn_2$flame_type = "acyclic";
		info_tsn_2$pdu_type = "acyclicTestDataAck";
		info_tsn_2$node_type = "master station";
		aggregationData_tsn_2 = create_aggregationData_tsn(info_tsn_2);
		insert_res_aggregationData_tsn(aggregationData_tsn_2, info_tsn_2);
	}
}

event raw::setup(p: raw_pkt_hdr, dataType: string, serviceVerType: string, srcNodeNumber: string, nodeId: int)
{
	local info_noip: Info_NOIP;
	local aggregationData_noip: AggregationData_NOIP;
	info_noip$ts = network_time();
	info_noip$src_mac = p$l2$src;
	info_noip$dst_mac = p$l2$dst;
	info_noip$pdu_type = "setup";
	if ( serviceVerType == "\x00" )
	{	
		info_noip$src_node_number="0x" + string_to_ascii_hex(srcNodeNumber);
		info_noip$node_id=nodeId;
		info_noip$service="cclink_ie_control";
	}
	else if ( serviceVerType == "\x01" )
	{	
		info_noip$src_node_number="0x" + string_to_ascii_hex(srcNodeNumber);
		info_noip$node_id=nodeId;
		info_noip$service="cclink_ie_field";
	} else {
		info_noip$service="unknownserviceVerType" + serviceVerType;
	}
			
	aggregationData_noip = create_aggregationData_noip(info_noip);
	insert_res_aggregationData_noip(aggregationData_noip, info_noip);
}

event raw::setupAck(p: raw_pkt_hdr, dataType: string, serviceVerType: string, srcNodeNumber: string)
{
	local info_noip: Info_NOIP;
	local aggregationData_noip: AggregationData_NOIP;
	info_noip$ts = network_time();
	info_noip$src_mac = p$l2$src;
	info_noip$dst_mac = p$l2$dst;
	info_noip$pdu_type = "setupAck";
	if ( serviceVerType == "\x00" )
	{
		info_noip$service="cclink_ie_control";
		info_noip$src_node_number="0x" + string_to_ascii_hex(srcNodeNumber);
	}
	else if ( serviceVerType == "\x01" )
	{	
		info_noip$service="cclink_ie_field";
		info_noip$src_node_number="0x" + string_to_ascii_hex(srcNodeNumber);
	} else {
		info_noip$service="unknownserviceVerType" + serviceVerType;
	}
			
	aggregationData_noip = create_aggregationData_noip(info_noip);
	insert_res_aggregationData_noip(aggregationData_noip, info_noip);
}

event raw::myStatus(p: raw_pkt_hdr, dataType: string, serviceVerType: string, srcNodeNumber: string, nodetype: string, nodeId: int, connectionInfo: string)
{
	local info_noip: Info_NOIP;
	local aggregationData_noip: AggregationData_NOIP;
	info_noip$ts = network_time();
	info_noip$src_mac = p$l2$src;
	info_noip$dst_mac = p$l2$dst;
	info_noip$pdu_type = "myStatus";
	if ( serviceVerType == "\x00" )
	{	
		info_noip$src_node_number="0x" + string_to_ascii_hex(srcNodeNumber);
		info_noip$node_id=nodeId;
		info_noip$service = "cclink_ie_control";
	}
	else if ( serviceVerType == "\x01" )
	{	
		info_noip$src_node_number="0x" + string_to_ascii_hex(srcNodeNumber);
		info_noip$node_id=nodeId;
		if (nodetype in res_nodetype_field){
			info_noip$node_type = res_nodetype_field[nodetype];
		} else {
			info_noip$node_type = "unknownNodetype" + nodetype;
		}
		info_noip$service = "cclink_ie_field";
	} else {
		info_noip$service = "unknownserviceVerType" + serviceVerType;
	}
			
	aggregationData_noip = create_aggregationData_noip(info_noip);
	insert_res_aggregationData_noip(aggregationData_noip, info_noip);
}
# -----------------------------------

# field 同期フレーム
# -----------------------------------
event raw::measure(p: raw_pkt_hdr, dataType: string, serviceVerType: string, srcNodeNumber: string, nodeId: int)
{
	local info_noip: Info_NOIP;
	local aggregationData_noip: AggregationData_NOIP;
	info_noip$ts = network_time();
	info_noip$src_mac = p$l2$src;
	info_noip$dst_mac = p$l2$dst;
	info_noip$pdu_type = "measure";
	if ( serviceVerType == "\x00" )
	{	
		info_noip$service="cclink_ie_control";
		info_noip$src_node_number="0x" + string_to_ascii_hex(srcNodeNumber);
	}
	else if ( serviceVerType == "\x01" )
	{	
		info_noip$service="cclink_ie_field";
		info_noip$src_node_number="0x" + string_to_ascii_hex(srcNodeNumber);
		info_noip$node_id=nodeId;
	} else {
		info_noip$service="unknownserviceVerType" + serviceVerType;
	}
			
	aggregationData_noip = create_aggregationData_noip(info_noip);
	insert_res_aggregationData_noip(aggregationData_noip, info_noip);
}

event raw::measureAck(p: raw_pkt_hdr, dataType: string, serviceVerType: string, srcNodeNumber: string, nodeId: int)
{
	local info_noip: Info_NOIP;
	local aggregationData_noip: AggregationData_NOIP;
	info_noip$ts = network_time();
	info_noip$src_mac = p$l2$src;
	info_noip$dst_mac = p$l2$dst;
	info_noip$pdu_type = "measureAck";
	if ( serviceVerType == "\x00" )
	{	
		info_noip$service="cclink_ie_control";
		info_noip$src_node_number="0x" + string_to_ascii_hex(srcNodeNumber);
	}
	else if ( serviceVerType == "\x01" )
	{
		info_noip$service="cclink_ie_field";
		info_noip$src_node_number="0x" + string_to_ascii_hex(srcNodeNumber);
		info_noip$node_id=nodeId;
	} else {
		info_noip$service="unknownserviceVerType" + serviceVerType;
	}
			
	aggregationData_noip = create_aggregationData_noip(info_noip);
	insert_res_aggregationData_noip(aggregationData_noip, info_noip);
}

event raw::offset(p: raw_pkt_hdr, dataType: string, serviceVerType: string, srcNodeNumber: string, nodeId: int)
{
	local info_noip: Info_NOIP;
	local aggregationData_noip: AggregationData_NOIP;
	info_noip$ts = network_time();
	info_noip$src_mac = p$l2$src;
	info_noip$dst_mac = p$l2$dst;
	info_noip$pdu_type = "offset";
	if ( serviceVerType == "\x00" )
	{	
		info_noip$service="cclink_ie_control";
		info_noip$src_node_number="0x" + string_to_ascii_hex(srcNodeNumber);
	}
	else if ( serviceVerType == "\x01" )
	{	
		info_noip$service="cclink_ie_field";
		info_noip$src_node_number="0x" + string_to_ascii_hex(srcNodeNumber);
		info_noip$node_id=nodeId;
	} else {
		info_noip$service="unknownserviceVerType" + serviceVerType;
	}
			
	aggregationData_noip = create_aggregationData_noip(info_noip);
	insert_res_aggregationData_noip(aggregationData_noip, info_noip);
}

event raw::update(p: raw_pkt_hdr, dataType: string, serviceVerType: string, srcNodeNumber: string, nodeId: int)
{
	local info_noip: Info_NOIP;
	local aggregationData_noip: AggregationData_NOIP;
	info_noip$ts = network_time();
	info_noip$src_mac = p$l2$src;
	info_noip$dst_mac = p$l2$dst;
	info_noip$pdu_type = "update";
	if ( serviceVerType == "\x00" )
	{	
		info_noip$service="cclink_ie_control";
		info_noip$src_node_number="0x" + string_to_ascii_hex(srcNodeNumber);
	}
	else if ( serviceVerType == "\x01" )
	{	
		info_noip$service="cclink_ie_field";
		info_noip$src_node_number="0x" + string_to_ascii_hex(srcNodeNumber);
		info_noip$node_id=nodeId;
	} else {
		info_noip$service="unknownserviceVerType" + serviceVerType;
	}
			
	aggregationData_noip = create_aggregationData_noip(info_noip);
	insert_res_aggregationData_noip(aggregationData_noip, info_noip);
}
# -----------------------------------

# field サイクリック伝送フレーム
# -----------------------------------
event raw::cyclicDataRWw(p: raw_pkt_hdr, dataType: string, serviceVerType: string, srcNodeNumber: string, nodeId: int)
{
	local info_noip: Info_NOIP;
	local aggregationData_noip: AggregationData_NOIP;
	info_noip$ts = network_time();
	info_noip$src_mac = p$l2$src;
	info_noip$dst_mac = p$l2$dst;
	info_noip$pdu_type = "cyclicDataRWw";
	if ( serviceVerType == "\x00" )
	{
		info_noip$service="cclink_ie_control";
		info_noip$src_node_number="0x" + string_to_ascii_hex(srcNodeNumber);
	}
	else if ( serviceVerType == "\x01" )
	{
		info_noip$service="cclink_ie_field";
		info_noip$src_node_number="0x" + string_to_ascii_hex(srcNodeNumber);
		info_noip$node_id=nodeId;
	} else {
		info_noip$service="unknownserviceVerType" + serviceVerType;
	}
			
	aggregationData_noip = create_aggregationData_noip(info_noip);
	insert_res_aggregationData_noip(aggregationData_noip, info_noip);
}

event raw::cyclicDataRY(p: raw_pkt_hdr, dataType: string, serviceVerType: string, srcNodeNumber: string, nodeId: int)
{
	local info_noip: Info_NOIP;
	local aggregationData_noip: AggregationData_NOIP;
	info_noip$ts = network_time();
	info_noip$src_mac = p$l2$src;
	info_noip$dst_mac = p$l2$dst;
	info_noip$pdu_type = "cyclicDataRY";
	if ( serviceVerType == "\x00" )
	{
		info_noip$service="cclink_ie_control";
		info_noip$src_node_number="0x" + string_to_ascii_hex(srcNodeNumber);
	}
	else if ( serviceVerType == "\x01" )
	{
		info_noip$service="cclink_ie_field";
		info_noip$src_node_number="0x" + string_to_ascii_hex(srcNodeNumber);
		info_noip$node_id=nodeId;
	} else {
		info_noip$service="unknownserviceVerType" + serviceVerType;
	}
			
	aggregationData_noip = create_aggregationData_noip(info_noip);
	insert_res_aggregationData_noip(aggregationData_noip, info_noip);
}

event raw::cyclicDataRWr(p: raw_pkt_hdr, dataType: string, serviceVerType: string, srcNodeNumber: string, nodeId: int)
{
	local info_noip: Info_NOIP;
	local aggregationData_noip: AggregationData_NOIP;
	info_noip$ts = network_time();
	info_noip$src_mac = p$l2$src;
	info_noip$dst_mac = p$l2$dst;
	info_noip$pdu_type = "cyclicDataRWr";
	if ( serviceVerType == "\x00" )
	{
		info_noip$service="cclink_ie_control";
		info_noip$src_node_number="0x" + string_to_ascii_hex(srcNodeNumber);
	}
	else if ( serviceVerType == "\x01" )
	{
		info_noip$service="cclink_ie_field";
		info_noip$src_node_number="0x" + string_to_ascii_hex(srcNodeNumber);
		info_noip$node_id=nodeId;
	} else {
		info_noip$service="unknownserviceVerType" + serviceVerType;
	}
			
	aggregationData_noip = create_aggregationData_noip(info_noip);
	insert_res_aggregationData_noip(aggregationData_noip, info_noip);
}

event raw::cyclicDataRX(p: raw_pkt_hdr, dataType: string, serviceVerType: string, srcNodeNumber: string, nodeId: int)
{
	local info_noip: Info_NOIP;
	local aggregationData_noip: AggregationData_NOIP;
	info_noip$ts = network_time();
	info_noip$src_mac = p$l2$src;
	info_noip$dst_mac = p$l2$dst;
	info_noip$pdu_type = "cyclicDataRX";
	if ( serviceVerType == "\x00" )
	{
		info_noip$service="cclink_ie_control";
		info_noip$src_node_number="0x" + string_to_ascii_hex(srcNodeNumber);
	}
	else if ( serviceVerType == "\x01" )
	{
		info_noip$service="cclink_ie_field";
		info_noip$src_node_number="0x" + string_to_ascii_hex(srcNodeNumber);
		info_noip$node_id=nodeId;
	} else {
		info_noip$service="unknownserviceVerType" + serviceVerType;
	}
			
	aggregationData_noip = create_aggregationData_noip(info_noip);
	insert_res_aggregationData_noip(aggregationData_noip, info_noip);
}
# -----------------------------------

# field トランジェント伝送フレーム
# -----------------------------------
type Transient1Data: record {
	command_7: string;
	subCommand_7: string;
	command_8: string;
    subCommand_8: string;
    ct: string;
};

event raw::transient1(p: raw_pkt_hdr, dataType: int, serviceVerType: string, srcNodeNumber: string, data: Transient1Data, connectionInfo: string, nodeId: int)
{
	local info_noip: Info_NOIP;
	local aggregationData_noip: AggregationData_NOIP;
	info_noip$ts = network_time();
	info_noip$src_mac = p$l2$src;
	info_noip$dst_mac = p$l2$dst;
	info_noip$pdu_type = "transient1";
	if ( serviceVerType == "\x00" ){
		info_noip$src_node_number="0x" + string_to_ascii_hex(srcNodeNumber);
		info_noip$connection_info="0x" + string_to_ascii_hex(connectionInfo);
		info_noip$node_id=nodeId;
		info_noip$service = "cclink_ie_control";
	} else if ( serviceVerType == "\x01" ){
		info_noip$src_node_number="0x" + string_to_ascii_hex(srcNodeNumber);
		info_noip$connection_info="0x" + string_to_ascii_hex(connectionInfo);
		info_noip$node_id=nodeId;
		if (dataType == 5){
			if (data$ct in res_ct_1){
				info_noip$cmd = res_ct_1[data$ct];
			} else {
				info_noip$cmd = "unknownCt" + data$ct;
			}
		} else if (dataType == 7){
			if (data$command_7 in res_command_7 && data$subCommand_7 in res_subCommand){
				info_noip$cmd = res_command_7[data$command_7] + res_subCommand[data$subCommand_7];
			} else {
				info_noip$cmd = "unknownCmd" + data$command_7 + data$subCommand_7;
			}
		} else if (dataType == 8){
			if (data$command_8 in res_command_8 && data$subCommand_8 in res_subCommand){
				info_noip$cmd = res_command_8[data$command_8] + res_subCommand[data$subCommand_8];
			} else {
				info_noip$cmd = "unknownCmd" + data$command_8 + data$subCommand_8;
			}
		}
		info_noip$service = "cclink_ie_field";
	} else {
		info_noip$service = "unknownserviceVerType" + serviceVerType;
	}
	
	aggregationData_noip = create_aggregationData_noip(info_noip);
	insert_res_aggregationData_noip(aggregationData_noip, info_noip);
}

event raw::transientAck(p: raw_pkt_hdr, dataType: string, serviceVerType: string, srcNodeNumber: string, connectionInfo: string, nodeId: int)
{
	local info_noip: Info_NOIP;
	local aggregationData_noip: AggregationData_NOIP;
	info_noip$ts = network_time();
	info_noip$src_mac = p$l2$src;
	info_noip$dst_mac = p$l2$dst;
	info_noip$pdu_type = "transientAck";
	if ( serviceVerType == "\x00" )
	{	
		info_noip$service="cclink_ie_control";
		info_noip$src_node_number="0x" + string_to_ascii_hex(srcNodeNumber);
	}
	else if ( serviceVerType == "\x01" )
	{
		info_noip$service="cclink_ie_field";
		info_noip$src_node_number="0x" + string_to_ascii_hex(srcNodeNumber);
		info_noip$connection_info="0x" + string_to_ascii_hex(connectionInfo);
		info_noip$node_id=nodeId;
	} else {
		info_noip$service="unknownserviceVerType" + serviceVerType;
	}
			
	aggregationData_noip = create_aggregationData_noip(info_noip);
	insert_res_aggregationData_noip(aggregationData_noip, info_noip);
}

event raw::transient2(p: raw_pkt_hdr, dataType: string, serviceVerType: string, srcNodeNumber: string, connectionInfo: string, nodeId: int, ct: string)
{
	local info_noip: Info_NOIP;
	local aggregationData_noip: AggregationData_NOIP;
	info_noip$ts = network_time();
	info_noip$src_mac = p$l2$src;
	info_noip$dst_mac = p$l2$dst;
	info_noip$pdu_type = "transient2";
	if ( serviceVerType == "\x00" )
	{	
		info_noip$src_node_number="0x" + string_to_ascii_hex(srcNodeNumber);
		info_noip$connection_info="0x" + string_to_ascii_hex(connectionInfo);
		info_noip$node_id=nodeId;
		if (ct in res_ct_2_control){
			info_noip$cmd = res_ct_2_control[ct];
		} else {
			info_noip$cmd = "unknownCt" + ct;
		}
		info_noip$service = "cclink_ie_control";
	}
	else if ( serviceVerType == "\x01" )
	{	
		info_noip$src_node_number="0x" + string_to_ascii_hex(srcNodeNumber);
		info_noip$connection_info="0x" + string_to_ascii_hex(connectionInfo);
		info_noip$node_id=nodeId;
		if (ct in res_ct_2_field){
			info_noip$cmd = res_ct_2_field[ct];
		} else {
			info_noip$cmd = "unknownCt" + ct;
		}
		info_noip$service = "cclink_ie_field";
	} else {
		info_noip$service = "unknownserviceVerType" + serviceVerType;
	}
			
	aggregationData_noip = create_aggregationData_noip(info_noip);
	insert_res_aggregationData_noip(aggregationData_noip, info_noip);	
}

event raw::paramCheck(p: raw_pkt_hdr, dataType: string, serviceVerType: string, srcNodeNumber: string, connectionInfo: string, nodeId: int)
{
	local info_noip: Info_NOIP;
	local aggregationData_noip: AggregationData_NOIP;
	info_noip$ts = network_time();
	info_noip$src_mac = p$l2$src;
	info_noip$dst_mac = p$l2$dst;
	info_noip$pdu_type = "paramCheck";
	if ( serviceVerType == "\x00" )
	{
		info_noip$service="cclink_ie_control";
		info_noip$src_node_number="0x" + string_to_ascii_hex(srcNodeNumber);
	}
	else if ( serviceVerType == "\x01" )
	{
		info_noip$service="cclink_ie_field";
		info_noip$src_node_number="0x" + string_to_ascii_hex(srcNodeNumber);
		info_noip$connection_info="0x" + string_to_ascii_hex(connectionInfo);
		info_noip$node_id=nodeId;
	} else {
		info_noip$service="unknownserviceVerType" + serviceVerType;
	}
			
	aggregationData_noip = create_aggregationData_noip(info_noip);
	insert_res_aggregationData_noip(aggregationData_noip, info_noip);
}

event raw::parameter(p: raw_pkt_hdr, dataType: string, serviceVerType: string, srcNodeNumber: string, connectionInfo: string, nodeId: int)
{
	local info_noip: Info_NOIP;
	local aggregationData_noip: AggregationData_NOIP;
	info_noip$ts = network_time();
	info_noip$src_mac = p$l2$src;
	info_noip$dst_mac = p$l2$dst;
	info_noip$pdu_type = "parameter";
	if ( serviceVerType == "\x00" )
	{	
		info_noip$service="cclink_ie_control";
		info_noip$src_node_number="0x" + string_to_ascii_hex(srcNodeNumber);
	}
	else if ( serviceVerType == "\x01" )
	{
		info_noip$service="cclink_ie_field";
		info_noip$src_node_number="0x" + string_to_ascii_hex(srcNodeNumber);
		info_noip$connection_info="0x" + string_to_ascii_hex(connectionInfo);
		info_noip$node_id=nodeId;
	} else {
		info_noip$service="unknownserviceVerType" + serviceVerType;
	}
			
	aggregationData_noip = create_aggregationData_noip(info_noip);
	insert_res_aggregationData_noip(aggregationData_noip, info_noip);
}

event raw::c_timer(p: raw_pkt_hdr, dataType: string, serviceVerType: string, srcNodeNumber: string)
{
	local info_noip: Info_NOIP;
	local aggregationData_noip: AggregationData_NOIP;
	info_noip$ts = network_time();
	info_noip$src_mac = p$l2$src;
	info_noip$dst_mac = p$l2$dst;
	info_noip$pdu_type = "timer";
	if ( serviceVerType == "\x00" )
	{	
		info_noip$service="cclink_ie_control";
		info_noip$src_node_number="0x" + string_to_ascii_hex(srcNodeNumber);
	}
	else if ( serviceVerType == "\x01" )
	{	
		info_noip$service="cclink_ie_field";
		info_noip$src_node_number="0x" + string_to_ascii_hex(srcNodeNumber);
	} else {
		info_noip$service="unknownserviceVerType" + serviceVerType;
	}
			
	aggregationData_noip = create_aggregationData_noip(info_noip);
	insert_res_aggregationData_noip(aggregationData_noip, info_noip);
}

event raw::ipTransient(p: raw_pkt_hdr, dataType: string, serviceVerType: string, srcNodeNumber: string, connectionInfo: string, nodeId: int)
{
	local info_noip: Info_NOIP;
	local aggregationData_noip: AggregationData_NOIP;
	info_noip$ts = network_time();
	info_noip$src_mac = p$l2$src;
	info_noip$dst_mac = p$l2$dst;
	info_noip$pdu_type = "ipTransient";
	if ( serviceVerType == "\x00" )
	{
		info_noip$service="cclink_ie_control";
		info_noip$src_node_number="0x" + string_to_ascii_hex(srcNodeNumber);
	}
	else if ( serviceVerType == "\x01" )
	{
		info_noip$service="cclink_ie_field";
		info_noip$src_node_number="0x" + string_to_ascii_hex(srcNodeNumber);
		info_noip$connection_info="0x" + string_to_ascii_hex(connectionInfo);
		info_noip$node_id=nodeId;
	} else {
		info_noip$service="unknownserviceVerType" + serviceVerType;
	}
			
	aggregationData_noip = create_aggregationData_noip(info_noip);
	insert_res_aggregationData_noip(aggregationData_noip, info_noip);
}
# -----------------------------------

# control 伝送制御フレーム
# -----------------------------------
event raw::connect(p: raw_pkt_hdr, c_priority: string, srcNodeNumber: string)
{
	local info_noip: Info_NOIP;
	local aggregationData_noip: AggregationData_NOIP;
	info_noip$ts = network_time();
	info_noip$src_mac = p$l2$src;
	info_noip$dst_mac = p$l2$dst;
	info_noip$pdu_type = "connect";
	info_noip$service="cclink_ie_control";
	info_noip$src_node_number="0x" + string_to_ascii_hex(srcNodeNumber);
			
	aggregationData_noip = create_aggregationData_noip(info_noip);
	insert_res_aggregationData_noip(aggregationData_noip, info_noip);
}

event raw::connectAck(p: raw_pkt_hdr, c_priority: string, srcNodeNumber: string)
{
	local info_noip: Info_NOIP;
	local aggregationData_noip: AggregationData_NOIP;
	info_noip$ts = network_time();
	info_noip$src_mac = p$l2$src;
	info_noip$dst_mac = p$l2$dst;
	info_noip$pdu_type = "connectAck";
	info_noip$service="cclink_ie_control";
	info_noip$src_node_number="0x" + string_to_ascii_hex(srcNodeNumber);
			
	aggregationData_noip = create_aggregationData_noip(info_noip);
	insert_res_aggregationData_noip(aggregationData_noip, info_noip);
}

event raw::scan(p: raw_pkt_hdr, c_priority: string, srcNodeNumber: string)
{
	local info_noip: Info_NOIP;
	local aggregationData_noip: AggregationData_NOIP;
	info_noip$ts = network_time();
	info_noip$src_mac = p$l2$src;
	info_noip$dst_mac = p$l2$dst;
	info_noip$pdu_type = "scan";
	info_noip$service="cclink_ie_control";
	info_noip$src_node_number="0x" + string_to_ascii_hex(srcNodeNumber);
			
	aggregationData_noip = create_aggregationData_noip(info_noip);
	insert_res_aggregationData_noip(aggregationData_noip, info_noip);
}

event raw::collect(p: raw_pkt_hdr, c_priority: string, srcNodeNumber: string)
{
	local info_noip: Info_NOIP;
	local aggregationData_noip: AggregationData_NOIP;
	info_noip$ts = network_time();
	info_noip$src_mac = p$l2$src;
	info_noip$dst_mac = p$l2$dst;
	info_noip$pdu_type = "collect";
	info_noip$service="cclink_ie_control";
	info_noip$src_node_number="0x" + string_to_ascii_hex(srcNodeNumber);
			
	aggregationData_noip = create_aggregationData_noip(info_noip);
	insert_res_aggregationData_noip(aggregationData_noip, info_noip);
}

event raw::select(p: raw_pkt_hdr, c_priority: string, srcNodeNumber: string)
{
	local info_noip: Info_NOIP;
	local aggregationData_noip: AggregationData_NOIP;
	info_noip$ts = network_time();
	info_noip$src_mac = p$l2$src;
	info_noip$dst_mac = p$l2$dst;
	info_noip$pdu_type = "select";
	info_noip$service="cclink_ie_control";
	info_noip$src_node_number="0x" + string_to_ascii_hex(srcNodeNumber);
			
	aggregationData_noip = create_aggregationData_noip(info_noip);
	insert_res_aggregationData_noip(aggregationData_noip, info_noip);
}

event raw::launch(p: raw_pkt_hdr, c_priority: string, srcNodeNumber: string)
{
	local info_noip: Info_NOIP;
	local aggregationData_noip: AggregationData_NOIP;
	info_noip$ts = network_time();
	info_noip$src_mac = p$l2$src;
	info_noip$dst_mac = p$l2$dst;
	info_noip$pdu_type = "launch";
	info_noip$service="cclink_ie_control";
	info_noip$src_node_number="0x" + string_to_ascii_hex(srcNodeNumber);
			
	aggregationData_noip = create_aggregationData_noip(info_noip);
	insert_res_aggregationData_noip(aggregationData_noip, info_noip);
}

event raw::token(p: raw_pkt_hdr, c_priority: string, srcNodeNumber: string)
{
	local info_noip: Info_NOIP;
	local aggregationData_noip: AggregationData_NOIP;
	info_noip$ts = network_time();
	info_noip$src_mac = p$l2$src;
	info_noip$dst_mac = p$l2$dst;
	info_noip$pdu_type = "token";
	info_noip$service="cclink_ie_control";
	info_noip$src_node_number="0x" + string_to_ascii_hex(srcNodeNumber);
			
	aggregationData_noip = create_aggregationData_noip(info_noip);
	insert_res_aggregationData_noip(aggregationData_noip, info_noip);
}

event raw::dummy(p: raw_pkt_hdr, c_priority: string, srcNodeNumber: string)
{
	local info_noip: Info_NOIP;
	local aggregationData_noip: AggregationData_NOIP;
	info_noip$ts = network_time();
	info_noip$src_mac = p$l2$src;
	info_noip$dst_mac = p$l2$dst;
	info_noip$pdu_type = "dummy";
	info_noip$service="cclink_ie_control";
	info_noip$src_node_number="0x" + string_to_ascii_hex(srcNodeNumber);
			
	aggregationData_noip = create_aggregationData_noip(info_noip);
	insert_res_aggregationData_noip(aggregationData_noip, info_noip);
}

event raw::nTNTest(p: raw_pkt_hdr, c_priority: string, srcNodeNumber: string)
{
	local info_noip: Info_NOIP;
	local aggregationData_noip: AggregationData_NOIP;
	info_noip$ts = network_time();
	info_noip$src_mac = p$l2$src;
	info_noip$dst_mac = p$l2$dst;
	info_noip$pdu_type = "nTNTest";
	info_noip$service="cclink_ie_control";
	info_noip$src_node_number="0x" + string_to_ascii_hex(srcNodeNumber);
			
	aggregationData_noip = create_aggregationData_noip(info_noip);
	insert_res_aggregationData_noip(aggregationData_noip, info_noip);
}
# -----------------------------------

# control サイクリック伝送フレーム
# -----------------------------------
event raw::cyclicDataW(p: raw_pkt_hdr, c_priority: string, srcNodeNumber: string)
{
	local info_noip: Info_NOIP;
	local aggregationData_noip: AggregationData_NOIP;
	info_noip$ts = network_time();
	info_noip$src_mac = p$l2$src;
	info_noip$dst_mac = p$l2$dst;
	info_noip$pdu_type = "cyclicDataW";
	info_noip$service="cclink_ie_control";
	info_noip$src_node_number="0x" + string_to_ascii_hex(srcNodeNumber);
			
	aggregationData_noip = create_aggregationData_noip(info_noip);
	insert_res_aggregationData_noip(aggregationData_noip, info_noip);
}

event raw::cyclicDataB(p: raw_pkt_hdr, c_priority: string, srcNodeNumber: string)
{
	local info_noip: Info_NOIP;
	local aggregationData_noip: AggregationData_NOIP;
	info_noip$ts = network_time();
	info_noip$src_mac = p$l2$src;
	info_noip$dst_mac = p$l2$dst;
	info_noip$pdu_type = "cyclicDataB";
	info_noip$service="cclink_ie_control";
	info_noip$src_node_number="0x" + string_to_ascii_hex(srcNodeNumber);
			
	aggregationData_noip = create_aggregationData_noip(info_noip);
	insert_res_aggregationData_noip(aggregationData_noip, info_noip);
}

event raw::cyclicDataOut1(p: raw_pkt_hdr, c_priority: string, srcNodeNumber: string)
{
	local info_noip: Info_NOIP;
	local aggregationData_noip: AggregationData_NOIP;
	info_noip$ts = network_time();
	info_noip$src_mac = p$l2$src;
	info_noip$dst_mac = p$l2$dst;
	info_noip$pdu_type = "cyclicDataOut1";
	info_noip$service="cclink_ie_control";
	info_noip$src_node_number="0x" + string_to_ascii_hex(srcNodeNumber);
			
	aggregationData_noip = create_aggregationData_noip(info_noip);
	insert_res_aggregationData_noip(aggregationData_noip, info_noip);
}

event raw::cyclicDataOut2(p: raw_pkt_hdr, c_priority: string, srcNodeNumber: string)
{
	local info_noip: Info_NOIP;
	local aggregationData_noip: AggregationData_NOIP;
	info_noip$ts = network_time();
	info_noip$src_mac = p$l2$src;
	info_noip$dst_mac = p$l2$dst;
	info_noip$pdu_type = "cyclicDataOut2";
	info_noip$service="cclink_ie_control";
	info_noip$src_node_number="0x" + string_to_ascii_hex(srcNodeNumber);
			
	aggregationData_noip = create_aggregationData_noip(info_noip);
	insert_res_aggregationData_noip(aggregationData_noip, info_noip);
}

event raw::cyclicDataIn1(p: raw_pkt_hdr, c_priority: string, srcNodeNumber: string)
{
	local info_noip: Info_NOIP;
	local aggregationData_noip: AggregationData_NOIP;
	info_noip$ts = network_time();
	info_noip$src_mac = p$l2$src;
	info_noip$dst_mac = p$l2$dst;
	info_noip$pdu_type = "cyclicDataIn1";
	info_noip$service="cclink_ie_control";
	info_noip$src_node_number="0x" + string_to_ascii_hex(srcNodeNumber);
			
	aggregationData_noip = create_aggregationData_noip(info_noip);
	insert_res_aggregationData_noip(aggregationData_noip, info_noip);
}

event raw::cyclicDataIn2(p: raw_pkt_hdr, c_priority: string, srcNodeNumber: string)
{
	local info_noip: Info_NOIP;
	local aggregationData_noip: AggregationData_NOIP;
	info_noip$ts = network_time();
	info_noip$src_mac = p$l2$src;
	info_noip$dst_mac = p$l2$dst;
	info_noip$pdu_type = "cyclicDataIn2";
	info_noip$service="cclink_ie_control";
	info_noip$src_node_number="0x" + string_to_ascii_hex(srcNodeNumber);
			
	aggregationData_noip = create_aggregationData_noip(info_noip);
	insert_res_aggregationData_noip(aggregationData_noip, info_noip);
}
# -----------------------------------

# tsnフレーム
# -----------------------------------
event raw::cyclicM(p: raw_pkt_hdr)
{
	local info_tsn: Info_TSN;
	local aggregationData_tsn: AggregationData_TSN;
	info_tsn$ts = network_time();
	info_tsn$src_mac = p$l2$src;
	info_tsn$dst_mac = p$l2$dst;
	info_tsn$service = "cclink_ie_tsn";
	info_tsn$flame_type = "cyclic";
	info_tsn$pdu_type = "cyclicM/cyclicMs";
		
	aggregationData_tsn = create_aggregationData_tsn(info_tsn);
	insert_res_aggregationData_tsn(aggregationData_tsn, info_tsn);
}


event raw::cyclicS(p: raw_pkt_hdr)
{
	local info_tsn: Info_TSN;
	local aggregationData_tsn: AggregationData_TSN;
	info_tsn$ts = network_time();
	info_tsn$src_mac = p$l2$src;
	info_tsn$dst_mac = p$l2$dst;
	info_tsn$service = "cclink_ie_tsn";
	info_tsn$flame_type = "cyclic";
	info_tsn$pdu_type = "cyclicS/cyclicSs";
		
	aggregationData_tsn = create_aggregationData_tsn(info_tsn);
	insert_res_aggregationData_tsn(aggregationData_tsn, info_tsn);
}


event raw::acyclicPriority(p: raw_pkt_hdr)
{
	local info_tsn: Info_TSN;
	local aggregationData_tsn: AggregationData_TSN;
	info_tsn$ts = network_time();
	info_tsn$src_mac = p$l2$src;
	info_tsn$dst_mac = p$l2$dst;
	info_tsn$service = "cclink_ie_tsn";
	info_tsn$flame_type = "acyclic";
	info_tsn$pdu_type = "acyclicPriority";
		
	aggregationData_tsn = create_aggregationData_tsn(info_tsn);
	insert_res_aggregationData_tsn(aggregationData_tsn, info_tsn);
}


event raw::acyclicDetection(p: raw_pkt_hdr, detectionVer: string)
{
	local info_tsn: Info_TSN;
	local aggregationData_tsn: AggregationData_TSN;
	info_tsn$ts = network_time();
	info_tsn$src_mac = p$l2$src;
	info_tsn$dst_mac = p$l2$dst;
	info_tsn$service = "cclink_ie_tsn";
	info_tsn$flame_type = "acyclic";
	if ( detectionVer == "\x00" ) {
		info_tsn$pdu_type = "acyclicDetection Ver.0";
	}
	else if ( detectionVer == "\x01" ) {
		info_tsn$pdu_type = "acyclicDetection Ver.1";
	}
		
	aggregationData_tsn = create_aggregationData_tsn(info_tsn);
	insert_res_aggregationData_tsn(aggregationData_tsn, info_tsn);
}


event raw::acyclicDetectionAck(p: raw_pkt_hdr, 
				  nodeType: string, 
				  detectionAckVer: string, 
				  deviceType: string, 
				  function1: int, 
				  function2: int, 
				  function3: int, 
				  function4: int, 
				  function5: int, 
				  function6: int, 
				  function7: int, 
				  function8: int, 
				  function9: int,
				  function10: int,
				  function11: int,
				  function12: int,
				  function13: int,
				  function14: int,
				  function15: int,
				  function16: int)
{
	local info_tsn: Info_TSN;
	local aggregationData_tsn: AggregationData_TSN;
	info_tsn$ts = network_time();
	info_tsn$src_mac = p$l2$src;
	info_tsn$dst_mac = p$l2$dst;
	info_tsn$service = "cclink_ie_tsn";
	info_tsn$flame_type = "acyclic";

	if ( detectionAckVer == "\x00" ) {
		info_tsn$pdu_type = "acyclicDetectionAck Ver.0";
	}
	else if ( detectionAckVer == "\x01" ) {
		info_tsn$pdu_type = "acyclicDetectionAck Ver.1";
	}

	if (nodeType in res_nodetype_tsn){
		info_tsn$node_type = res_nodetype_tsn[nodeType];
	}

	if (deviceType in res_devicetype){
		info_tsn$device_type = res_devicetype[deviceType];
	}

	local function_name: string = "";
	if (function2 == 1){
		function_name = function_name + "s";
	}
	if (function3 == 1){
		function_name = function_name + "r";
	}
	if (function4 == 1){
		function_name = function_name + "S";
	}
	if (function5 == 1){
		function_name = function_name + "b";
	}
	if (function6 == 1){
		function_name = function_name + "w";
	}
	if (function7 == 1){
		function_name = function_name + "c";
	}
	if (function8 == 1){
		function_name = function_name + "l";
	}
	if (function9 == 1){
		function_name = function_name + "v";
	}
	if (function10 == 1){
		function_name = function_name + "t";
	}
	if (function11 == 1){
		function_name = function_name + "p";
	}
	if (function12 == 1){
		function_name = function_name + "d";
	}
	if (function13 == 1){
		function_name = function_name + "i";
	}
	if (function14 == 1){
		function_name = function_name + "I";
	}
	if (function15 == 1){
		function_name = function_name + "m";
	}
	if (function16 == 1){
		function_name = function_name + "R";
	}
	info_tsn$function_name = function_name;

	aggregationData_tsn = create_aggregationData_tsn(info_tsn);
	insert_res_aggregationData_tsn(aggregationData_tsn, info_tsn);
}


event raw::acyclicData(p: raw_pkt_hdr)
{
	local info_tsn: Info_TSN;
	local aggregationData_tsn: AggregationData_TSN;
	info_tsn$ts = network_time();
	info_tsn$src_mac = p$l2$src;
	info_tsn$dst_mac = p$l2$dst;
	info_tsn$service = "cclink_ie_tsn";
	info_tsn$flame_type = "acyclic";
	info_tsn$pdu_type = "acyclicData";
		
	aggregationData_tsn = create_aggregationData_tsn(info_tsn);
	insert_res_aggregationData_tsn(aggregationData_tsn, info_tsn);
}
# -----------------------------------

# local debug
event zeek_done()
{
	if (|res_aggregationData_noip| > 0) {
		for ( i in res_aggregationData_noip ){
			local info_noip: Info_NOIP = [];
			info_noip$ts = res_aggregationData_noip[i]$ts_s;
			info_noip$src_mac = i$src_mac;
			info_noip$dst_mac = i$dst_mac;
			info_noip$service = i$service;
			info_noip$pdu_type = i$pdu_type;
			if ( i?$cmd ){
				info_noip$cmd = i$cmd;
			}
			if ( i?$node_type ){
				info_noip$node_type = i$node_type;
			}
			if ( i?$node_id ){
				info_noip$node_id = i$node_id;
			}
			if ( i?$connection_info ){
				info_noip$connection_info = i$connection_info;
			}
			if ( i?$src_node_number ){
				info_noip$src_node_number = i$src_node_number;
			}
			if ( res_aggregationData_noip[i]?$ts_e ){
				info_noip$ts_end = res_aggregationData_noip[i]$ts_e;
			}
			if ( res_aggregationData_noip[i]?$num ){
				info_noip$number = res_aggregationData_noip[i]$num;
			}

			Log::write(NO_IP::LOG_NOIP, info_noip);
		}
	}

	if (|res_aggregationData_tsn| > 0) {
		for ( j in res_aggregationData_tsn ){
			local info_tsn: Info_TSN = [];
			info_tsn$ts = res_aggregationData_tsn[j]$ts_s;
			info_tsn$src_mac = j$src_mac;
			info_tsn$dst_mac = j$dst_mac;
			info_tsn$service = j$service;
			info_tsn$flame_type = j$flame_type;
			info_tsn$pdu_type = j$pdu_type;
			if ( j?$node_type ){
				info_tsn$node_type = j$node_type;
			}
			if ( j?$device_type ){
				info_tsn$device_type = j$device_type;
			}
			if ( j?$function_name ){
				info_tsn$function_name = j$function_name;
			}
			if ( res_aggregationData_tsn[j]?$ts_e ){
				info_tsn$ts_end = res_aggregationData_tsn[j]$ts_e;
			}
			if ( res_aggregationData_tsn[j]?$num ){
				info_tsn$number = res_aggregationData_tsn[j]$num;
			}

			Log::write(NO_IP::LOG_TSN, info_tsn);
		}
	}
}
