module PacketAnalyzer::SPICY_RAWLAYER;
module NO_IP;

export {
	redef enum Log::ID += { LOG };

	type Info: record {
		ts:				time &log &optional;
		src_mac:		string &log &optional;
		dst_mac:		string &log &optional;
		service:		string &log &optional;
		pdu_type: 		string &log &optional;
		cmd:			string &log &optional;
		node_type:		string &log &optional;
		node_id:		int &log &optional;
		connection_info:string &log &optional;
		src_node_number:string &log &optional;
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

	type AggregationData: record {
		src_mac:		string &log &optional;
		dst_mac:		string &log &optional;
		service:		string &log &optional;
		pdu_type: 		string &log &optional;
		cmd:			string &log &optional;
		node_type:		string &log &optional;
		node_id:		int &log &optional;
		connection_info:string &log &optional;
		src_node_number:string &log &optional;
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
	info_insert$pdu_type = idx$pdu_type;
	if ( idx?$cmd ){
		info_insert$cmd = idx$cmd;
	}
	if ( idx?$node_type ){
		info_insert$node_type = idx$node_type;
	}
	if ( idx?$node_id ){
		info_insert$node_id = idx$node_id;
	}
	if ( idx?$connection_info ){
		info_insert$connection_info = idx$connection_info;
	}
	if ( idx?$src_node_number ){
		info_insert$src_node_number = idx$src_node_number;
	}
	if ( res_aggregationData[idx]?$ts_e ){
		info_insert$ts_end = res_aggregationData[idx]$ts_e;
	}
	if ( res_aggregationData[idx]?$num ){
		info_insert$number = res_aggregationData[idx]$num;
	}
	# print res_aggregationData;
	# print info;
	Log::write(NO_IP::LOG, info_insert);
	# res_aggregationData = {};
	return 0secs;
	}

	global res_aggregationData: table[AggregationData] of Ts_num &create_expire=60sec &expire_func=insert_log;
}

event zeek_init() &priority=5
	{
	# local f = Log::get_filter(Conn::LOG, "default");
    # f$interv = 1 min;
    # Log::add_filter(NO_IP::LOG, f);
	# insert_log(res_aggregationData, "test");
	Log::create_stream(NO_IP::LOG, [$columns = Info, $path="cclink-ie"]);
	}

event zeek_init()
	{
	if ( ! PacketAnalyzer::try_register_packet_analyzer_by_name("Ethernet", 0x890f, "spicy::NO_IP") )
		print "cannot register raw layer analyzer";
	}

function create_aggregationData(info: Info): AggregationData
	{
	local aggregationData: AggregationData;
	aggregationData$src_mac = info$src_mac;
	aggregationData$dst_mac = info$dst_mac;
	aggregationData$pdu_type = info$pdu_type;
	if ( info?$cmd ){
		aggregationData$cmd = info$cmd;
	}
	if ( info?$node_type ){
		aggregationData$node_type = info$node_type;
	}
	if ( info?$node_id ){
		aggregationData$node_id = info$node_id;
	}
	if ( info?$connection_info ){
		aggregationData$connection_info = info$connection_info;
	}
	if ( info?$src_node_number ){
		aggregationData$src_node_number = info$src_node_number;
	}
	aggregationData$service = info$service;

	return aggregationData;
	}

function insert_res_aggregationData(aggregationData: AggregationData, info: Info): string
	{
		if (aggregationData in res_aggregationData){
			res_aggregationData[aggregationData]$num = res_aggregationData[aggregationData]$num + 1;
			res_aggregationData[aggregationData]$ts_e = info$ts;
		} else {
			res_aggregationData[aggregationData] = [$ts_s = info$ts, $num = 1];
		}

		return "done";
	}

# field 伝送制御フレーム
# -----------------------------------
event raw::tokenM(p: raw_pkt_hdr, dataType: string, protocolVerType: string, srcNodeNumber: string, nodeId: int)
	{
	local info: Info;
	local aggregationData: AggregationData;
	info$ts = network_time();
	info$src_mac = p$l2$src;
	info$dst_mac = p$l2$dst;
	info$pdu_type = "tokenM";
	if ( protocolVerType == "\x00" )
	{	
		info$service="cclink_ie_control";
		info$src_node_number="0x" + string_to_ascii_hex(srcNodeNumber);
		info$node_id=nodeId;
	}
	else if ( protocolVerType == "\x01" )
	{	
		info$service="cclink_ie_field";
		info$src_node_number="0x" + string_to_ascii_hex(srcNodeNumber);
		info$node_id=nodeId;
	} else {
		info$service="unknownProtocolVerType" + protocolVerType;
	}
		
	aggregationData = create_aggregationData(info);
	insert_res_aggregationData(aggregationData, info);

	# Log::write(NO_IP::LOG, info);
	# print fmt("MACs: src=%s dst=%s", p$l2$src, p$l2$dst);
	# print "raw data", protocolVerType;
	}

event raw::persuasion(p: raw_pkt_hdr, dataType: string, protocolVerType: string, srcNodeNumber: string, nodetype: string)
	{
	local info: Info;
	local aggregationData: AggregationData;
	info$ts = network_time();
	info$src_mac = p$l2$src;
	info$dst_mac = p$l2$dst;
	info$pdu_type = "persuasion";
	if ( protocolVerType == "\x00" )
	{	
		info$src_node_number="0x" + string_to_ascii_hex(srcNodeNumber);
		if (nodetype in res_nodetype_control){
			info$node_type = res_nodetype_control[nodetype];
		} else {
			info$node_type = "unknownNodetype" + nodetype;
		}
		info$service = "cclink_ie_control";
	}
	else if ( protocolVerType == "\x01" )
	{	
		info$src_node_number="0x" + string_to_ascii_hex(srcNodeNumber);
		if (nodetype in res_nodetype_field){
			info$node_type = res_nodetype_field[nodetype];
		} else {
			info$node_type = "unknownNodetype" + nodetype;
		}
		info$service = "cclink_ie_field";
	} else {
		info$service = "unknownProtocolVerType" + protocolVerType;
	}
			
	aggregationData = create_aggregationData(info);
	insert_res_aggregationData(aggregationData, info);

	# Log::write(NO_IP::LOG, info);

	# print fmt("MACs: src=%s dst=%s", p$l2$src, p$l2$dst);
	# print "raw data", protocolVerType;
	}

event raw::testData(p: raw_pkt_hdr, dataType: string, protocolVerType: string, srcNodeNumber: string, nodetype: string)
	{
	local info: Info;
	local aggregationData: AggregationData;
	info$ts = network_time();
	info$src_mac = p$l2$src;
	info$dst_mac = p$l2$dst;
	info$pdu_type = "testData";
	if ( protocolVerType == "\x00" )
	{	
		info$src_node_number="0x" + string_to_ascii_hex(srcNodeNumber);
		if (nodetype in res_nodetype_control){
			info$node_type = res_nodetype_control[nodetype];
		} else {
			info$node_type = "unknownNodetype" + nodetype;
		}
		info$service = "cclink_ie_control";
	}
	else if ( protocolVerType == "\x01" )
	{	
		info$src_node_number="0x" + string_to_ascii_hex(srcNodeNumber);
		if (nodetype in res_nodetype_field){
			info$node_type = res_nodetype_field[nodetype];
		} else {
			info$node_type = "unknownNodetype" + nodetype;
		}
		info$service = "cclink_ie_field";
	} else {
		info$service = "unknownProtocolVerType" + protocolVerType;
	}
			
	aggregationData = create_aggregationData(info);
	insert_res_aggregationData(aggregationData, info);

	# Log::write(NO_IP::LOG, info);

	# print fmt("MACs: src=%s dst=%s", p$l2$src, p$l2$dst);
	# print "raw data", protocolVerType;
	}

event raw::testDataAck(p: raw_pkt_hdr, dataType: string, protocolVerType: string, srcNodeNumber: string, nodetype: string)
	{
	local info: Info;
	local aggregationData: AggregationData;
	info$ts = network_time();
	info$src_mac = p$l2$src;
	info$dst_mac = p$l2$dst;
	if ( protocolVerType == "\x00" )
	{	
		info$pdu_type = "testDataAck";
		info$src_node_number="0x" + string_to_ascii_hex(srcNodeNumber);
		if (nodetype in res_nodetype_control){
			info$node_type = res_nodetype_control[nodetype];
		} else {
			info$node_type = "unknownNodetype" + nodetype;
		}
		info$service = "cclink_ie_control";
	}
	else if ( protocolVerType == "\x01" )
	{	
		info$pdu_type = "testDataAck";
		info$src_node_number="0x" + string_to_ascii_hex(srcNodeNumber);
		if (nodetype in res_nodetype_field){
			info$node_type = res_nodetype_field[nodetype];
		} else {
			info$node_type = "unknownNodetype" + nodetype;
		}
		info$service = "cclink_ie_field";
	} else {
		info$service = "unknownProtocolVerType" + protocolVerType;
	}
			
	aggregationData = create_aggregationData(info);
	insert_res_aggregationData(aggregationData, info);

	# Log::write(NO_IP::LOG, info);

	# print fmt("MACs: src=%s dst=%s", p$l2$src, p$l2$dst);
	# print "raw data", protocolVerType;
	}

event raw::setup(p: raw_pkt_hdr, dataType: string, protocolVerType: string, srcNodeNumber: string, nodeId: int)
	{
	local info: Info;
	local aggregationData: AggregationData;
	info$ts = network_time();
	info$src_mac = p$l2$src;
	info$dst_mac = p$l2$dst;
	info$pdu_type = "setup";
	if ( protocolVerType == "\x00" )
	{	
		info$src_node_number="0x" + string_to_ascii_hex(srcNodeNumber);
		info$node_id=nodeId;
		info$service="cclink_ie_control";
	}
	else if ( protocolVerType == "\x01" )
	{	
		info$src_node_number="0x" + string_to_ascii_hex(srcNodeNumber);
		info$node_id=nodeId;
		info$service="cclink_ie_field";
	} else {
		info$service="unknownProtocolVerType" + protocolVerType;
	}
			
	aggregationData = create_aggregationData(info);
	insert_res_aggregationData(aggregationData, info);

	# Log::write(NO_IP::LOG, info);

	# print fmt("MACs: src=%s dst=%s", p$l2$src, p$l2$dst);
	# print "raw data", protocolVerType;
	}

event raw::setupAck(p: raw_pkt_hdr, dataType: string, protocolVerType: string, srcNodeNumber: string)
	{
	local info: Info;
	local aggregationData: AggregationData;
	info$ts = network_time();
	info$src_mac = p$l2$src;
	info$dst_mac = p$l2$dst;
	info$pdu_type = "setupAck";
	if ( protocolVerType == "\x00" )
	{
		info$service="cclink_ie_control";
		info$src_node_number="0x" + string_to_ascii_hex(srcNodeNumber);
	}
	else if ( protocolVerType == "\x01" )
	{	
		info$service="cclink_ie_field";
		info$src_node_number="0x" + string_to_ascii_hex(srcNodeNumber);
	} else {
		info$service="unknownProtocolVerType" + protocolVerType;
	}
			
	aggregationData = create_aggregationData(info);
	insert_res_aggregationData(aggregationData, info);

	# Log::write(NO_IP::LOG, info);

	# print fmt("MACs: src=%s dst=%s", p$l2$src, p$l2$dst);
	# print "raw data", protocolVerType;
	}

event raw::myStatus(p: raw_pkt_hdr, dataType: string, protocolVerType: string, srcNodeNumber: string, nodetype: string, nodeId: int, connectionInfo: string)
	{
	local info: Info;
	local aggregationData: AggregationData;
	info$ts = network_time();
	info$src_mac = p$l2$src;
	info$dst_mac = p$l2$dst;
	info$pdu_type = "myStatus";
	if ( protocolVerType == "\x00" )
	{	
		info$src_node_number="0x" + string_to_ascii_hex(srcNodeNumber);
		info$node_id=nodeId;
		info$service = "cclink_ie_control";
	}
	else if ( protocolVerType == "\x01" )
	{	
		info$src_node_number="0x" + string_to_ascii_hex(srcNodeNumber);
		info$node_id=nodeId;
		if (nodetype in res_nodetype_field){
			info$node_type = res_nodetype_field[nodetype];
		} else {
			info$node_type = "unknownNodetype" + nodetype;
		}
		info$service = "cclink_ie_field";
	} else {
		info$service = "unknownProtocolVerType" + protocolVerType;
	}
			
	aggregationData = create_aggregationData(info);
	insert_res_aggregationData(aggregationData, info);

	# Log::write(NO_IP::LOG, info);

	# print fmt("MACs: src=%s dst=%s", p$l2$src, p$l2$dst);
	# print "raw data", protocolVerType;
	}
# -----------------------------------

# field 同期フレーム
# -----------------------------------
event raw::measure(p: raw_pkt_hdr, dataType: string, protocolVerType: string, srcNodeNumber: string, nodeId: int)
	{
	local info: Info;
	local aggregationData: AggregationData;
	info$ts = network_time();
	info$src_mac = p$l2$src;
	info$dst_mac = p$l2$dst;
	info$pdu_type = "measure";
	if ( protocolVerType == "\x00" )
	{	
		info$service="cclink_ie_control";
		info$src_node_number="0x" + string_to_ascii_hex(srcNodeNumber);
	}
	else if ( protocolVerType == "\x01" )
	{	
		info$service="cclink_ie_field";
		info$src_node_number="0x" + string_to_ascii_hex(srcNodeNumber);
		info$node_id=nodeId;
	} else {
		info$service="unknownProtocolVerType" + protocolVerType;
	}
			
	aggregationData = create_aggregationData(info);
	insert_res_aggregationData(aggregationData, info);

	# Log::write(NO_IP::LOG, info);

	# print fmt("MACs: src=%s dst=%s", p$l2$src, p$l2$dst);
	# print "raw data", protocolVerType;
	}

event raw::measureAck(p: raw_pkt_hdr, dataType: string, protocolVerType: string, srcNodeNumber: string, nodeId: int)
	{
	local info: Info;
	local aggregationData: AggregationData;
	info$ts = network_time();
	info$src_mac = p$l2$src;
	info$dst_mac = p$l2$dst;
	info$pdu_type = "measureAck";
	if ( protocolVerType == "\x00" )
	{	
		info$service="cclink_ie_control";
		info$src_node_number="0x" + string_to_ascii_hex(srcNodeNumber);
	}
	else if ( protocolVerType == "\x01" )
	{
		info$service="cclink_ie_field";
		info$src_node_number="0x" + string_to_ascii_hex(srcNodeNumber);
		info$node_id=nodeId;
	} else {
		info$service="unknownProtocolVerType" + protocolVerType;
	}
			
	aggregationData = create_aggregationData(info);
	insert_res_aggregationData(aggregationData, info);

	# Log::write(NO_IP::LOG, info);

	# print fmt("MACs: src=%s dst=%s", p$l2$src, p$l2$dst);
	# print "raw data", protocolVerType;
	}

event raw::offset(p: raw_pkt_hdr, dataType: string, protocolVerType: string, srcNodeNumber: string, nodeId: int)
	{
	local info: Info;
	local aggregationData: AggregationData;
	info$ts = network_time();
	info$src_mac = p$l2$src;
	info$dst_mac = p$l2$dst;
	info$pdu_type = "offset";
	if ( protocolVerType == "\x00" )
	{	
		info$service="cclink_ie_control";
		info$src_node_number="0x" + string_to_ascii_hex(srcNodeNumber);
	}
	else if ( protocolVerType == "\x01" )
	{	
		info$service="cclink_ie_field";
		info$src_node_number="0x" + string_to_ascii_hex(srcNodeNumber);
		info$node_id=nodeId;
	} else {
		info$service="unknownProtocolVerType" + protocolVerType;
	}
			
	aggregationData = create_aggregationData(info);
	insert_res_aggregationData(aggregationData, info);

	# Log::write(NO_IP::LOG, info);

	# print fmt("MACs: src=%s dst=%s", p$l2$src, p$l2$dst);
	# print "raw data", protocolVerType;
	}

event raw::update(p: raw_pkt_hdr, dataType: string, protocolVerType: string, srcNodeNumber: string, nodeId: int)
	{
	local info: Info;
	local aggregationData: AggregationData;
	info$ts = network_time();
	info$src_mac = p$l2$src;
	info$dst_mac = p$l2$dst;
	info$pdu_type = "update";
	if ( protocolVerType == "\x00" )
	{	
		info$service="cclink_ie_control";
		info$src_node_number="0x" + string_to_ascii_hex(srcNodeNumber);
	}
	else if ( protocolVerType == "\x01" )
	{	
		info$service="cclink_ie_field";
		info$src_node_number="0x" + string_to_ascii_hex(srcNodeNumber);
		info$node_id=nodeId;
	} else {
		info$service="unknownProtocolVerType" + protocolVerType;
	}
			
	aggregationData = create_aggregationData(info);
	insert_res_aggregationData(aggregationData, info);

	# Log::write(NO_IP::LOG, info);

	# print fmt("MACs: src=%s dst=%s", p$l2$src, p$l2$dst);
	# print "raw data", protocolVerType;
	}
# -----------------------------------

# field サイクリック伝送フレーム
# -----------------------------------
event raw::cyclicDataRWw(p: raw_pkt_hdr, dataType: string, protocolVerType: string, srcNodeNumber: string, nodeId: int)
	{
	local info: Info;
	local aggregationData: AggregationData;
	info$ts = network_time();
	info$src_mac = p$l2$src;
	info$dst_mac = p$l2$dst;
	info$pdu_type = "cyclicDataRWw";
	if ( protocolVerType == "\x00" )
	{
		info$service="cclink_ie_control";
		info$src_node_number="0x" + string_to_ascii_hex(srcNodeNumber);
	}
	else if ( protocolVerType == "\x01" )
	{
		info$service="cclink_ie_field";
		info$src_node_number="0x" + string_to_ascii_hex(srcNodeNumber);
		info$node_id=nodeId;
	} else {
		info$service="unknownProtocolVerType" + protocolVerType;
	}
			
	aggregationData = create_aggregationData(info);
	insert_res_aggregationData(aggregationData, info);

	# Log::write(NO_IP::LOG, info);

	# print fmt("MACs: src=%s dst=%s", p$l2$src, p$l2$dst);
	# print "raw data", protocolVerType;
	}

event raw::cyclicDataRY(p: raw_pkt_hdr, dataType: string, protocolVerType: string, srcNodeNumber: string, nodeId: int)
	{
	local info: Info;
	local aggregationData: AggregationData;
	info$ts = network_time();
	info$src_mac = p$l2$src;
	info$dst_mac = p$l2$dst;
	info$pdu_type = "cyclicDataRY";
	if ( protocolVerType == "\x00" )
	{
		info$service="cclink_ie_control";
		info$src_node_number="0x" + string_to_ascii_hex(srcNodeNumber);
	}
	else if ( protocolVerType == "\x01" )
	{
		info$service="cclink_ie_field";
		info$src_node_number="0x" + string_to_ascii_hex(srcNodeNumber);
		info$node_id=nodeId;
	} else {
		info$service="unknownProtocolVerType" + protocolVerType;
	}
			
	aggregationData = create_aggregationData(info);
	insert_res_aggregationData(aggregationData, info);

	# Log::write(NO_IP::LOG, info);

	# print fmt("MACs: src=%s dst=%s", p$l2$src, p$l2$dst);
	# print "raw data", protocolVerType;
	}

event raw::cyclicDataRWr(p: raw_pkt_hdr, dataType: string, protocolVerType: string, srcNodeNumber: string, nodeId: int)
	{
	local info: Info;
	local aggregationData: AggregationData;
	info$ts = network_time();
	info$src_mac = p$l2$src;
	info$dst_mac = p$l2$dst;
	info$pdu_type = "cyclicDataRWr";
	if ( protocolVerType == "\x00" )
	{
		info$service="cclink_ie_control";
		info$src_node_number="0x" + string_to_ascii_hex(srcNodeNumber);
	}
	else if ( protocolVerType == "\x01" )
	{
		info$service="cclink_ie_field";
		info$src_node_number="0x" + string_to_ascii_hex(srcNodeNumber);
		info$node_id=nodeId;
	} else {
		info$service="unknownProtocolVerType" + protocolVerType;
	}
			
	aggregationData = create_aggregationData(info);
	insert_res_aggregationData(aggregationData, info);

	# Log::write(NO_IP::LOG, info);

	# print fmt("MACs: src=%s dst=%s", p$l2$src, p$l2$dst);
	# print "raw data", protocolVerType;
	}

event raw::cyclicDataRX(p: raw_pkt_hdr, dataType: string, protocolVerType: string, srcNodeNumber: string, nodeId: int)
	{
	local info: Info;
	local aggregationData: AggregationData;
	info$ts = network_time();
	info$src_mac = p$l2$src;
	info$dst_mac = p$l2$dst;
	info$pdu_type = "cyclicDataRX";
	if ( protocolVerType == "\x00" )
	{
		info$service="cclink_ie_control";
		info$src_node_number="0x" + string_to_ascii_hex(srcNodeNumber);
	}
	else if ( protocolVerType == "\x01" )
	{
		info$service="cclink_ie_field";
		info$src_node_number="0x" + string_to_ascii_hex(srcNodeNumber);
		info$node_id=nodeId;
	} else {
		info$service="unknownProtocolVerType" + protocolVerType;
	}
			
	aggregationData = create_aggregationData(info);
	insert_res_aggregationData(aggregationData, info);

	# Log::write(NO_IP::LOG, info);

	# print fmt("MACs: src=%s dst=%s", p$l2$src, p$l2$dst);
	# print "raw data", protocolVerType;
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

event raw::transient1(p: raw_pkt_hdr, dataType: int, protocolVerType: string, srcNodeNumber: string, data: Transient1Data, connectionInfo: string, nodeId: int)
	{
	local info: Info;
	local aggregationData: AggregationData;
	info$ts = network_time();
	info$src_mac = p$l2$src;
	info$dst_mac = p$l2$dst;
	info$pdu_type = "transient1";

	if ( protocolVerType == "\x00" ){
		info$src_node_number="0x" + string_to_ascii_hex(srcNodeNumber);
		info$connection_info="0x" + string_to_ascii_hex(connectionInfo);
		info$node_id=nodeId;
		info$service = "cclink_ie_control";
	} else if ( protocolVerType == "\x01" ){
		info$src_node_number="0x" + string_to_ascii_hex(srcNodeNumber);
		info$connection_info="0x" + string_to_ascii_hex(connectionInfo);
		info$node_id=nodeId;
		if (dataType == 5){
			if (data$ct in res_ct_1){
				info$cmd = res_ct_1[data$ct];
			} else {
				info$cmd = "unknownCt" + data$ct;
			}
		} else if (dataType == 7){
			if (data$command_7 in res_command_7 && data$subCommand_7 in res_subCommand){
				info$cmd = res_command_7[data$command_7] + res_subCommand[data$subCommand_7];
			} else {
				info$cmd = "unknownCmd" + data$command_7 + data$subCommand_7;
			}
		} else if (dataType == 8){
			if (data$command_8 in res_command_8 && data$subCommand_8 in res_subCommand){
				info$cmd = res_command_8[data$command_8] + res_subCommand[data$subCommand_8];
			} else {
				info$cmd = "unknownCmd" + data$command_8 + data$subCommand_8;
			}
		}
		info$service = "cclink_ie_field";
	} else {
		info$service = "unknownProtocolVerType" + protocolVerType;
	}
	
	aggregationData = create_aggregationData(info);
	insert_res_aggregationData(aggregationData, info);

	# Log::write(NO_IP::LOG, info);
	# print fmt("MACs: src=%s dst=%s %s", p$l2$src, p$l2$dst, data);
	# print "raw data", dataType;
	}

event raw::transientAck(p: raw_pkt_hdr, dataType: string, protocolVerType: string, srcNodeNumber: string, connectionInfo: string, nodeId: int)
	{
	local info: Info;
	local aggregationData: AggregationData;
	info$ts = network_time();
	info$src_mac = p$l2$src;
	info$dst_mac = p$l2$dst;
	info$pdu_type = "transientAck";
	if ( protocolVerType == "\x00" )
	{	
		info$service="cclink_ie_control";
		info$src_node_number="0x" + string_to_ascii_hex(srcNodeNumber);
	}
	else if ( protocolVerType == "\x01" )
	{
		info$service="cclink_ie_field";
		info$src_node_number="0x" + string_to_ascii_hex(srcNodeNumber);
		info$connection_info="0x" + string_to_ascii_hex(connectionInfo);
		info$node_id=nodeId;
	} else {
		info$service="unknownProtocolVerType" + protocolVerType;
	}
			
	aggregationData = create_aggregationData(info);
	insert_res_aggregationData(aggregationData, info);

	# Log::write(NO_IP::LOG, info);

	# print fmt("MACs: src=%s dst=%s", p$l2$src, p$l2$dst);
	# print "raw data", protocolVerType;
	}

event raw::transient2(p: raw_pkt_hdr, dataType: string, protocolVerType: string, srcNodeNumber: string, connectionInfo: string, nodeId: int, ct: string)
	{
	local info: Info;
	local aggregationData: AggregationData;
	info$ts = network_time();
	info$src_mac = p$l2$src;
	info$dst_mac = p$l2$dst;
	info$pdu_type = "transient2";
	if ( protocolVerType == "\x00" )
	{	
		info$src_node_number="0x" + string_to_ascii_hex(srcNodeNumber);
		info$connection_info="0x" + string_to_ascii_hex(connectionInfo);
		info$node_id=nodeId;
		if (ct in res_ct_2_control){
			info$cmd = res_ct_2_control[ct];
		} else {
			info$cmd = "unknownCt" + ct;
		}
		info$service = "cclink_ie_control";
	}
	else if ( protocolVerType == "\x01" )
	{	
		info$src_node_number="0x" + string_to_ascii_hex(srcNodeNumber);
		info$connection_info="0x" + string_to_ascii_hex(connectionInfo);
		info$node_id=nodeId;
		if (ct in res_ct_2_field){
			info$cmd = res_ct_2_field[ct];
		} else {
			info$cmd = "unknownCt" + ct;
		}
		info$service = "cclink_ie_field";
	} else {
		info$service = "unknownProtocolVerType" + protocolVerType;
	}
			
	aggregationData = create_aggregationData(info);
	insert_res_aggregationData(aggregationData, info);

	# Log::write(NO_IP::LOG, info);

	# print fmt("MACs: src=%s dst=%s", p$l2$src, p$l2$dst);
	# print "raw data", protocolVerType;
	}

event raw::paramCheck(p: raw_pkt_hdr, dataType: string, protocolVerType: string, srcNodeNumber: string, connectionInfo: string, nodeId: int)
	{
	local info: Info;
	local aggregationData: AggregationData;
	info$ts = network_time();
	info$src_mac = p$l2$src;
	info$dst_mac = p$l2$dst;
	info$pdu_type = "paramCheck";
	if ( protocolVerType == "\x00" )
	{
		info$service="cclink_ie_control";
		info$src_node_number="0x" + string_to_ascii_hex(srcNodeNumber);
	}
	else if ( protocolVerType == "\x01" )
	{
		info$service="cclink_ie_field";
		info$src_node_number="0x" + string_to_ascii_hex(srcNodeNumber);
		info$connection_info="0x" + string_to_ascii_hex(connectionInfo);
		info$node_id=nodeId;
	} else {
		info$service="unknownProtocolVerType" + protocolVerType;
	}
			
	aggregationData = create_aggregationData(info);
	insert_res_aggregationData(aggregationData, info);

	# Log::write(NO_IP::LOG, info);

	# print fmt("MACs: src=%s dst=%s", p$l2$src, p$l2$dst);
	# print "raw data", protocolVerType;
	}

event raw::parameter(p: raw_pkt_hdr, dataType: string, protocolVerType: string, srcNodeNumber: string, connectionInfo: string, nodeId: int)
	{
	local info: Info;
	local aggregationData: AggregationData;
	info$ts = network_time();
	info$src_mac = p$l2$src;
	info$dst_mac = p$l2$dst;
	info$pdu_type = "parameter";
	if ( protocolVerType == "\x00" )
	{	
		info$service="cclink_ie_control";
		info$src_node_number="0x" + string_to_ascii_hex(srcNodeNumber);
	}
	else if ( protocolVerType == "\x01" )
	{
		info$service="cclink_ie_field";
		info$src_node_number="0x" + string_to_ascii_hex(srcNodeNumber);
		info$connection_info="0x" + string_to_ascii_hex(connectionInfo);
		info$node_id=nodeId;
	} else {
		info$service="unknownProtocolVerType" + protocolVerType;
	}
			
	aggregationData = create_aggregationData(info);
	insert_res_aggregationData(aggregationData, info);

	# Log::write(NO_IP::LOG, info);

	# print fmt("MACs: src=%s dst=%s", p$l2$src, p$l2$dst);
	# print "raw data", protocolVerType;
	}

event raw::c_timer(p: raw_pkt_hdr, dataType: string, protocolVerType: string, srcNodeNumber: string)
	{
	local info: Info;
	local aggregationData: AggregationData;
	info$ts = network_time();
	info$src_mac = p$l2$src;
	info$dst_mac = p$l2$dst;
	info$pdu_type = "timer";
	if ( protocolVerType == "\x00" )
	{	
		info$service="cclink_ie_control";
		info$src_node_number="0x" + string_to_ascii_hex(srcNodeNumber);
	}
	else if ( protocolVerType == "\x01" )
	{	
		info$service="cclink_ie_field";
		info$src_node_number="0x" + string_to_ascii_hex(srcNodeNumber);
	} else {
		info$service="unknownProtocolVerType" + protocolVerType;
	}
			
	aggregationData = create_aggregationData(info);
	insert_res_aggregationData(aggregationData, info);

	# Log::write(NO_IP::LOG, info);

	# print fmt("MACs: src=%s dst=%s", p$l2$src, p$l2$dst);
	# print "raw data", protocolVerType;
	}

event raw::ipTransient(p: raw_pkt_hdr, dataType: string, protocolVerType: string, srcNodeNumber: string, connectionInfo: string, nodeId: int)
	{
	local info: Info;
	local aggregationData: AggregationData;
	info$ts = network_time();
	info$src_mac = p$l2$src;
	info$dst_mac = p$l2$dst;
	info$pdu_type = "ipTransient";
	if ( protocolVerType == "\x00" )
	{
		info$service="cclink_ie_control";
		info$src_node_number="0x" + string_to_ascii_hex(srcNodeNumber);
	}
	else if ( protocolVerType == "\x01" )
	{
		info$service="cclink_ie_field";
		info$src_node_number="0x" + string_to_ascii_hex(srcNodeNumber);
		info$connection_info="0x" + string_to_ascii_hex(connectionInfo);
		info$node_id=nodeId;
	} else {
		info$service="unknownProtocolVerType" + protocolVerType;
	}
			
	aggregationData = create_aggregationData(info);
	insert_res_aggregationData(aggregationData, info);

	# Log::write(NO_IP::LOG, info);

	# print fmt("MACs: src=%s dst=%s", p$l2$src, p$l2$dst);
	# print "raw data", protocolVerType;
	}
# -----------------------------------

# control 伝送制御フレーム
# -----------------------------------
event raw::connect(p: raw_pkt_hdr, c_priority: string, srcNodeNumber: string)
	{
	local info: Info;
	local aggregationData: AggregationData;
	info$ts = network_time();
	info$src_mac = p$l2$src;
	info$dst_mac = p$l2$dst;
	info$pdu_type = "connect";
	info$service="cclink_ie_control";
	info$src_node_number="0x" + string_to_ascii_hex(srcNodeNumber);
			
	aggregationData = create_aggregationData(info);
	insert_res_aggregationData(aggregationData, info);

	# Log::write(NO_IP::LOG, info);
	# print fmt("MACs: src=%s dst=%s", p$l2$src, p$l2$dst);
	# print "raw data", c_priority;
	}

event raw::connectAck(p: raw_pkt_hdr, c_priority: string, srcNodeNumber: string)
	{
	local info: Info;
	local aggregationData: AggregationData;
	info$ts = network_time();
	info$src_mac = p$l2$src;
	info$dst_mac = p$l2$dst;
	info$pdu_type = "connectAck";
	info$service="cclink_ie_control";
	info$src_node_number="0x" + string_to_ascii_hex(srcNodeNumber);
			
	aggregationData = create_aggregationData(info);
	insert_res_aggregationData(aggregationData, info);

	# Log::write(NO_IP::LOG, info);
	# print fmt("MACs: src=%s dst=%s", p$l2$src, p$l2$dst);
	# print "raw data", c_priority;
	}

event raw::scan(p: raw_pkt_hdr, c_priority: string, srcNodeNumber: string)
	{
	local info: Info;
	local aggregationData: AggregationData;
	info$ts = network_time();
	info$src_mac = p$l2$src;
	info$dst_mac = p$l2$dst;
	info$pdu_type = "scan";
	info$service="cclink_ie_control";
	info$src_node_number="0x" + string_to_ascii_hex(srcNodeNumber);
			
	aggregationData = create_aggregationData(info);
	insert_res_aggregationData(aggregationData, info);

	# Log::write(NO_IP::LOG, info);
	# print fmt("MACs: src=%s dst=%s", p$l2$src, p$l2$dst);
	# print "raw data", c_priority;
	}

event raw::collect(p: raw_pkt_hdr, c_priority: string, srcNodeNumber: string)
	{
	local info: Info;
	local aggregationData: AggregationData;
	info$ts = network_time();
	info$src_mac = p$l2$src;
	info$dst_mac = p$l2$dst;
	info$pdu_type = "collect";
	info$service="cclink_ie_control";
	info$src_node_number="0x" + string_to_ascii_hex(srcNodeNumber);
			
	aggregationData = create_aggregationData(info);
	insert_res_aggregationData(aggregationData, info);

	# Log::write(NO_IP::LOG, info);
	# print fmt("MACs: src=%s dst=%s", p$l2$src, p$l2$dst);
	# print "raw data", c_priority;
	}

event raw::select(p: raw_pkt_hdr, c_priority: string, srcNodeNumber: string)
	{
	local info: Info;
	local aggregationData: AggregationData;
	info$ts = network_time();
	info$src_mac = p$l2$src;
	info$dst_mac = p$l2$dst;
	info$pdu_type = "select";
	info$service="cclink_ie_control";
	info$src_node_number="0x" + string_to_ascii_hex(srcNodeNumber);
			
	aggregationData = create_aggregationData(info);
	insert_res_aggregationData(aggregationData, info);

	# Log::write(NO_IP::LOG, info);
	# print fmt("MACs: src=%s dst=%s", p$l2$src, p$l2$dst);
	# print "raw data", c_priority;
	}

event raw::launch(p: raw_pkt_hdr, c_priority: string, srcNodeNumber: string)
	{
	local info: Info;
	local aggregationData: AggregationData;
	info$ts = network_time();
	info$src_mac = p$l2$src;
	info$dst_mac = p$l2$dst;
	info$pdu_type = "launch";
	info$service="cclink_ie_control";
	info$src_node_number="0x" + string_to_ascii_hex(srcNodeNumber);
			
	aggregationData = create_aggregationData(info);
	insert_res_aggregationData(aggregationData, info);

	# Log::write(NO_IP::LOG, info);
	# print fmt("MACs: src=%s dst=%s", p$l2$src, p$l2$dst);
	# print "raw data", c_priority;
	}

event raw::token(p: raw_pkt_hdr, c_priority: string, srcNodeNumber: string)
	{
	local info: Info;
	local aggregationData: AggregationData;
	info$ts = network_time();
	info$src_mac = p$l2$src;
	info$dst_mac = p$l2$dst;
	info$pdu_type = "token";
	info$service="cclink_ie_control";
	info$src_node_number="0x" + string_to_ascii_hex(srcNodeNumber);
			
	aggregationData = create_aggregationData(info);
	insert_res_aggregationData(aggregationData, info);

	# Log::write(NO_IP::LOG, info);
	# print fmt("MACs: src=%s dst=%s", p$l2$src, p$l2$dst);
	# print "raw data", c_priority;
	}

event raw::dummy(p: raw_pkt_hdr, c_priority: string, srcNodeNumber: string)
	{
	local info: Info;
	local aggregationData: AggregationData;
	info$ts = network_time();
	info$src_mac = p$l2$src;
	info$dst_mac = p$l2$dst;
	info$pdu_type = "dummy";
	info$service="cclink_ie_control";
	info$src_node_number="0x" + string_to_ascii_hex(srcNodeNumber);
			
	aggregationData = create_aggregationData(info);
	insert_res_aggregationData(aggregationData, info);

	# Log::write(NO_IP::LOG, info);
	# print fmt("MACs: src=%s dst=%s", p$l2$src, p$l2$dst);
	# print "raw data", c_priority;
	}

event raw::nTNTest(p: raw_pkt_hdr, c_priority: string, srcNodeNumber: string)
	{
	local info: Info;
	local aggregationData: AggregationData;
	info$ts = network_time();
	info$src_mac = p$l2$src;
	info$dst_mac = p$l2$dst;
	info$pdu_type = "nTNTest";
	info$service="cclink_ie_control";
	info$src_node_number="0x" + string_to_ascii_hex(srcNodeNumber);
			
	aggregationData = create_aggregationData(info);
	insert_res_aggregationData(aggregationData, info);

	# Log::write(NO_IP::LOG, info);
	# print fmt("MACs: src=%s dst=%s", p$l2$src, p$l2$dst);
	# print "raw data", c_priority;
	}
# -----------------------------------

# control サイクリック伝送フレーム
# -----------------------------------
event raw::cyclicDataW(p: raw_pkt_hdr, c_priority: string, srcNodeNumber: string)
	{
	local info: Info;
	local aggregationData: AggregationData;
	info$ts = network_time();
	info$src_mac = p$l2$src;
	info$dst_mac = p$l2$dst;
	info$pdu_type = "cyclicDataW";
	info$service="cclink_ie_control";
	info$src_node_number="0x" + string_to_ascii_hex(srcNodeNumber);
			
	aggregationData = create_aggregationData(info);
	insert_res_aggregationData(aggregationData, info);

	# Log::write(NO_IP::LOG, info);
	# print fmt("MACs: src=%s dst=%s", p$l2$src, p$l2$dst);
	# print "raw data", c_priority;
	}

event raw::cyclicDataB(p: raw_pkt_hdr, c_priority: string, srcNodeNumber: string)
	{
	local info: Info;
	local aggregationData: AggregationData;
	info$ts = network_time();
	info$src_mac = p$l2$src;
	info$dst_mac = p$l2$dst;
	info$pdu_type = "cyclicDataB";
	info$service="cclink_ie_control";
	info$src_node_number="0x" + string_to_ascii_hex(srcNodeNumber);
			
	aggregationData = create_aggregationData(info);
	insert_res_aggregationData(aggregationData, info);

	# Log::write(NO_IP::LOG, info);
	# print fmt("MACs: src=%s dst=%s", p$l2$src, p$l2$dst);
	# print "raw data", c_priority;
	}

event raw::cyclicDataOut1(p: raw_pkt_hdr, c_priority: string, srcNodeNumber: string)
	{
	local info: Info;
	local aggregationData: AggregationData;
	info$ts = network_time();
	info$src_mac = p$l2$src;
	info$dst_mac = p$l2$dst;
	info$pdu_type = "cyclicDataOut1";
	info$service="cclink_ie_control";
	info$src_node_number="0x" + string_to_ascii_hex(srcNodeNumber);
			
	aggregationData = create_aggregationData(info);
	insert_res_aggregationData(aggregationData, info);

	# Log::write(NO_IP::LOG, info);
	# print fmt("MACs: src=%s dst=%s", p$l2$src, p$l2$dst);
	# print "raw data", c_priority;
	}

event raw::cyclicDataOut2(p: raw_pkt_hdr, c_priority: string, srcNodeNumber: string)
	{
	local info: Info;
	local aggregationData: AggregationData;
	info$ts = network_time();
	info$src_mac = p$l2$src;
	info$dst_mac = p$l2$dst;
	info$pdu_type = "cyclicDataOut2";
	info$service="cclink_ie_control";
	info$src_node_number="0x" + string_to_ascii_hex(srcNodeNumber);
			
	aggregationData = create_aggregationData(info);
	insert_res_aggregationData(aggregationData, info);

	# Log::write(NO_IP::LOG, info);
	# print fmt("MACs: src=%s dst=%s", p$l2$src, p$l2$dst);
	# print "raw data", c_priority;
	}

event raw::cyclicDataIn1(p: raw_pkt_hdr, c_priority: string, srcNodeNumber: string)
	{
	local info: Info;
	local aggregationData: AggregationData;
	info$ts = network_time();
	info$src_mac = p$l2$src;
	info$dst_mac = p$l2$dst;
	info$pdu_type = "cyclicDataIn1";
	info$service="cclink_ie_control";
	info$src_node_number="0x" + string_to_ascii_hex(srcNodeNumber);
			
	aggregationData = create_aggregationData(info);
	insert_res_aggregationData(aggregationData, info);

	# Log::write(NO_IP::LOG, info);
	# print fmt("MACs: src=%s dst=%s", p$l2$src, p$l2$dst);
	# print "raw data", c_priority;
	}

event raw::cyclicDataIn2(p: raw_pkt_hdr, c_priority: string, srcNodeNumber: string)
	{
	local info: Info;
	local aggregationData: AggregationData;
	info$ts = network_time();
	info$src_mac = p$l2$src;
	info$dst_mac = p$l2$dst;
	info$pdu_type = "cyclicDataIn2";
	info$service="cclink_ie_control";
	info$src_node_number="0x" + string_to_ascii_hex(srcNodeNumber);
			
	aggregationData = create_aggregationData(info);
	insert_res_aggregationData(aggregationData, info);

	# Log::write(NO_IP::LOG, info);
	# print fmt("MACs: src=%s dst=%s", p$l2$src, p$l2$dst);
	# print "raw data", c_priority;
	}
# -----------------------------------

# 集約 local debug用
#event zeek_done()
#	{
#	# print "zeek_done()";
#	# print res_aggregationData;
#	for ( i in res_aggregationData ){
#		# print i;
#		local info: Info = [];
#		info$ts = res_aggregationData[i]$ts_s;
#		info$src_mac = i$src_mac;
#		info$dst_mac = i$dst_mac;
#		info$service = i$service;
#		info$pdu_type = i$pdu_type;
#		if ( i?$cmd ){
#			info$cmd = i$cmd;
#		}
#		if ( i?$node_type ){
#			info$node_type = i$node_type;
#		}
#		if ( i?$node_id ){
#			info$node_id = i$node_id;
#		}
#		if ( i?$connection_info ){
#			info$connection_info = i$connection_info;
#		}
#		if ( i?$src_node_number ){
#			info$src_node_number = i$src_node_number;
#		}
#		if ( res_aggregationData[i]?$ts_e ){
#			info$ts_end = res_aggregationData[i]$ts_e;
#		}
#		if ( res_aggregationData[i]?$num ){
#			info$number = res_aggregationData[i]$num;
#		}
#		# print res_aggregationData;
#		# print info;
#		Log::write(NO_IP::LOG, info);
#	}
#	Log::write(NO_IP::LOG, [$ts = network_time()]);
#	Log::write(NO_IP::LOG, [$ts = network_time()]);
#	# res_aggregationData = {};
#	# print res_aggregationData;
#	}
