module PacketAnalyzer::SPICY_RAWLAYER;
module NO_IP;

export {
	redef enum Log::ID += { LOG };

	type Info: record {
		ts:				time &log;
		src_mac:		string &log;
		dst_mac:		string &log;
		service:		string &log;
		pdu_type: 		string &log;
		cmd:			string &log &optional;
		node_type:		string &log &optional;
		node_id:		int &log &optional;
		connection_info:string &log &optional;
		src_node_number:string &log &optional;
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
}

event zeek_init() &priority=5
	{
	Log::create_stream(NO_IP::LOG, [$columns = Info, $path="field_control"]);
	}

event zeek_init()
	{
	if ( ! PacketAnalyzer::try_register_packet_analyzer_by_name("Ethernet", 0x890f, "spicy::NO_IP") )
		print "cannot register raw layer analyzer";
	}


# field 伝送制御フレーム
# -----------------------------------
event raw::tokenM(p: raw_pkt_hdr, dataType: string, protocolVerType: string, srcNodeNumber: string, nodeId: int)
	{
	if ( protocolVerType == "\x00" )
	{
		Log::write(NO_IP::LOG, [$ts  = network_time(),
							$src_mac=p$l2$src,
							$dst_mac=p$l2$dst,
							$service="cc_link_control",
							$pdu_type="tokenM",
							$src_node_number="0x" + string_to_ascii_hex(srcNodeNumber),
							$node_id=nodeId]);
	}
	else if ( protocolVerType == "\x01" )
	{
		Log::write(NO_IP::LOG, [$ts  = network_time(),
							$src_mac=p$l2$src,
							$dst_mac=p$l2$dst,
							$service="cc_link_field",
							$pdu_type="tokenM",
							$src_node_number="0x" + string_to_ascii_hex(srcNodeNumber),
							$node_id=nodeId]);
	} else {
		Log::write(NO_IP::LOG, [$ts  = network_time(),
							$src_mac=p$l2$src,
							$dst_mac=p$l2$dst,
							$service="unknownProtocolVerType" + protocolVerType,
							$pdu_type="tokenM"]);
	}

	# print fmt("MACs: src=%s dst=%s", p$l2$src, p$l2$dst);
	# print "raw data", protocolVerType;
	}

event raw::persuasion(p: raw_pkt_hdr, dataType: string, protocolVerType: string, srcNodeNumber: string, nodetype: string)
	{
	local info: Info;
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
		info$service = "cc_link_control";
	}
	else if ( protocolVerType == "\x01" )
	{	
		info$src_node_number="0x" + string_to_ascii_hex(srcNodeNumber);
		if (nodetype in res_nodetype_field){
			info$node_type = res_nodetype_field[nodetype];
		} else {
			info$node_type = "unknownNodetype" + nodetype;
		}
		info$service = "cc_link_field";
	} else {
		info$service = "unknownProtocolVerType" + protocolVerType;
	}
	Log::write(NO_IP::LOG, info);

	# print fmt("MACs: src=%s dst=%s", p$l2$src, p$l2$dst);
	# print "raw data", protocolVerType;
	}

event raw::testData(p: raw_pkt_hdr, dataType: string, protocolVerType: string, srcNodeNumber: string, nodetype: string)
	{
	local info: Info;
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
		info$service = "cc_link_control";
	}
	else if ( protocolVerType == "\x01" )
	{	
		info$src_node_number="0x" + string_to_ascii_hex(srcNodeNumber);
		if (nodetype in res_nodetype_field){
			info$node_type = res_nodetype_field[nodetype];
		} else {
			info$node_type = "unknownNodetype" + nodetype;
		}
		info$service = "cc_link_field";
	} else {
		info$service = "unknownProtocolVerType" + protocolVerType;
	}
	Log::write(NO_IP::LOG, info);

	# print fmt("MACs: src=%s dst=%s", p$l2$src, p$l2$dst);
	# print "raw data", protocolVerType;
	}

event raw::testDataAck(p: raw_pkt_hdr, dataType: string, protocolVerType: string, srcNodeNumber: string, nodetype: string)
	{
	local info: Info;
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
		info$service = "cc_link_control";
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
		info$service = "cc_link_field";
	} else {
		info$service = "unknownProtocolVerType" + protocolVerType;
	}
	Log::write(NO_IP::LOG, info);

	# print fmt("MACs: src=%s dst=%s", p$l2$src, p$l2$dst);
	# print "raw data", protocolVerType;
	}

event raw::setup(p: raw_pkt_hdr, dataType: string, protocolVerType: string, srcNodeNumber: string, nodeId: int)
	{
	if ( protocolVerType == "\x00" )
	{
		Log::write(NO_IP::LOG, [$ts  = network_time(),
							$src_mac=p$l2$src,
							$dst_mac=p$l2$dst,
							$service="cc_link_control",
							$pdu_type="setup",
							$src_node_number="0x" + string_to_ascii_hex(srcNodeNumber),
							$node_id=nodeId]);
	}
	else if ( protocolVerType == "\x01" )
	{
		Log::write(NO_IP::LOG, [$ts  = network_time(),
							$src_mac=p$l2$src,
							$dst_mac=p$l2$dst,
							$service="cc_link_field",
							$pdu_type="setup",
							$src_node_number="0x" + string_to_ascii_hex(srcNodeNumber),
							$node_id=nodeId]);
	} else {
		Log::write(NO_IP::LOG, [$ts  = network_time(),
							$src_mac=p$l2$src,
							$dst_mac=p$l2$dst,
							$service="unknownProtocolVerType" + protocolVerType,
							$pdu_type="setup"]);
	}

	# print fmt("MACs: src=%s dst=%s", p$l2$src, p$l2$dst);
	# print "raw data", protocolVerType;
	}

event raw::setupAck(p: raw_pkt_hdr, dataType: string, protocolVerType: string, srcNodeNumber: string)
	{
	if ( protocolVerType == "\x00" )
	{
		Log::write(NO_IP::LOG, [$ts  = network_time(),
							$src_mac=p$l2$src,
							$dst_mac=p$l2$dst,
							$service="cc_link_control",
							$pdu_type="setupAck",
							$src_node_number="0x" + string_to_ascii_hex(srcNodeNumber)]);
	}
	else if ( protocolVerType == "\x01" )
	{
		Log::write(NO_IP::LOG, [$ts  = network_time(),
							$src_mac=p$l2$src,
							$dst_mac=p$l2$dst,
							$service="cc_link_field",
							$pdu_type="setupAck",
							$src_node_number="0x" + string_to_ascii_hex(srcNodeNumber)]);
	} else {
		Log::write(NO_IP::LOG, [$ts  = network_time(),
							$src_mac=p$l2$src,
							$dst_mac=p$l2$dst,
							$service="unknownProtocolVerType" + protocolVerType,
							$pdu_type="setupAck"]);
	}

	# print fmt("MACs: src=%s dst=%s", p$l2$src, p$l2$dst);
	# print "raw data", protocolVerType;
	}

event raw::myStatus(p: raw_pkt_hdr, dataType: string, protocolVerType: string, srcNodeNumber: string, nodetype: string, nodeId: int, connectionInfo: string)
	{
	local info: Info;
	info$ts = network_time();
	info$src_mac = p$l2$src;
	info$dst_mac = p$l2$dst;
	info$pdu_type = "myStatus";
	if ( protocolVerType == "\x00" )
	{	
		info$src_node_number="0x" + string_to_ascii_hex(srcNodeNumber);
		info$node_id=nodeId;
		info$service = "cc_link_control";
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
		info$service = "cc_link_field";
	} else {
		info$service = "unknownProtocolVerType" + protocolVerType;
	}
	Log::write(NO_IP::LOG, info);

	# print fmt("MACs: src=%s dst=%s", p$l2$src, p$l2$dst);
	# print "raw data", protocolVerType;
	}
# -----------------------------------

# field 同期フレーム
# -----------------------------------
event raw::measure(p: raw_pkt_hdr, dataType: string, protocolVerType: string, srcNodeNumber: string, nodeId: int)
	{
	if ( protocolVerType == "\x00" )
	{
		Log::write(NO_IP::LOG, [$ts  = network_time(),
							$src_mac=p$l2$src,
							$dst_mac=p$l2$dst,
							$service="cc_link_control",
							$pdu_type="measure",
							$src_node_number="0x" + string_to_ascii_hex(srcNodeNumber)]);
	}
	else if ( protocolVerType == "\x01" )
	{
		Log::write(NO_IP::LOG, [$ts  = network_time(),
							$src_mac=p$l2$src,
							$dst_mac=p$l2$dst,
							$service="cc_link_field",
							$pdu_type="measure",
							$src_node_number="0x" + string_to_ascii_hex(srcNodeNumber),
							$node_id=nodeId]);
	} else {
		Log::write(NO_IP::LOG, [$ts  = network_time(),
							$src_mac=p$l2$src,
							$dst_mac=p$l2$dst,
							$service="unknownProtocolVerType" + protocolVerType,
							$pdu_type="measure"]);
	}

	# print fmt("MACs: src=%s dst=%s", p$l2$src, p$l2$dst);
	# print "raw data", protocolVerType;
	}

event raw::measureAck(p: raw_pkt_hdr, dataType: string, protocolVerType: string, srcNodeNumber: string, nodeId: int)
	{
	if ( protocolVerType == "\x00" )
	{
		Log::write(NO_IP::LOG, [$ts  = network_time(),
							$src_mac=p$l2$src,
							$dst_mac=p$l2$dst,
							$service="cc_link_control",
							$pdu_type="measureAck",
							$src_node_number="0x" + string_to_ascii_hex(srcNodeNumber)]);
	}
	else if ( protocolVerType == "\x01" )
	{
		Log::write(NO_IP::LOG, [$ts  = network_time(),
							$src_mac=p$l2$src,
							$dst_mac=p$l2$dst,
							$service="cc_link_field",
							$pdu_type="measureAck",
							$src_node_number="0x" + string_to_ascii_hex(srcNodeNumber),
							$node_id=nodeId]);
	} else {
		Log::write(NO_IP::LOG, [$ts  = network_time(),
							$src_mac=p$l2$src,
							$dst_mac=p$l2$dst,
							$service="unknownProtocolVerType" + protocolVerType,
							$pdu_type="measureAck"]);
	}

	# print fmt("MACs: src=%s dst=%s", p$l2$src, p$l2$dst);
	# print "raw data", protocolVerType;
	}

event raw::offset(p: raw_pkt_hdr, dataType: string, protocolVerType: string, srcNodeNumber: string, nodeId: int)
	{
	if ( protocolVerType == "\x00" )
	{
		Log::write(NO_IP::LOG, [$ts  = network_time(),
							$src_mac=p$l2$src,
							$dst_mac=p$l2$dst,
							$service="cc_link_control",
							$pdu_type="offset",
							$src_node_number="0x" + string_to_ascii_hex(srcNodeNumber)]);
	}
	else if ( protocolVerType == "\x01" )
	{
		Log::write(NO_IP::LOG, [$ts  = network_time(),
							$src_mac=p$l2$src,
							$dst_mac=p$l2$dst,
							$service="cc_link_field",
							$pdu_type="offset",
							$src_node_number="0x" + string_to_ascii_hex(srcNodeNumber),
							$node_id=nodeId]);
	} else {
		Log::write(NO_IP::LOG, [$ts  = network_time(),
							$src_mac=p$l2$src,
							$dst_mac=p$l2$dst,
							$service="unknownProtocolVerType" + protocolVerType,
							$pdu_type="offset"]);
	}

	# print fmt("MACs: src=%s dst=%s", p$l2$src, p$l2$dst);
	# print "raw data", protocolVerType;
	}

event raw::update(p: raw_pkt_hdr, dataType: string, protocolVerType: string, srcNodeNumber: string, nodeId: int)
	{
	if ( protocolVerType == "\x00" )
	{
		Log::write(NO_IP::LOG, [$ts  = network_time(),
							$src_mac=p$l2$src,
							$dst_mac=p$l2$dst,
							$service="cc_link_control",
							$pdu_type="update",
							$src_node_number="0x" + string_to_ascii_hex(srcNodeNumber)]);
	}
	else if ( protocolVerType == "\x01" )
	{
		Log::write(NO_IP::LOG, [$ts  = network_time(),
							$src_mac=p$l2$src,
							$dst_mac=p$l2$dst,
							$service="cc_link_field",
							$pdu_type="update",
							$src_node_number="0x" + string_to_ascii_hex(srcNodeNumber),
							$node_id=nodeId]);
	} else {
		Log::write(NO_IP::LOG, [$ts  = network_time(),
							$src_mac=p$l2$src,
							$dst_mac=p$l2$dst,
							$service="unknownProtocolVerType" + protocolVerType,
							$pdu_type="update"]);
	}

	# print fmt("MACs: src=%s dst=%s", p$l2$src, p$l2$dst);
	# print "raw data", protocolVerType;
	}
# -----------------------------------

# field サイクリック伝送フレーム
# -----------------------------------
event raw::cyclicDataRWw(p: raw_pkt_hdr, dataType: string, protocolVerType: string, srcNodeNumber: string, nodeId: int)
	{
	if ( protocolVerType == "\x00" )
	{
		Log::write(NO_IP::LOG, [$ts  = network_time(),
							$src_mac=p$l2$src,
							$dst_mac=p$l2$dst,
							$service="cc_link_control",
							$pdu_type="cyclicDataRWw",
							$src_node_number="0x" + string_to_ascii_hex(srcNodeNumber)]);
	}
	else if ( protocolVerType == "\x01" )
	{
		Log::write(NO_IP::LOG, [$ts  = network_time(),
							$src_mac=p$l2$src,
							$dst_mac=p$l2$dst,
							$service="cc_link_field",
							$pdu_type="cyclicDataRWw",
							$src_node_number="0x" + string_to_ascii_hex(srcNodeNumber),
							$node_id=nodeId]);
	} else {
		Log::write(NO_IP::LOG, [$ts  = network_time(),
							$src_mac=p$l2$src,
							$dst_mac=p$l2$dst,
							$service="unknownProtocolVerType" + protocolVerType,
							$pdu_type="cyclicDataRWw"]);
	}

	# print fmt("MACs: src=%s dst=%s", p$l2$src, p$l2$dst);
	# print "raw data", protocolVerType;
	}

event raw::cyclicDataRY(p: raw_pkt_hdr, dataType: string, protocolVerType: string, srcNodeNumber: string, nodeId: int)
	{
	if ( protocolVerType == "\x00" )
	{
		Log::write(NO_IP::LOG, [$ts  = network_time(),
							$src_mac=p$l2$src,
							$dst_mac=p$l2$dst,
							$service="cc_link_control",
							$pdu_type="cyclicDataRY",
							$src_node_number="0x" + string_to_ascii_hex(srcNodeNumber)]);
	}
	else if ( protocolVerType == "\x01" )
	{
		Log::write(NO_IP::LOG, [$ts  = network_time(),
							$src_mac=p$l2$src,
							$dst_mac=p$l2$dst,
							$service="cc_link_field",
							$pdu_type="cyclicDataRY",
							$src_node_number="0x" + string_to_ascii_hex(srcNodeNumber),
							$node_id=nodeId]);
	} else {
		Log::write(NO_IP::LOG, [$ts  = network_time(),
							$src_mac=p$l2$src,
							$dst_mac=p$l2$dst,
							$service="unknownProtocolVerType" + protocolVerType,
							$pdu_type="cyclicDataRY"]);
	}

	# print fmt("MACs: src=%s dst=%s", p$l2$src, p$l2$dst);
	# print "raw data", protocolVerType;
	}

event raw::cyclicDataRWr(p: raw_pkt_hdr, dataType: string, protocolVerType: string, srcNodeNumber: string, nodeId: int)
	{
	if ( protocolVerType == "\x00" )
	{
		Log::write(NO_IP::LOG, [$ts  = network_time(),
							$src_mac=p$l2$src,
							$dst_mac=p$l2$dst,
							$service="cc_link_control",
							$pdu_type="cyclicDataRWr",
							$src_node_number="0x" + string_to_ascii_hex(srcNodeNumber)]);
	}
	else if ( protocolVerType == "\x01" )
	{
		Log::write(NO_IP::LOG, [$ts  = network_time(),
							$src_mac=p$l2$src,
							$dst_mac=p$l2$dst,
							$service="cc_link_field",
							$pdu_type="cyclicDataRWr",
							$src_node_number="0x" + string_to_ascii_hex(srcNodeNumber),
							$node_id=nodeId]);
	} else {
		Log::write(NO_IP::LOG, [$ts  = network_time(),
							$src_mac=p$l2$src,
							$dst_mac=p$l2$dst,
							$service="unknownProtocolVerType" + protocolVerType,
							$pdu_type="cyclicDataRWr"]);
	}

	# print fmt("MACs: src=%s dst=%s", p$l2$src, p$l2$dst);
	# print "raw data", protocolVerType;
	}

event raw::cyclicDataRX(p: raw_pkt_hdr, dataType: string, protocolVerType: string, srcNodeNumber: string, nodeId: int)
	{
	if ( protocolVerType == "\x00" )
	{
		Log::write(NO_IP::LOG, [$ts  = network_time(),
							$src_mac=p$l2$src,
							$dst_mac=p$l2$dst,
							$service="cc_link_control",
							$pdu_type="cyclicDataRX",
							$src_node_number="0x" + string_to_ascii_hex(srcNodeNumber)]);
	}
	else if ( protocolVerType == "\x01" )
	{
		Log::write(NO_IP::LOG, [$ts  = network_time(),
							$src_mac=p$l2$src,
							$dst_mac=p$l2$dst,
							$service="cc_link_field",
							$pdu_type="cyclicDataRX",
							$src_node_number="0x" + string_to_ascii_hex(srcNodeNumber),
							$node_id=nodeId]);
	} else {
		Log::write(NO_IP::LOG, [$ts  = network_time(),
							$src_mac=p$l2$src,
							$dst_mac=p$l2$dst,
							$service="unknownProtocolVerType" + protocolVerType,
							$pdu_type="cyclicDataRX"]);
	}

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
	info$ts = network_time();
	info$src_mac = p$l2$src;
	info$dst_mac = p$l2$dst;
	info$pdu_type = "transient1";

	if ( protocolVerType == "\x00" ){
		info$src_node_number="0x" + string_to_ascii_hex(srcNodeNumber);
		info$connection_info="0x" + string_to_ascii_hex(connectionInfo);
		info$node_id=nodeId;
		info$service = "cc_link_control";
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
		info$service = "cc_link_field";
	} else {
		info$service = "unknownProtocolVerType" + protocolVerType;
	}
	Log::write(NO_IP::LOG, info);

	# print fmt("MACs: src=%s dst=%s %s", p$l2$src, p$l2$dst, data);
	# print "raw data", dataType;
	}

event raw::transientAck(p: raw_pkt_hdr, dataType: string, protocolVerType: string, srcNodeNumber: string, connectionInfo: string, nodeId: int)
	{
	if ( protocolVerType == "\x00" )
	{
		Log::write(NO_IP::LOG, [$ts  = network_time(),
							$src_mac=p$l2$src,
							$dst_mac=p$l2$dst,
							$service="cc_link_control",
							$pdu_type="transientAck",
							$src_node_number="0x" + string_to_ascii_hex(srcNodeNumber)]);
	}
	else if ( protocolVerType == "\x01" )
	{
		Log::write(NO_IP::LOG, [$ts  = network_time(),
							$src_mac=p$l2$src,
							$dst_mac=p$l2$dst,
							$service="cc_link_field",
							$pdu_type="transientAck",
							$src_node_number="0x" + string_to_ascii_hex(srcNodeNumber),
							$connection_info="0x" + string_to_ascii_hex(connectionInfo),
							$node_id=nodeId]);
	} else {
		Log::write(NO_IP::LOG, [$ts  = network_time(),
							$src_mac=p$l2$src,
							$dst_mac=p$l2$dst,
							$service="unknownProtocolVerType" + protocolVerType,
							$pdu_type="transientAck"]);
	}

	# print fmt("MACs: src=%s dst=%s", p$l2$src, p$l2$dst);
	# print "raw data", protocolVerType;
	}

event raw::transient2(p: raw_pkt_hdr, dataType: string, protocolVerType: string, srcNodeNumber: string, connectionInfo: string, nodeId: int, ct: string)
	{
	local info: Info;
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
		info$service = "cc_link_control";
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
		info$service = "cc_link_field";
	} else {
		info$service = "unknownProtocolVerType" + protocolVerType;
	}
	Log::write(NO_IP::LOG, info);

	# print fmt("MACs: src=%s dst=%s", p$l2$src, p$l2$dst);
	# print "raw data", protocolVerType;
	}

event raw::paramCheck(p: raw_pkt_hdr, dataType: string, protocolVerType: string, srcNodeNumber: string, connectionInfo: string, nodeId: int)
	{
	if ( protocolVerType == "\x00" )
	{
		Log::write(NO_IP::LOG, [$ts  = network_time(),
							$src_mac=p$l2$src,
							$dst_mac=p$l2$dst,
							$service="cc_link_control",
							$pdu_type="paramCheck",
							$src_node_number="0x" + string_to_ascii_hex(srcNodeNumber)]);
	}
	else if ( protocolVerType == "\x01" )
	{
		Log::write(NO_IP::LOG, [$ts  = network_time(),
							$src_mac=p$l2$src,
							$dst_mac=p$l2$dst,
							$service="cc_link_field",
							$pdu_type="paramCheck",
							$src_node_number="0x" + string_to_ascii_hex(srcNodeNumber),
							$connection_info="0x" + string_to_ascii_hex(connectionInfo),
							$node_id=nodeId]);
	} else {
		Log::write(NO_IP::LOG, [$ts  = network_time(),
							$src_mac=p$l2$src,
							$dst_mac=p$l2$dst,
							$service="unknownProtocolVerType" + protocolVerType,
							$pdu_type="paramCheck"]);
	}

	# print fmt("MACs: src=%s dst=%s", p$l2$src, p$l2$dst);
	# print "raw data", protocolVerType;
	}

event raw::parameter(p: raw_pkt_hdr, dataType: string, protocolVerType: string, srcNodeNumber: string, connectionInfo: string, nodeId: int)
	{
	if ( protocolVerType == "\x00" )
	{
		Log::write(NO_IP::LOG, [$ts  = network_time(),
							$src_mac=p$l2$src,
							$dst_mac=p$l2$dst,
							$service="cc_link_control",
							$pdu_type="parameter",
							$src_node_number="0x" + string_to_ascii_hex(srcNodeNumber)]);
	}
	else if ( protocolVerType == "\x01" )
	{
		Log::write(NO_IP::LOG, [$ts  = network_time(),
							$src_mac=p$l2$src,
							$dst_mac=p$l2$dst,
							$service="cc_link_field",
							$pdu_type="parameter",
							$src_node_number="0x" + string_to_ascii_hex(srcNodeNumber),
							$connection_info="0x" + string_to_ascii_hex(connectionInfo),
							$node_id=nodeId]);
	} else {
		Log::write(NO_IP::LOG, [$ts  = network_time(),
							$src_mac=p$l2$src,
							$dst_mac=p$l2$dst,
							$service="unknownProtocolVerType" + protocolVerType,
							$pdu_type="parameter"]);
	}

	# print fmt("MACs: src=%s dst=%s", p$l2$src, p$l2$dst);
	# print "raw data", protocolVerType;
	}

event raw::c_timer(p: raw_pkt_hdr, dataType: string, protocolVerType: string, srcNodeNumber: string)
	{
	if ( protocolVerType == "\x00" )
	{
		Log::write(NO_IP::LOG, [$ts  = network_time(),
							$src_mac=p$l2$src,
							$dst_mac=p$l2$dst,
							$service="cc_link_control",
							$pdu_type="timer",
							$src_node_number="0x" + string_to_ascii_hex(srcNodeNumber)]);
	}
	else if ( protocolVerType == "\x01" )
	{
		Log::write(NO_IP::LOG, [$ts  = network_time(),
							$src_mac=p$l2$src,
							$dst_mac=p$l2$dst,
							$service="cc_link_field",
							$pdu_type="timer",
							$src_node_number="0x" + string_to_ascii_hex(srcNodeNumber)]);
	} else {
		Log::write(NO_IP::LOG, [$ts  = network_time(),
							$src_mac=p$l2$src,
							$dst_mac=p$l2$dst,
							$service="unknownProtocolVerType" + protocolVerType,
							$pdu_type="timer"]);
	}

	# print fmt("MACs: src=%s dst=%s", p$l2$src, p$l2$dst);
	# print "raw data", protocolVerType;
	}

event raw::ipTransient(p: raw_pkt_hdr, dataType: string, protocolVerType: string, srcNodeNumber: string, connectionInfo: string, nodeId: int)
	{
	if ( protocolVerType == "\x00" )
	{
		Log::write(NO_IP::LOG, [$ts  = network_time(),
							$src_mac=p$l2$src,
							$dst_mac=p$l2$dst,
							$service="cc_link_control",
							$pdu_type="ipTransient",
							$src_node_number="0x" + string_to_ascii_hex(srcNodeNumber)]);
	}
	else if ( protocolVerType == "\x01" )
	{
		Log::write(NO_IP::LOG, [$ts  = network_time(),
							$src_mac=p$l2$src,
							$dst_mac=p$l2$dst,
							$service="cc_link_field",
							$pdu_type="ipTransient",
							$src_node_number="0x" + string_to_ascii_hex(srcNodeNumber),
							$connection_info="0x" + string_to_ascii_hex(connectionInfo),
							$node_id=nodeId]);
	} else {
		Log::write(NO_IP::LOG, [$ts  = network_time(),
							$src_mac=p$l2$src,
							$dst_mac=p$l2$dst,
							$service="unknownProtocolVerType" + protocolVerType,
							$pdu_type="ipTransient"]);
	}

	# print fmt("MACs: src=%s dst=%s", p$l2$src, p$l2$dst);
	# print "raw data", protocolVerType;
	}
# -----------------------------------

# control 伝送制御フレーム
# -----------------------------------
event raw::connect(p: raw_pkt_hdr, c_priority: string, srcNodeNumber: string)
	{
	Log::write(NO_IP::LOG, [$ts  = network_time(),
							$src_mac=p$l2$src,
							$dst_mac=p$l2$dst,
							$service="cc_link_control",
							$pdu_type="connect",
							$src_node_number="0x" + string_to_ascii_hex(srcNodeNumber)]);
	# print fmt("MACs: src=%s dst=%s", p$l2$src, p$l2$dst);
	# print "raw data", c_priority;
	}

event raw::connectAck(p: raw_pkt_hdr, c_priority: string, srcNodeNumber: string)
	{
	Log::write(NO_IP::LOG, [$ts  = network_time(),
							$src_mac=p$l2$src,
							$dst_mac=p$l2$dst,
							$service="cc_link_control",
							$pdu_type="connect",
							$src_node_number="0x" + string_to_ascii_hex(srcNodeNumber)]);
	# print fmt("MACs: src=%s dst=%s", p$l2$src, p$l2$dst);
	# print "raw data", c_priority;
	}

event raw::scan(p: raw_pkt_hdr, c_priority: string, srcNodeNumber: string)
	{
	Log::write(NO_IP::LOG, [$ts  = network_time(),
							$src_mac=p$l2$src,
							$dst_mac=p$l2$dst,
							$service="cc_link_control",
							$pdu_type="scan",
							$src_node_number="0x" + string_to_ascii_hex(srcNodeNumber)]);
	# print fmt("MACs: src=%s dst=%s", p$l2$src, p$l2$dst);
	# print "raw data", c_priority;
	}

event raw::collect(p: raw_pkt_hdr, c_priority: string, srcNodeNumber: string)
	{
	Log::write(NO_IP::LOG, [$ts  = network_time(),
							$src_mac=p$l2$src,
							$dst_mac=p$l2$dst,
							$service="cc_link_control",
							$pdu_type="collect",
							$src_node_number="0x" + string_to_ascii_hex(srcNodeNumber)]);
	# print fmt("MACs: src=%s dst=%s", p$l2$src, p$l2$dst);
	# print "raw data", c_priority;
	}

event raw::select(p: raw_pkt_hdr, c_priority: string, srcNodeNumber: string)
	{
	Log::write(NO_IP::LOG, [$ts  = network_time(),
							$src_mac=p$l2$src,
							$dst_mac=p$l2$dst,
							$service="cc_link_control",
							$pdu_type="select",
							$src_node_number="0x" + string_to_ascii_hex(srcNodeNumber)]);
	# print fmt("MACs: src=%s dst=%s", p$l2$src, p$l2$dst);
	# print "raw data", c_priority;
	}

event raw::launch(p: raw_pkt_hdr, c_priority: string, srcNodeNumber: string)
	{
	Log::write(NO_IP::LOG, [$ts  = network_time(),
							$src_mac=p$l2$src,
							$dst_mac=p$l2$dst,
							$service="cc_link_control",
							$pdu_type="launch",
							$src_node_number="0x" + string_to_ascii_hex(srcNodeNumber)]);
	# print fmt("MACs: src=%s dst=%s", p$l2$src, p$l2$dst);
	# print "raw data", c_priority;
	}

event raw::token(p: raw_pkt_hdr, c_priority: string, srcNodeNumber: string)
	{
	Log::write(NO_IP::LOG, [$ts  = network_time(),
							$src_mac=p$l2$src,
							$dst_mac=p$l2$dst,
							$service="cc_link_control",
							$pdu_type="token",
							$src_node_number="0x" + string_to_ascii_hex(srcNodeNumber)]);
	# print fmt("MACs: src=%s dst=%s", p$l2$src, p$l2$dst);
	# print "raw data", c_priority;
	}

event raw::dummy(p: raw_pkt_hdr, c_priority: string, srcNodeNumber: string)
	{
	Log::write(NO_IP::LOG, [$ts  = network_time(),
							$src_mac=p$l2$src,
							$dst_mac=p$l2$dst,
							$service="cc_link_control",
							$pdu_type="dummy",
							$src_node_number="0x" + string_to_ascii_hex(srcNodeNumber)]);
	# print fmt("MACs: src=%s dst=%s", p$l2$src, p$l2$dst);
	# print "raw data", c_priority;
	}

event raw::nTNTest(p: raw_pkt_hdr, c_priority: string, srcNodeNumber: string)
	{
	Log::write(NO_IP::LOG, [$ts  = network_time(),
							$src_mac=p$l2$src,
							$dst_mac=p$l2$dst,
							$service="cc_link_control",
							$pdu_type="nTNTest",
							$src_node_number="0x" + string_to_ascii_hex(srcNodeNumber)]);
	# print fmt("MACs: src=%s dst=%s", p$l2$src, p$l2$dst);
	# print "raw data", c_priority;
	}
# -----------------------------------

# control サイクリック伝送フレーム
# -----------------------------------
event raw::cyclicDataW(p: raw_pkt_hdr, c_priority: string, srcNodeNumber: string)
	{
	Log::write(NO_IP::LOG, [$ts  = network_time(),
							$src_mac=p$l2$src,
							$dst_mac=p$l2$dst,
							$service="cc_link_control",
							$pdu_type="cyclicDataW",
							$src_node_number="0x" + string_to_ascii_hex(srcNodeNumber)]);
	# print fmt("MACs: src=%s dst=%s", p$l2$src, p$l2$dst);
	# print "raw data", c_priority;
	}

event raw::cyclicDataB(p: raw_pkt_hdr, c_priority: string, srcNodeNumber: string)
	{
	Log::write(NO_IP::LOG, [$ts  = network_time(),
							$src_mac=p$l2$src,
							$dst_mac=p$l2$dst,
							$service="cc_link_control",
							$pdu_type="cyclicDataB",
							$src_node_number="0x" + string_to_ascii_hex(srcNodeNumber)]);
	# print fmt("MACs: src=%s dst=%s", p$l2$src, p$l2$dst);
	# print "raw data", c_priority;
	}

event raw::cyclicDataOut1(p: raw_pkt_hdr, c_priority: string, srcNodeNumber: string)
	{
	Log::write(NO_IP::LOG, [$ts  = network_time(),
							$src_mac=p$l2$src,
							$dst_mac=p$l2$dst,
							$service="cc_link_control",
							$pdu_type="cyclicDataOut1",
							$src_node_number="0x" + string_to_ascii_hex(srcNodeNumber)]);
	# print fmt("MACs: src=%s dst=%s", p$l2$src, p$l2$dst);
	# print "raw data", c_priority;
	}

event raw::cyclicDataOut2(p: raw_pkt_hdr, c_priority: string, srcNodeNumber: string)
	{
	Log::write(NO_IP::LOG, [$ts  = network_time(),
							$src_mac=p$l2$src,
							$dst_mac=p$l2$dst,
							$service="cc_link_control",
							$pdu_type="cyclicDataOut2",
							$src_node_number="0x" + string_to_ascii_hex(srcNodeNumber)]);
	# print fmt("MACs: src=%s dst=%s", p$l2$src, p$l2$dst);
	# print "raw data", c_priority;
	}

event raw::cyclicDataIn1(p: raw_pkt_hdr, c_priority: string, srcNodeNumber: string)
	{
	Log::write(NO_IP::LOG, [$ts  = network_time(),
							$src_mac=p$l2$src,
							$dst_mac=p$l2$dst,
							$service="cc_link_control",
							$pdu_type="cyclicDataIn1",
							$src_node_number="0x" + string_to_ascii_hex(srcNodeNumber)]);
	# print fmt("MACs: src=%s dst=%s", p$l2$src, p$l2$dst);
	# print "raw data", c_priority;
	}

event raw::cyclicDataIn2(p: raw_pkt_hdr, c_priority: string, srcNodeNumber: string)
	{
	Log::write(NO_IP::LOG, [$ts  = network_time(),
							$src_mac=p$l2$src,
							$dst_mac=p$l2$dst,
							$service="cc_link_control",
							$pdu_type="cyclicDataIn2",
							$src_node_number="0x" + string_to_ascii_hex(srcNodeNumber)]);
	# print fmt("MACs: src=%s dst=%s", p$l2$src, p$l2$dst);
	# print "raw data", c_priority;
	}
# -----------------------------------
