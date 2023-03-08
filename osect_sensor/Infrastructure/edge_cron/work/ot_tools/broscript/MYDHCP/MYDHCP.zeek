module MYDHCP;

export {
	redef enum Log::ID += { LOG };

	type Info: record {
		ts:		time &log;
		SrcIP:	addr &log;
		SrcMAC: string &log;
		Hostname: string &log &optional;
		ParameterList: vector of count &log &optional;
		ClassId: string &log &optional;

		# Set to block number of final piece of data once received.
		final_block: count &optional;

		# Set to true once logged.
		done: bool &default=F;
	};

	## Event that can be handled to access the mydhcp logging record.
	global log_mydhcp: event(rec: Info);

	global res_endCode: table[string] of string = { ["\x00\x00"] = "nomal", 
	                                    ["\xCF\x80"] = "stop",
										};
}

# Maps a partial data connection ID to the request's Info record.
global expected_data_conns: table[addr, port, addr] of Info;

redef record connection += {
	mydhcp: Info &optional;
};

event zeek_init() &priority=5
	{
	Log::create_stream(MYDHCP::LOG, [$columns = Info, $ev = log_mydhcp, $path="mydhcp"]);
	}

event MYDHCP::message(
	c: connection, is_orig: bool, msg: DHCP::Msg, options: DHCP::Options
	)
	{

	local info: Info;
	info$ts = network_time();
	info$SrcIP = c$id$orig_h;
	info$SrcMAC = c$orig$l2_addr;
	if ( options?$host_name ){
		info$Hostname = options$host_name;
	}
	if ( options?$param_list ){
		info$ParameterList = options$param_list;
	}
	if ( options?$vendor_class ){
		info$ClassId = options$vendor_class;
	}
	Log::write(MYDHCP::LOG, info);
	c$mydhcp = info;
	if ( options?$host_name ){
		print fmt("Zeek saw from %s %s to %s: %s options: %s msg:%s", c$start_time, c$id$orig_h, c$id$resp_h, c$orig$l2_addr, options, msg);
	} else {
		print fmt("Zeek saw from %s %s to %s: %s options: no", c$start_time, c$id$orig_h, c$id$resp_h, c$orig$l2_addr);
	}
	}
