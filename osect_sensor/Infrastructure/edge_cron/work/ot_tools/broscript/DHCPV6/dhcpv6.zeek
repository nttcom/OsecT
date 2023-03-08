module DHCPV6;

export {
	redef enum Log::ID += { LOG };

	type Info: record {
		ts:		time &log;
		SrcIP:	addr &log;
		SrcMAC: string &log;
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
	Log::write(DHCPV6::LOG, info);
	c$dhcpv6 = info;
	# print fmt("Zeek saw from %s %s to %s: %s options: %s", c$start_time, c$id$orig_h, c$id$resp_h, c$orig$l2_addr, options$host_name);
	}
