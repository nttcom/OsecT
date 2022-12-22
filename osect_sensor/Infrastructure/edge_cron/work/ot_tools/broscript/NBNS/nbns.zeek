module NBNS;

export {
	redef enum Log::ID += { LOG };

	type Info: record {
		ts:		time &log;
		SrcIP:	addr &log;
		SrcMAC: string &log;
		Name: string &log &optional;
		TTL: count &log &optional;
		ServiceType: string &log &optional;

		# Set to block number of final piece of data once received.
		final_block: count &optional;

		# Set to true once logged.
		done: bool &default=F;
	};

	## Event that can be handled to access the nbns logging record.
	global log_nbns: event(rec: Info);

	global res_serviceType: table[string] of string = { ["00"] = "Workstation", 
	                                    ["03"] = "Messenger", 
										["06"] = "RAS Server", 
										["1f"] = "NetDDE", 
										["20"] = "Server", 
										["21"] = "RAS Client", 
										["be"] = "Network Monitor Agent", 
										["bf"] = "Network Monitor Application", 
										["1d"] = "Master Browser", 
										["1b"] = "Domain Master Browser", 
										["1c"] = "Domain Controllers", 
										["1e"] = "Browser Service Elections", 
										["01"] = "Master Browser", 
										};
}

# Maps a partial data connection ID to the request's Info record.
global expected_data_conns: table[addr, port, addr] of Info;

redef record connection += {
	nbns: Info &optional;
};

function del_space(s: string): string
	{
	local res = "";
	for ( i in  s ) {
		if (i != " ") {
			res = res + i;
		}
	}
	return res;
	}

function half_to_full(queries_name: string): string
{	
	local i = 0;
	local tmp1 = 0;
	local tmp2 = 0;
	local tmp3 = "";
	local res: vector of string = {};
	local res_return = "";

	while ( i < 32 )
	{	
		tmp1 = (bytestring_to_count(queries_name[i]) - 0x41) * 16;
		tmp2 = (bytestring_to_count(queries_name[i + 1]) - 0x41) & 0xf;
		tmp3 = fmt("%x", tmp1 | tmp2);
		if (tmp3 == "0"){
			res[|res|] = hexstr_to_bytestring("00");
		} else {
			res[|res|] = hexstr_to_bytestring(tmp3);
		}
		i = i + 2;
	}
	for ( i in  res) 
	{	
		res_return = res_return + res[i];
	}
	return res_return;
}

event zeek_init() &priority=5
	{
	Log::create_stream(NBNS::LOG, [$columns = Info, $ev = log_nbns, $path="nbns"]);
	}

event NBNS::message(c: connection, name_type: int, additional_records_ttl: count, queries_name: string)
	{
	# print fmt("%s %s %s %s %s %s %s", network_time(), c$id$orig_h, c$id$resp_h, c$orig$l2_addr, name_type, additional_records_ttl, queries_name);
	if (name_type == 0){
		local info: Info;
		local tmp: string;
		info$ts = network_time();
		info$SrcIP = c$id$orig_h;
		info$SrcMAC = c$orig$l2_addr;
		info$TTL = additional_records_ttl;
		info$Name = del_space(half_to_full(queries_name[1:-1])[:-2]);
		tmp = bytestring_to_hexstr(half_to_full(queries_name[1:-1])[-1]);
		if (tmp in res_serviceType) {
			info$ServiceType = res_serviceType[tmp];
		} else {
			info$ServiceType = "Unknown";
		}
		Log::write(NBNS::LOG, info);
		c$nbns = info;
		# print fmt("%s %s %s %s %s %s %s", network_time(), c$id$orig_h, c$id$resp_h, c$orig$l2_addr, name_type, half_to_full(queries_name[1:-1]), additional_records_ttl);
	}
	}
