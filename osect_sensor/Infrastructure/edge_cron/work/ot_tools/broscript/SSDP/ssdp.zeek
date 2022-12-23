module SSDP;

export {
	redef enum Log::ID += { LOG };

	type Info: record {
		ts:		time &log;
		SrcIP:	addr &log;
		SrcMAC: string &log;
		Method: string &log &optional;
		SERVER_or_USER_AGENT: string &log &optional;

		# Set to block number of final piece of data once received.
		final_block: count &optional;

		# Set to true once logged.
		done: bool &default=F;
	};

	## Event that can be handled to access the ssdp logging record.
	global log_ssdp: event(rec: Info);
}

# Maps a partial data connection ID to the request's Info record.
global expected_data_conns: table[addr, port, addr] of Info;

redef record connection += {
	ssdp: Info &optional;
};

event zeek_init() &priority=5
	{
	Log::create_stream(SSDP::LOG, [$columns = Info, $ev = log_ssdp, $path="ssdp"]);
	}

type Line: record {
	v: vector of string;
};

function split_s(s: string): vector of string
{	
	local res1 = "";
	local res2 = "";
	local flag = F;
	for (i in s) {
		if (flag == T) {
			res1 = res1 + i;
		} else {
			res2 = res2 + i;
		}
		if (i == " ") {
			flag = T;
		}
    }
	local res3: vector of string = { res2, res1 };
	return res3;
}

event SSDP::message(c: connection, method: string, line: Line)
	{
	# print fmt("%s %s %s %s %s %s %s", network_time(), c$id$orig_h, c$id$resp_h, c$orig$l2_addr, name_type, additional_records_ttl, queries_name);

	local info: Info;
	local res: vector of string;
	info$ts = network_time();
	info$SrcIP = c$id$orig_h;
	info$SrcMAC = c$orig$l2_addr;
	if (method == "NOTIFY * HTTP/1.1") {
		info$Method = "NOTIFY";
		for (i in line$v) {
			res = split_s(line$v[i]);
			if (to_upper(res[0]) == "SERVER: ") {
				info$SERVER_or_USER_AGENT = res[1];
			}
		}
	} else if (method == "M-SEARCH * HTTP/1.1") {
		info$Method = "M-SEARCH Request";
		for (i in line$v) {
			res = split_s(line$v[i]);
			if (to_upper(res[0]) == "USER-AGENT: ") {
				info$SERVER_or_USER_AGENT = res[1];
			}
		}
	} else if (method == "HTTP/1.1 200 OK") {
		info$Method = "M-SEARCH Response";
		for (i in line$v) {
			res = split_s(line$v[i]);
			if (to_upper(res[0]) == "SERVER: ") {
				info$SERVER_or_USER_AGENT = res[1];
			}
		}
	} 
	# info$SERVER_or_USER_AGENT = line.v;
	Log::write(SSDP::LOG, info);
	c$ssdp = info;
	# print fmt("%s %s %s %s %s %s %s", network_time(), c$id$orig_h, c$id$resp_h, c$orig$l2_addr, name_type, half_to_full(queries_name[1:-1]), additional_records_ttl);
	}
