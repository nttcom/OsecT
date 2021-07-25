@load base/frameworks/notice

module NS;

export {
	redef enum Log::ID += { LOG };

	type Info: record {
		ts:		time		&log;
		orig_mac:	string		&log &optional;
		resp_mac:	string		&log &optional;
		orig_ip:	addr		&log &optional;
		resp_ip:	addr		&log &optional;
		who_has:	addr		&log &optional;
	};

	global log_neighbor: event(rec: Info);
}

event zeek_init() &priority=5
	{
	Log::create_stream(NS::LOG, [$columns=Info, $ev=log_neighbor]);
	}

function log_request(rec: Info)
        {
        Log::write(NS::LOG, rec);
        }

event icmp_neighbor_solicitation(c: connection, info: icmp_info, tgt: addr, options: icmp6_nd_options)
	{
	local request: Info;

	if ( c$id$orig_p == 135/icmp )
		{
			request$ts = network_time();
			request$orig_mac = c$orig$l2_addr;
			request$orig_ip = c$id$orig_h;
			request$resp_ip = tgt;
			request$who_has = tgt;
			log_request(request);
		}
	else if ( c$id$resp_p == 135/icmp )
		{
			request$ts = network_time();
			request$orig_mac = c$resp$l2_addr;
			request$orig_ip = c$id$resp_h; 
			request$resp_ip = tgt;
			request$who_has = tgt;
			log_request(request);
		}
	}

event icmp_neighbor_advertisement(c: connection, info: icmp_info, router: bool, solicited: bool, override: bool, tgt: addr, options: icmp6_nd_options)
	{
	local request: Info;

	if ( c$id$orig_p == 136/icmp )
		{
			request$ts = network_time();
			request$orig_mac = c$resp$l2_addr;
			request$resp_mac = c$orig$l2_addr;
			request$orig_ip = c$id$resp_h;
			request$resp_ip = tgt;
			log_request(request);
        	}
	else if ( c$id$resp_p == 136/icmp )
		{
			request$ts = network_time();
			request$orig_mac = c$orig$l2_addr;
			request$resp_mac = c$resp$l2_addr;
			request$orig_ip = c$id$orig_h;
			request$resp_ip = tgt;
			log_request(request);
		}
	}
