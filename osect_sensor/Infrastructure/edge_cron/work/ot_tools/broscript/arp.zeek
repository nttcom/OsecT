@load base/frameworks/notice

module ARP;

export {
	redef enum Log::ID += { LOG };

	type Info: record {
		ts:		time		&log;
		orig_mac:	string		&log &optional;
		orig_ip:	addr		&log &optional;
		resp_mac:	string		&log &optional;
		resp_ip:	addr		&log &optional;
		unsolicited:	bool		&log &default=F;
		no_resp:	bool		&log &default=F;
		who_has:	addr		&log &optional;
		is_at:		string		&log &optional;
	};

	global log_arp: event(rec: Info);
}

const broadcast_mac_addrs = { "00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff", };
const broadcast_addrs = { 0.0.0.0, 255.255.255.255, };

event zeek_init() &priority=5
        {
        Log::create_stream(ARP::LOG, [$columns=Info, $ev=log_arp]);
        }

function log_request(rec: Info)
	{
	Log::write(ARP::LOG, rec);
	}

event arp_request(mac_src: string, mac_dst: string, SPA: addr, SHA: string, TPA: addr, THA: string)
	{
        local request: Info;
	request$ts = network_time();
        request$orig_mac = mac_src;
	request$orig_ip = SPA;
	request$resp_ip = TPA;
	request$who_has = TPA;
	log_request(request);
	}

event arp_reply(mac_src: string, mac_dst: string, SPA: addr, SHA: string, TPA: addr, THA: string)
	{
	local request: Info;
	request$ts = network_time();
	request$orig_mac = mac_dst;
	request$resp_mac = mac_src;
	request$orig_ip = TPA;
	request$resp_ip = SPA;
	log_request(request);
	}

