module CIFS;

export {
	redef enum Log::ID += { LOG };

	type Info: record {
		ts:		time &log;
		SrcIP:	addr &log;
		SrcMAC: string &log;
		ServerName: string &log;
		OSVersion: string &log;
		ServerType: string &log;
		BrowserVersion: string &log;
		Signature: string &log;
		HostComment: string &log;


		# Set to block number of final piece of data once received.
		final_block: count &optional;

		# Set to true once logged.
		done: bool &default=F;
	};

	## Event that can be handled to access the cifs logging record.
	global log_cifs: event(rec: Info);

	global res_endCode: table[string] of string = { ["\x00\x00"] = "nomal", 
	                                    ["\xCF\x80"] = "stop",
										};
}

# Maps a partial data connection ID to the request's Info record.
global expected_data_conns: table[addr, port, addr] of Info;

redef record connection += {
	cifs: Info &optional;
};

event zeek_init() &priority=5
	{
	Log::create_stream(CIFS::LOG, [$columns = Info, $ev = log_cifs, $path="cifs"]);
	}

function log_pending(c: connection)
	{
	if ( ! c?$cifs || c$cifs$done )
		return;

	Log::write(CIFS::LOG, c$cifs);
	c$cifs$done = T;
	}

function find_string(s: string): string
	{
	local x = "\x00";
	local res = "";

	for ( c in s )
		{
		if ( c == x )
			{
			break;
			}
		else
			{
			res = res + c;
			}
		}
	if ( res == "" )
		{
		return "";
		}

	return res;
	}

function uint16_to_hex(num: int): string
	{
	local hex_list: table[count] of string = { [0] = "0", [1] = "1", [2] = "2", [3] = "3", [4] = "4", [5] = "5", [6] = "6", 
    [7] = "7", [8] = "8", [9] = "9", [10] = "a", [11] = "b", [12] = "c", 
    [13] = "d", [14] = "e", [15] = "f", };

	local left = 0;
	local right = 0;
	
    right = num % 16;
    left = num / 16;
    
    local res = hex_list[left] +  hex_list[right];
    return cat(res);
	}

function del_0(s: string): string
	{
	local i = 0;
	for ( c in s )
		{
		if ( c == "0" )
			{
			i = 1 + i;
			next;
			}
		else
			{
			break;
			}
		}
	return s[i:];
	}

event CIFS::hostAnnouncement(
	c: connection, serverName: string, osversion_1: int, osversion_2: int,
	serverType_1: int, serverType_2: int, serverType_3: int, serverType_4: int,
	browserVersion_1: int, browserVersion_2: int, signature_1: string, signature_2: string, 
	hostComment: string
	)
	{
	# log_pending(c);

	local info: Info;
	Log::write(CIFS::LOG, [$ts  = network_time(),
							$SrcIP  = c$id$orig_h,
							$SrcMAC =  c$orig$l2_addr,
							$ServerName = find_string(serverName),
							$OSVersion = cat(osversion_1) + "." + cat(osversion_2),
							$ServerType = "0x" + del_0(uint16_to_hex(serverType_4) + uint16_to_hex(serverType_3) + uint16_to_hex(serverType_2) + uint16_to_hex(serverType_1)),
							$BrowserVersion = cat(browserVersion_1) + "." + cat(browserVersion_2),
							$Signature = "0x" + string_to_ascii_hex(signature_2) + string_to_ascii_hex(signature_1),
							$HostComment = find_string(hostComment)]);
	c$cifs = info;
	# print fmt("Zeek saw from %s %s to %s: %s host", c$start_time, c$id$orig_h, c$id$resp_h, c$orig$l2_addr);
	}

event CIFS::localMatserAnnouncement(
	c: connection, serverName: string, osversion_1: int, osversion_2: int,
	serverType_1: int, serverType_2: int, serverType_3: int, serverType_4: int,
	browserVersion_1: int, browserVersion_2: int, signature_1: string, signature_2: string, 
	hostComment: string
									)
	{
	# log_pending(c);

	local info: Info;
	Log::write(CIFS::LOG, [$ts  = network_time(),
							$SrcIP  = c$id$orig_h,
							$SrcMAC =  c$orig$l2_addr,
							$ServerName = find_string(serverName),
							$OSVersion = cat(osversion_1) + "." + cat(osversion_2),
							$ServerType = "0x" + del_0(uint16_to_hex(serverType_4) + uint16_to_hex(serverType_3) + uint16_to_hex(serverType_2) + uint16_to_hex(serverType_1)),
							$BrowserVersion = cat(browserVersion_1) + "." + cat(browserVersion_2),
							$Signature = "0x" + string_to_ascii_hex(signature_2) + string_to_ascii_hex(signature_1),
							$HostComment = find_string(hostComment)]);
	c$cifs = info;
	# print fmt("Zeek saw from %s %s to %s: %s %s local", c$start_time, c$id$orig_h, c$id$resp_h, c$orig$l2_addr, network_time());
	}
