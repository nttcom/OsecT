##! This script adds link-layer address (MAC) information to the connection logs

@load base/protocols/http

module HTTP;

redef record Info += {
	## Link-layer address of the originator, if available.
	orig_l2_addr: string	&log &optional;
	## Link-layer address of the responder, if available.
	resp_l2_addr: string	&log &optional;
};

# Add the link-layer addresses to the Conn::Info structure after the connection
# has been removed. This ensures it's only done once, and is done before the
# connection information is written to the log.
#
event http_message_done(c: connection, is_orig: bool, stat: http_message_stat) &priority = 5
	{
	if ( c$orig?$l2_addr )
		c$http$orig_l2_addr = c$orig$l2_addr;
	if ( c$resp?$l2_addr )
		c$http$resp_l2_addr = c$resp$l2_addr;
	}
