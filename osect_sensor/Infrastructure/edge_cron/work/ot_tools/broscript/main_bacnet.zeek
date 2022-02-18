module BACnet;

export {
    redef enum Log::ID += {
        Log_BACnet
        };
    
    ## header info
    type BACnet: record {
        ts              : time &log;                ## Timestamp for when the event happened.
        uid             : string &log;              ## Unique ID for the connection.
        id              : conn_id &log;             ## The connection's 4-tuple of endpoint addresses/ports.

        bvlc_function   : string &optional &log;    ##
        bvlc_len        : count &optional &log;     ##
        apdu_type       : string &optional &log;
        pdu_flags       : count &optional;
        service_choice  : string &optional &log;
        data            : string_vec &optional &log;
        };
    ## Event that can be handled to access the record as it is sent
    global log_bacnet: event(rec: BACnet);
    }

redef record connection += {
    bacnet: BACnet &optional;
    };

## define listening ports
const ports = {
    47808/udp
    };
redef likely_server_ports += {
    ports
    };

##!======================================================
##! convert bytes not covered in bytestring_to_count
##!======================================================
function bytes_to_count(len: count, input: string): count {
    local number: count = 0;
    switch(len) {
        case 3:
            number = bytestring_to_count(input[0])*(0x010000) + bytestring_to_count(input[1:3]);
            break;
        case 5:
            number = bytestring_to_count(input[0])*(0x0100000000) + bytestring_to_count(input[1:5]);
            break;
        case 6:
            number = bytestring_to_count(input[0])*(0x010000000000) + bytestring_to_count(input[1])*(0x0100000000) + bytestring_to_count(input[2:6]);
            break;
        case 7:
            number = bytestring_to_count(input[0])*(0x01000000000000) + bytestring_to_count(input[1])*(0x010000000000) + bytestring_to_count(input[2])*(0x0100000000) + bytestring_to_count(input[3:7]);
            break;
        default:
            number = bytestring_to_count(input);
            break;
        }        
        
    return number;
    }

event zeek_init() &priority=5 {
    Log::create_stream(BACnet::Log_BACnet,
                        [$columns=BACnet,
                        $ev=log_bacnet,
                        $path="bacnet"]);
    Analyzer::register_for_ports(Analyzer::ANALYZER_BACNET, ports);
    }

event bacnet(c:connection, is_orig:bool,
            bvlc_function: count,
            bvlc_len: count,
            rest_of_data: string) {
    if(!c?$bacnet) {
        c$bacnet = [$ts=network_time(), $uid=c$uid, $id=c$id];
        }

    
    delete c$bacnet;
    }

event connection_state_remove(c: connection) &priority=-5 {
    if(c?$bacnet) {
        delete c$bacnet;
        }
    }
