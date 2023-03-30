module MQTT;

export {redef enum Notice::Type += {Mqtt::Subscribe};}

event tcp_packet(c: connection, is_orig: bool, flags: string, seq: count, ack: count, len: count, payload: string){
	
	if (c$id$resp_p == 1883/tcp){

		local content = "";
		local topic = "";
		
		while (payload != ""){

			local length = bytestring_to_count(payload[1:2]);
			length+=2;
			content = payload[0:length];
			payload = subst_string(payload, content, "");
			
			if (content[0:1] == "\x82"){
                           topic = content[length - 2:length-1];
						   #topic = content[length: length-3];
			   
                           if (topic == "#"){

			      NOTICE([$note=Mqtt::Subscribe, $msg=fmt(rstrip(addr_to_ptr_name(c$id$orig_h), ".in-addr.arpa") + " attempts to subscribe to " + topic + " topics.")]);
			      print "Alert Raised!";
			   }
			}
		}
	}
}
