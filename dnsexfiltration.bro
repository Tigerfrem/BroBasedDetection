
export{redef enum Notice::Type += { DNS::Exfiltration };}

event dns_request(c: connection, msg: dns_msg, query: string, qtype: count, qclass: count){
    print query;
    if(|query| > 52){
        print |query|;
    }
    if (|query| > 52) {
        local notice_msg = fmt("Long Domain. Possible DNS exfiltration/tunnel by %s. Offending domain name: %s", c$id$orig_h, query);

        NOTICE([$note=DNS::Exfiltration, $msg=notice_msg]);
    }
}

