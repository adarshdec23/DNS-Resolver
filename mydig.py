from dns.resolver import dns
import dns.query, dns.message
from config import config
import sys
import time


class Resolver:

    type_map = {
        "A": dns.rdatatype.A,
        "MX": dns.rdatatype.MX,
        "NS": dns.rdatatype.NS,
        "SOA": dns.rdatatype.SOA,
        "DNSKEY": dns.rdatatype.DNSKEY
    }

    def __init__(self, url, rec_type="A"):
        self.root_servers = config.root_servers
        self.url = dns.name.from_text(url)
        self.type = Resolver.type_map[rec_type]

    def resolve_iteration(self, resolver_list):
        """
        Make one DNS query
        :param resolver_list: List of IPs
        :return: dns.message.Message
        """
        m = dns.message.make_query(self.url, self.type)
        # Loop through all "resolvers" until one responds with an answer
        for resolver in resolver_list:
            response = dns.query.udp(m, resolver, config.TIMEOUT)
            return response
        return False

    @staticmethod
    def get_ip(section):
        """
        Return the IP addresses for the "A" record
        :param section: list of RRSet
        :return: list of IP
        """
        ips = []
        for rrset in section:
            for rr in rrset:
                if rr.rdtype == dns.rdatatype.A:
                    ips.append(rr.address)
        return ips

    def get_resolvers(self, response):
        """
        This is need when we have a non authority response with no IP address.
        Example google.co.jp. The function uses recursion to get the IP for the NS
        :param response: dns.message.Message
        :return: [] List of IP of resolvers
        """
        resolvers = []
        if not response.answer and not response.additional:
            # This means we have no "ip" for further resolution.
            # We will have to resolve the ip Authority section to proceed
            for rrset in response.authority:
                for rr in rrset:
                    if rr.rdtype == dns.rdatatype.NS:
                        # We want the A record for this. So we use good ol' recursion
                        res = Resolver(str(rr))
                        resolvers = Resolver.get_ip(res.resolve().answer)
        else:
            resolvers = Resolver.get_ip(response.additional)
        return resolvers

    def additional_res_for_mx(self, result):
        """
        For MX records, the answer section has a URL and not an IP.
        We need another set of resolutions for getting the A record of the MX url
        :param result: The result of the DNS resolution
        :return: None
        """
        if not result.additional:
            result.additional = []
        for rrset in result.answer:
            for rr in rrset:
                # Get the A record
                if rr.rdtype == dns.rdatatype.MX or rr.rdtype == dns.rdatatype.NS:
                    try:
                        # We split to get the URL. It is the last part of the RR
                        res = Resolver(str(rr).split(" ")[-1], "A")
                        result.additional.append(res.resolve().answer[0])
                    except dns.exception.Timeout:
                        # If there's a time out, do nothing and proceed
                        pass

    def resolve(self):
        response = self.resolve_iteration(self.root_servers)  # type:dns.message.Message
        # Iterate till we have an authoritative answer: flag AA is set
        while (response.flags & dns.flags.AA) != dns.flags.AA:
            resolvers = self.get_resolvers(response)
            response = self.resolve_iteration(resolvers)
        self.additional_res_for_mx(response)
        return response


class Printer:
    """
    A class to do nothing but print the results that we get
    """
    @staticmethod
    def print_help():
        print("""mydig can be run using the following parameters:
mydig <url> <record_type>
    url: The url to resolve
    record_type: The type of record to resolve. Currently "A", "MX" and "NS" are supported""")

    @staticmethod
    def print_question(url, type):
        print("QUESTION SECTION:")
        print("{0}\t\tIN\t{1}".format(url, type))

    @staticmethod
    def print_result(qresult):
        print("ANSWER SECTION:")
        for rrset in qresult.answer:
            print(rrset)
        if not qresult.answer:
            for rrset in qresult.authority:
                print(rrset)
        if qresult.additional:
            print("ADDITIONAL SECTION")
            for rrset in qresult.additional:
                print(rrset)

    @staticmethod
    def print_misc(qresult, total_time):
        print()
        print("MSG SIZE: ", sys.getsizeof(qresult.to_wire())-10)
        print("Time taken:", total_time, "s")

    @staticmethod
    def print(result, url, total_time, type="A",):
        Printer.print_question(url, type)
        Printer.print_result(result)
        Printer.print_misc(result, total_time)


if __name__ == '__main__':
    if len(sys.argv) < 2:
        Printer.print_help()
        exit()
    url = sys.argv[1]
    rec_type = sys.argv[2] if len(sys.argv) > 2 else "A"  # Assume A record to be the default
    r = Resolver(url, rec_type)
    stime = time.time()
    try:
        result = r.resolve()
    except:
        print("Exception occurred: Timeout")
        exit(0)
    total_time = time.time() - stime
    Printer.print(result, url, total_time, rec_type)

