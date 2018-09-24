from dns.resolver import dns
import dns.query, dns.message
from config import config
import sys


class Resolver:

    type_map = {
        "A": dns.rdatatype.A,
        "MX": dns.rdatatype.MX,
        "NS": dns.rdatatype.NS,
        "SOA": dns.rdatatype.SOA
    }

    def __init__(self, url, rec_type="A"):
        self.root_servers = config.root_servers
        self.url = dns.name.from_text(url)
        self.type = Resolver.type_map[rec_type]

    def resolve_iteration(self, resolver_list) -> dns.message.Message:
        m = dns.message.make_query(self.url, self.type)
        # Loop through all "resolvers" until one responds with an answer
        for resolver in resolver_list:
            response = dns.query.udp(m, resolver, config.TIMEOUT)
            #print(response)
            return response
        print("returning false")
        return False

    @staticmethod
    def get_ip(section):
        ips = []
        for rrset in section:
            for rr in rrset:
                if rr.rdtype == dns.rdatatype.A:
                    ips.append(rr.address)
        return ips

    def get_resolvers(self, response: [dns.message.Message]):
        resolvers = []
        if not response.answer and not response.additional:
            # This means we have no "ip" for further resolution.
            # We will have to resolve the ip Authority section to proceed
            for rrset in response.authority:
                for rr in rrset:
                    if rr.rdtype == dns.rdatatype.NS:
                        # We want the A record for this. So we use good ol' recurssion
                        res = Resolver(str(rr))
                        resolvers = Resolver.get_ip(res.resolve().answer)
        else:
            resolvers = Resolver.get_ip(response.additional)
        return resolvers

    def resolve(self):
        response = self.resolve_iteration(self.root_servers)  # type:dns.message.Message
        while (response.flags & dns.flags.AA) != dns.flags.AA:
            resolvers = self.get_resolvers(response)
            response = self.resolve_iteration(resolvers)
        # for rrset in response.answer:
        #     print(rrset)
        return response


class Printer:
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

    @staticmethod
    def print(result, url, type="A"):
        Printer.print_question(url, type)
        Printer.print_result(result)


if __name__ == '__main__':
    if len(sys.argv) < 2:
        Printer.print_help()
        exit()
    url = sys.argv[1]
    rec_type = sys.argv[2] if len(sys.argv) > 2 else "A"
    r = Resolver(url, rec_type)
    result = r.resolve()
    Printer.print(result, url, rec_type)

