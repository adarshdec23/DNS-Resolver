from dns.resolver import dns
import dns.query, dns.message
from config import config
import sys


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
        self.url_index = -1
        self.url_list = str(self.url).split(".")
        self.ds_stack = []
        self.ds_start = True  # flag to check "special" root validation

    def get_next_url_part(self):
        to_ret = self.url_list[self.url_index:]
        self.url_index -= 1
        return '.'.join(to_ret)

    @staticmethod
    def get_url_part_for_dnssec(response):
        for rrset in response.authority:
            return rrset.to_text().split(" ")[0]

    @staticmethod
    def get_rrset(section, rdatatype):
        """
        Get the rrset with the rdatatype
        :param section: List of rrset
        :param rdatatype: dns.radatatype
        :return: list of rrest
        """
        for rrset in section:
            for rr in rrset:
                if rr.rdtype == rdatatype:
                    return rrset
        return False

    def make_ds(self, answer, sec_part_of_url):
        """
        Method to create a digital signature.
        :param answer: RRset with answer section
        :param sec_part_of_url: The url to verify
        :return: list of DS
        """
        keyrrset = answer[0]
        ds = []
        for rr in keyrrset:
            ds.append(dns.dnssec.make_ds(sec_part_of_url, rr, 'SHA256'))
        return ds

    def validate(self, response, key_response, sec_part_of_url):
        """
        Check whether the response received is secure.
        :param response: The "regular" response
        :param key_response: The response to the "DNSKEY" query
        :param sec_part_of_url: Url to verify
        :return: True if valid, False other wise
        """
        if self.ds_start:
            self.ds_start = False
            self.ds_stack.insert(0, response.authority[1][0])
            return True
        # Not root, we have something to validate against
        if self.ds_stack:
            parent_ds = self.ds_stack.pop(0)
            ds_list = self.make_ds(key_response.answer, sec_part_of_url)
            for ds in ds_list:
                if ds == parent_ds:
                    return True
        # We are at the end. Check A record
        else:
            try:
                dns.dnssec.validate(response.answer[0], response.answer[1], {dns.name.from_text(sec_part_of_url): key_response.answer[0]})
                return True
            except (dns.dnssec.ValidationFailure, Exception) as e:
                # print(e)
                pass
        return False

    def is_nsec(self, response):
        """
        Check whether DNSSEC is supported
        :param response: response to check
        :return: bool
        """
        for rrset in response.authority:
            for rr in rrset:
                # If we have NSEC or NSEC3 records, check whether it contains RRSIG/DNSKEY.
                # If it does, that means the child does not support DNSSEC
                if rr.rdtype == dns.rdatatype.NSEC or rr.rdtype == dns.rdatatype.NSEC3:
                    if rr.to_text().find("DNSKEY") > -1 or rr.to_text().find("RRSIG") > -1:
                        return True
        return False

    def resolve_iteration(self, url_to_resolve, resolver_list) -> dns.message.Message:
        m = dns.message.make_query(self.url, self.type, want_dnssec=True)
        # Loop through all "resolvers" until one responds with an answer
        for resolver in resolver_list:
            response = dns.query.udp(m, resolver, config.TIMEOUT)
            if (response.flags & dns.flags.AA) != dns.flags.AA and self.is_nsec(response):
                print("DNSSEC not supported")
                exit(0)
            # Make a request for the DNS key
            url_to_resolve = '.'+url_to_resolve
            sec_url_part = url_to_resolve[url_to_resolve.find(".")+1:]
            key_message = dns.message.make_query(dns.name.from_text(sec_url_part), dns.rdatatype.DNSKEY, want_dnssec=True)
            key_response = dns.query.udp(key_message, resolver, config.TIMEOUT)
            if not self.validate(response, key_response, sec_url_part):
                print("DNSSec verification failed")
                exit(0)
            return response
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
                        # We want the A record for this. So we use good ol' recursion
                        res = Resolver(str(rr))
                        resolvers = Resolver.get_ip(res.resolve().answer)
        else:
            resolvers = Resolver.get_ip(response.additional)
        return resolvers

    def resolve(self):
        current_url = self.get_next_url_part()
        response = self.resolve_iteration(current_url, self.root_servers)  # type:dns.message.Message
        while (response.flags & dns.flags.AA) != dns.flags.AA:
            resolvers = self.get_resolvers(response)
            current_url = self.get_next_url_part()
            response = self.resolve_iteration(current_url, resolvers)
        return response


class Printer:
    @staticmethod
    def print_help():
        print("""q2.py can be run using the following parameters:
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

