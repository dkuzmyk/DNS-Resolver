"""
resolve.py: a recursive resolver built using dnspython
"""

import argparse

import dns.message
import dns.name
import dns.query
import dns.rdata
import dns.rdataclass
import dns.rdatatype

FORMATS = (("CNAME", "{alias} is an alias for {name}"),
           ("A", "{name} has address {address}"),
           ("AAAA", "{name} has IPv6 address {address}"),
           ("MX", "{name} mail is handled by {preference} {exchange}"))

# current as of 25 October 2018
ROOT_SERVERS = ("198.41.0.4",
                "199.9.14.201",
                "192.33.4.12",
                "199.7.91.13",
                "192.203.230.10",
                "192.5.5.241",
                "192.112.36.4",
                "198.97.190.53",
                "192.36.148.17",
                "192.58.128.30",
                "193.0.14.129",
                "199.7.83.42",
                "202.12.27.33")

cache = dict()

def collect_results(name: str) -> dict:
    """
    This function parses final answers into the proper data structure that
    print_results requires. The main work is done within the `lookup` function.
    """
    if name in cache:       # check cache for the current query, if yes return the data
        print('======== Cache found', name, '========')
        return cache[name]

    print('======== Searching', name, '========')
    full_response = {}
    target_name = dns.name.from_text(name)
    # lookup CNAME
    # print('CNAME-->', dns.rdatatype.CNAME)
    response = lookup(target_name, dns.rdatatype.CNAME)
    cnames = []
    # print('Received response:', response)
    try:
        for answers in response.answer:
            for answer in answers:
                cnames.append({"name": answer, "alias": name})
    except:
        print('No CNAME for', name)
    # lookup A
    # print('A-->', dns.rdatatype.A)
    response = lookup(target_name, dns.rdatatype.A)
    # print('Received response:', response)
    arecords = []
    try:
        for answers in response.answer:
            a_name = answers.name
            for answer in answers:
                if answer.rdtype == 1:  # A record
                    arecords.append({"name": a_name, "address": str(answer)})
    except:
        print('No A for', name)
    # lookup AAAA
    # print('AAAA-->', dns.rdatatype.AAAA)
    response = lookup(target_name, dns.rdatatype.AAAA)
    # print('Received response:', response)
    aaaarecords = []
    try:
        for answers in response.answer:
            aaaa_name = answers.name
            for answer in answers:
                if answer.rdtype == 28:  # AAAA record
                    aaaarecords.append({"name": aaaa_name, "address": str(answer)})
    except:
        print('No AAAA for', name)
    # lookup MX
    # print('MX-->', dns.rdatatype.MX)
    try:
        response = lookup(target_name, dns.rdatatype.MX)
        # print('Received response:', response)
        mxrecords = []
        for answers in response.answer:
            mx_name = answers.name
            for answer in answers:
                if answer.rdtype == 15:  # MX record
                    mxrecords.append({"name": mx_name,
                                      "preference": answer.preference,
                                      "exchange": str(answer.exchange)})
    except:
        print('No MX for', name)

    full_response["CNAME"] = cnames
    full_response["A"] = arecords
    full_response["AAAA"] = aaaarecords
    full_response["MX"] = mxrecords
    print('Full response', full_response)
    cache[name] = full_response             # save cache, use in case of same query
    return full_response


def lookup(target_name: dns.name.Name,
           qtype: dns.rdata.Rdata, server=ROOT_SERVERS[0]) -> dns.message.Message:
    """
    This function uses a recursive resolver to find the relevant answer to the
    query.

    TODO: replace this implementation with one which asks the root servers
    and recurses to find the proper answer.
    """

    servers = list()                    # store all servers from root_servers
    servers = servers+list(ROOT_SERVERS)
    visited = list()

    while True:
        # print('..................')     # debug to divide each query
        # print(servers)
        if servers:                     # if servers list is empty -> query a root
            s = servers[0]
            if s not in visited:
                try:                        # try catch for error handling
                    # print('Looking up:', s)# debug
                    outbound_query = dns.message.make_query(target_name, qtype)
                    response = dns.query.udp(outbound_query, server, timeout=3)  # timeout 3s
                    visited.append(s)
                except:
                    # print('Could not query', s)    # debug
                    servers.remove(s)
                    continue
            else:
                if servers:
                    del servers[0]
                    continue
                else:
                    print('Exhausted all options. ')
                    break
        else:
            print('Exhausted all options. ')
            break

        del servers[0]                  # pop current server from servers
        # visited.append(server)

        # print('Response:', response)    # debug
        # find all servers from response
        # print('Answer found:', response.answer) # debug

        row = 'NONE'

        if not response.answer:     # if there's no answer to our query, we take the additional servers
            # get the additional info that has the ip of the next server to check
            # create a recursive path for each of them
            for e in response.additional:
                if ' A ' in e.to_text():
                    row = e.to_text()

                if row == 'NONE':
                    # print('No element found on this path.')
                    continue

                # print('Look here ->', row)
                server = row[row.find(' A ') + 3:]

                # print('Found server:', server)
                # save the next servers to look up
                # insert to top so that it's the priority servers
                servers.insert(0, server)

        # if answer is present but has redirect, consider redirect for CNAME
        elif 'IN CNAME' in response.answer[0].to_text() and qtype is not dns.rdatatype.CNAME:
            # get new link
            redirect_target = response.answer[0].to_text()
            redirect_target = redirect_target[redirect_target.find('CNAME ') + 6:len(redirect_target) - 1]
            # print('Looking up link ->', redirect_target)
            return lookup(redirect_target, qtype)

        # answer has been found
        else:
            # print('sending response:', response)
            return response


def print_results(results: dict) -> None:
    """
    take the results of a `lookup` and print them to the screen like the host
    program would.
    """

    for rtype, fmt_str in FORMATS:
        for result in results.get(rtype, []):
            print(fmt_str.format(**result))


def main():
    """
    if run from the command line, take args and call
    printresults(lookup(hostname))
    """
    argument_parser = argparse.ArgumentParser()
    argument_parser.add_argument("name", nargs="+",
                                 help="DNS name(s) to look up")
    argument_parser.add_argument("-v", "--verbose",
                                 help="increase output verbosity",
                                 action="store_true")
    program_args = argument_parser.parse_args()
    for a_domain_name in program_args.name:
        print_results(collect_results(a_domain_name))


if __name__ == "__main__":
    main()
