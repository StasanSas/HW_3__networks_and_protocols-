import asyncio
import time
from argparse import ArgumentParser, Namespace
from protocol_on_port import *
from scapy.all import sr1
from scapy.layers.inet import TCP, IP

class MainArguments:
    def __init__(self, ip, timeout, num_threads, is_verbose, is_guess):
        self.ip = ip
        self.options = dict()
        self.options['timeout'] = timeout
        self.options['num_threads'] = num_threads
        self.options['is_verbose'] = is_verbose
        self.options['is_guess'] = is_guess

class PortScaner:
    def init(self):
        self.main_arg = None
        self.protocol_and_ports = None

    def parse_console_query(self):
        parser = ArgumentParser()

        parser.add_argument('-t', '--timeout', type=float, default=2)
        parser.add_argument('-j', '--num-threads', type=int, default=64)
        parser.add_argument('-v', '--verbose', action='store_true')
        parser.add_argument('-g', '--guess', action='store_true')
        parser.add_argument("ip", nargs=1)
        parser.add_argument("ports_and_protocol_args", nargs="+")

        all_args: Namespace = parser.parse_args()
        self.main_arg = MainArguments(all_args.ip[0], all_args.timeout,
                                            all_args.num_threads, all_args.verbose,
                                            all_args.guess)
        self.protocol_and_ports = self.parse_ports_and_protocols(all_args.ports_and_protocol_args)

    def parse_ports_and_protocols(self, list_not_parse_args):
        list_parsed_args = []
        for arg in list_not_parse_args:
            protocol = arg[0:3]
            not_parsed_ports = arg[4:]
            parsed_ports_with_protocol = []
            while True:
                end_next_port = not_parsed_ports.find(",")
                if end_next_port == -1:
                    parsed_ports_with_protocol += self.parse_ports_with_protocol(not_parsed_ports, protocol)
                    break
                ports = not_parsed_ports[:end_next_port]
                parsed_ports_with_protocol += self.parse_ports_with_protocol(ports, protocol)
                not_parsed_ports = not_parsed_ports[end_next_port + 1:]
            list_parsed_args += parsed_ports_with_protocol
        return list_parsed_args

    def parse_ports_with_protocol(self, ports, protocol):
        range_ports = ports.split("-")
        if len(range_ports) == 2:
            result = []
            for i in range(int(range_ports[0]), int(range_ports[1]) + 1):
                result.append((protocol, i))
            return result
        else:
            return [(protocol, int(range_ports[0]))]

    async def run(self):
        self.parse_console_query()
        await self.process_analiz()

    async def process_analiz(self):
        treads = self.main_arg.options['num_threads']
        while len(self.protocol_and_ports) != 0:
            tasks = []
            for i in range(0, min(treads, len(self.protocol_and_ports))):
                protocol_and_port = self.protocol_and_ports.pop(0)
                task = asyncio.create_task(self.process_port(self.main_arg, protocol_and_port))
                tasks.append(task)
            await asyncio.gather(*tasks)

    async def process_port(self, main_argument, port_and_protocol):
        if port_and_protocol[0] == 'tcp':
            await self.process_tcp(main_argument, int(port_and_protocol[1]))
        elif port_and_protocol[0] == 'udp':
            await self.process_udp(main_argument, port_and_protocol[1])

    async def process_tcp(self, main_argument, port):

        have_timeout = False
        timeout = main_argument.options['timeout']
        tcp_packet = IP(dst=main_argument.ip) / TCP(dport=port, flags="S")
        start = time.time()

        response = await loop.run_in_executor(None, lambda: sr1(tcp_packet, timeout=timeout, verbose=False))

        time_ms = ((time.time() - start) * 1000) // 1
        # флаги здесь говорят,что был прнят ответ типа SYN + ACK там где 0x12
        if not (response and response.haslayer(TCP) and response.getlayer(TCP).flags == 0x12):
            return

        protocol_on_port = ""
        if main_argument.options['is_guess']:
            protocol_on_port = self.parse_protocol(port, main_argument.ip, socket.SOCK_STREAM)

        if main_argument.options['is_verbose']:
            print(f"TCP {port} {time_ms} ms {protocol_on_port}")
        else:
            print(f"TCP {port} {protocol_on_port}")


    async def process_udp(self, main_argument, port):
        have_timeout = False
        timeout = main_argument.options['timeout']
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        query = b'\xAA\xAA\x01\x00\x00\x01\x00\x00' + b'\x00\x00\x00\x00' + b'\x07' + b'example' \
                + b'\x03' + b'com' + b'\x00' + b'\x00\x01' + b'\x00\x01'
        sock.sendto(query, (main_argument.ip, port) )
        try:
            data, _ = sock.recvfrom(1024)
        except socket.timeout:
            have_timeout = True
        finally:
            sock.close()
        if have_timeout:
            return
        protocol_on_port = ""
        if main_argument.options['is_guess']:
            protocol_on_port = self.parse_protocol(port, main_argument.ip, socket.SOCK_DGRAM)
        print(f"UDP {port} {protocol_on_port}")

    def parse_protocol(self, port, ip, tcp_or_udp):
        if http(port, ip, tcp_or_udp):
            return "HTTP"
        elif dns(port, ip, tcp_or_udp):
            return "DNS"
        elif echo(port, ip, tcp_or_udp):
            return "ECHO"
        else:
            return "-"



port_ckaner = PortScaner()
loop = asyncio.get_event_loop()
forecast = loop.run_until_complete(port_ckaner.run())
loop.close()


