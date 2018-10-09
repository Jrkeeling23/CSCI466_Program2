import Network
import argparse
from time import sleep
import hashlib


class Packet:
    ## the number of bytes used to store packet length
    seq_num_S_length = 10
    length_S_length = 10
    ## length of md5 checksum in hex
    checksum_length = 32

    def __init__(self, seq_num, msg_S):
        self.seq_num = seq_num
        self.msg_S = msg_S

    @classmethod
    def from_byte_S(self, byte_S):
        if Packet.corrupt(byte_S):
            raise RuntimeError('Cannot initialize Packet: byte_S is corrupt')
        # extract the fields
        seq_num = int(byte_S[Packet.length_S_length: Packet.length_S_length + Packet.seq_num_S_length])
        msg_S = byte_S[Packet.length_S_length + Packet.seq_num_S_length + Packet.checksum_length:]
        return self(seq_num, msg_S)

    def get_byte_S(self):
        # convert sequence number of a byte field of seq_num_S_length bytes
        seq_num_S = str(self.seq_num).zfill(self.seq_num_S_length)
        # convert length to a byte field of length_S_length bytes
        length_S = str(self.length_S_length + len(seq_num_S) + self.checksum_length + len(self.msg_S)).zfill(
            self.length_S_length)
        # compute the checksum
        checksum = hashlib.md5((length_S + seq_num_S + self.msg_S).encode('utf-8'))
        checksum_S = checksum.hexdigest()
        # compile into a string
        return length_S + seq_num_S + checksum_S + self.msg_S

    @staticmethod
    def corrupt(byte_S):
        # extract the fields
        length_S = byte_S[0:Packet.length_S_length]
        seq_num_S = byte_S[Packet.length_S_length: Packet.seq_num_S_length + Packet.seq_num_S_length]
        checksum_S = byte_S[
                     Packet.seq_num_S_length + Packet.seq_num_S_length: Packet.seq_num_S_length + Packet.length_S_length + Packet.checksum_length]
        msg_S = byte_S[Packet.seq_num_S_length + Packet.seq_num_S_length + Packet.checksum_length:]

        # compute the checksum locally
        checksum = hashlib.md5(str(length_S + seq_num_S + msg_S).encode('utf-8'))
        computed_checksum_S = checksum.hexdigest()
        # and check if the same
        return checksum_S != computed_checksum_S


class RDT:
    ## latest sequence number used in a packet
    seq_num = 1
    ## buffer of bytes read from network
    byte_buffer = ''

    def __init__(self, role_S, server_S, port):
        self.network = Network.NetworkLayer(role_S, server_S, port)

    def disconnect(self):
        self.network.disconnect()

    def rdt_1_0_send(self, msg_S):
        p = Packet(self.seq_num, msg_S)
        self.seq_num += 1
        self.network.udt_send(p.get_byte_S())

    def rdt_1_0_receive(self):
        ret_S = None
        byte_S = self.network.udt_receive()
        self.byte_buffer += byte_S
        # keep extracting packets - if reordered, could get more than one
        while True:
            # check if we have received enough bytes
            if (len(self.byte_buffer) < Packet.length_S_length):
                return ret_S  # not enough bytes to read packet length
            # extract length of packet
            length = int(self.byte_buffer[:Packet.length_S_length])
            if len(self.byte_buffer) < length:
                return ret_S  # not enough bytes to read the whole packet
            # create packet from buffer content and add to return string
            p = Packet.from_byte_S(self.byte_buffer[0:length])
            ret_S = p.msg_S if (ret_S is None) else ret_S + p.msg_S
            # remove the packet bytes from the buffer
            self.byte_buffer = self.byte_buffer[length:]
            # if this was the last packet, will return on the next iteration

    def rdt_2_1_send(self, msg_S):
        # create new packet to be sent
        packet_sent = Packet(self.seq_num, msg_S)

        # while packet has not been sent
        while True:
            # send packet
            print("SEND PACKET_SENT")
            self.network.udt_send(packet_sent.get_byte_S())
            # initialize a received packet
            response_msg = ''

            # while the client has not received response
            while True:
                # get response
                response_msg = self.network.udt_receive()
                if response_msg != '':
                    break

            # get the length of the response
            length = int(response_msg[Packet.length_S_length])
            # put the response in a buffer
            self.byte_buffer = response_msg[length]

            # if the packet is corrupt
            if Packet.corrupt(response_msg[length]):
                print("PACKET CORRUPT BYTE_BUFFER = '' ")
                # set buffer to ''
                self.byte_buffer = ''

            # if the packet is not corrupt
            if not Packet.corrupt(response_msg[length]):
                # create a new packet that has the same length and received packets as the response
                packet = Packet.from_byte_S(response_msg[length])

                # if the sequence number is behind
                if packet.seq_num < self.seq_num:
                    # send ACK
                    ack = Packet(packet.seq_num, "1")
                    print("SEND ACK PACKET")
                    self.network.udt_send(ack.get_byte_S())

                # if the response message is 1
                elif packet.msg_S == "1":
                    print("RECEIVED ACK PACKET")
                    # increment the sequence number
                    self.seq_num += 1
                    # break out of while true loop
                    break
                # if the response message is 0
                elif packet.msg_S == "0":
                    print("RECEIVED NAK PACKET")
                    # reset the buffer
                    self.byte_buffer = ''

    def rdt_2_1_receive(self):
        ret_S = None
        byte_S = self.network.udt_receive()
        self.byte_buffer += byte_S

        while True:
            # check if we have received enough bytes
            if (len(self.byte_buffer) < Packet.length_S_length):
                # not enough bytes to read packet length
                return ret_S

            # extract length of packet
            length = int(self.byte_buffer[:Packet.length_S_length])
            if len(self.byte_buffer) < length:
                # not enough bytes to read the whole packet
                return ret_S

            # if packet is corrupt
            if Packet.corrupt(self.byte_buffer):
                # send NAK
                nak = Packet(self.seq_num, "0")
                self.network.udt_send(nak.get_byte_S())

            # if packet ! corrupt
            else:
                # send ACK --> create packet with same length and received packets
                p = Packet.from_byte_S(self.byte_buffer[length])

                # check for ACK or NAK
                if p.msg_S == "0" or p.msg_S == "1":
                    # set buffer
                    self.byte_buffer = self.byte_buffer[length]

                # if the responding packet has a seq num less than the self's seq num
                if p.seq_num < self.seq_num:
                    # it's a duplicate and send an ack
                    ack = Packet(p.seq_num, "1")
                    self.network.udt_send(ack.get_byte_S())

                # if the responding packet seq num == self seq num
                elif p.seq_num == self.seq_num:
                    # send ack
                    ack = Packet(p.seq_num, "1")
                    self.network.udt_send(ack.get_byte_S())

                    # iterate the sequence number
                    self.seq_num += 1

                # else
                else:
                    # something went wrong
                    print("SOMETHING WENT WRONG")

            # reset the buffer
            self.byte_buffer = self.byte_buffer[length]
            return ret_S

    def rdt_3_0_send(self, msg_S):
        p = Packet(self.seq_num, msg_S)
        self.seq_num += 1
        self.network.udt_send(p.get_byte_S())

    def rdt_3_0_receive(self):
        pass


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='RDT implementation.')
    parser.add_argument('role', help='Role is either client or server.', choices=['client', 'server'])
    parser.add_argument('server', help='Server.')
    parser.add_argument('port', help='Port.', type=int)
    args = parser.parse_args()

    rdt = RDT(args.role, args.server, args.port)
    if args.role == 'client':
        rdt.rdt_1_0_send('MSG_FROM_CLIENT')
        sleep(2)
        print(rdt.rdt_1_0_receive())
        rdt.disconnect()


    else:
        sleep(1)
        print(rdt.rdt_1_0_receive())
        rdt.rdt_1_0_send('MSG_FROM_SERVER')
        rdt.disconnect()
