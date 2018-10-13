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
        # print("----------------------in from_byte_s\n")
        if Packet.corrupt(byte_S):
            raise RuntimeError('Cannot initialize Packet: byte_S is corrupt')
        # extract the fields
        seq_num = int(byte_S[Packet.length_S_length: Packet.length_S_length + Packet.seq_num_S_length])
        #print("seq_num : ", seq_num)
        msg_S = byte_S[Packet.length_S_length + Packet.seq_num_S_length + Packet.checksum_length:]
        # print("msg_s : ", msg_S)
        return self(seq_num, msg_S)

    def get_byte_S(self):
        # print("\n----------------------in get_byte_s\n")
        # convert sequence number of a byte field of seq_num_S_length bytes
        seq_num_S = str(self.seq_num).zfill(self.seq_num_S_length)
        #print("Seq_num_s = " + seq_num_S)
        # convert length to a byte field of length_S_length bytes
        length_S = str(self.length_S_length + len(seq_num_S) + self.checksum_length + len(self.msg_S)).zfill(
            self.length_S_length)

        # print("str len(seq_num_S) = " + str(len(seq_num_S)))
        # print("str checksum_length = " + str(self.checksum_length))
        # print("str msg_s = " + str(len(self.msg_S)))
        # print("length_s = " + length_S)

        # compute the checksum
        checksum = hashlib.md5((length_S + seq_num_S + self.msg_S).encode('utf-8'))

        #print((length_S + seq_num_S + self.msg_S).encode('utf-8'))
        # print(length_S + seq_num_S + self.msg_S)
        # print((checksum).encode('utf-8'))

        checksum_S = checksum.hexdigest()

        #print(checksum_S)
        #print(length_S + seq_num_S + checksum_S + self.msg_S)

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
        packet_sent = Packet(self.seq_num, msg_S)                   # create new packet to be sent

        while True:                                                 # while packet has not been sent
            print("SEND PACKET_SENT")
            self.network.udt_send(packet_sent.get_byte_S())         # send packet
            response_msg = ''                                       # initialize a received packet

            while response_msg == '':                               # while the client has not received response
                # print("GET RESPONSE")
                response_msg = self.network.udt_receive()           # get response

            length = int(response_msg[:Packet.length_S_length])     # get the length of the response
            self.byte_buffer = response_msg[length:]                # put the response in a byte buffer

            if Packet.corrupt(response_msg[:length]):               # if the packet is corrupt
                print("PACKET CORRUPT BYTE_BUFFER = '' ")
                self.byte_buffer = ''                               # reset the buffer to '' (nothing)

            #if not Packet.corrupt(response_msg[:length]):           # if the packet is not corrupt
            else:
                packet = Packet.from_byte_S(response_msg[:length])  # create a new packet that has the same length
                                                                    # and received packets as the response
                if packet.seq_num < self.seq_num:                   # if the sequence number is behind
                    ack = Packet(packet.seq_num, "1")               # create ACk packet to be sent
                    print("SEND ACK PACKET")
                    self.network.udt_send(ack.get_byte_S())         # send ACK

                elif packet.msg_S == "1":                           # if the response message is 1 (ACK packet received)
                    print("RECEIVED ACK PACKET")
                    self.seq_num += 1                               # increment the sequence number
                    break                                           # break out of loop

                elif packet.msg_S == "0":                           # if the response message is 0 (NAK packet received)
                    print("RECEIVED NAK PACKET")
                    self.byte_buffer = ''                           # reset the buffer
                    continue

    @property
    def rdt_2_1_receive(self):
        #print("RDT 2.1 RECEIVE")
        ret_S = None  # --------------------------------------------- taken from rdt 1.0 receive --------------------
        byte_S = self.network.udt_receive()
        self.byte_buffer += byte_S
        cur_seq = self.seq_num
        while cur_seq == self.seq_num:
            if (len(self.byte_buffer) < Packet.length_S_length):      # check if we have received enough bytes
                # print("buffer BREAK")
                break                                       # not enough bytes to read packet length

            length = int(self.byte_buffer[:Packet.length_S_length]) # extract length of packet

            if len(self.byte_buffer) < length:
                print("length BREAK")
                break                                        # not enough bytes to read the whole packet
            # -------------------------------------------------------------------------------------------------------
            if Packet.corrupt(self.byte_buffer):                    # if packet is corrupt
                print("Packet corrupt")
                nak = Packet(self.seq_num, "0")                     # send NAK
                self.network.udt_send(nak.get_byte_S())

            else:                                                   # if packet ! corrupt
                print("packet NOT corrupt")
                p = Packet.from_byte_S(self.byte_buffer[0:length])   # create packet w/ same length and received packets
                print("SELF SEQ: ", self.seq_num)

                print("P SEQ: ", p.seq_num)

                #if p.msg_S != "0" or p.msg_S != "1":                # check for ACK (msg = 1) or NAK (msg = 0)

                if p.msg_S == "1":
                    self.byte_buffer = self.byte_buffer[length:]    # set byte buffer
                    continue

                #if p.msg_S != "0" or p.msg_S != "1":
                if p.seq_num < self.seq_num:                        # if responding packet seq num < self's seq num
                    print("DUPLICATE")
                    ack = Packet(p.seq_num, "1")                    # it's a duplicate create ACK to be sent
                    self.network.udt_send(ack.get_byte_S())         # send ACK

                elif p.seq_num == self.seq_num:                     # if the responding packet seq num == self seq num
                    print("INCREMENT sequence number")
                    ack = Packet(p.seq_num, "1")                    # send ACK
                    self.network.udt_send(ack.get_byte_S())
                    self.seq_num += 1                               # increment the sequence number

                ret_S = p.msg_S if (ret_S is None) else ret_S + p.msg_S

            self.byte_buffer = self.byte_buffer[length:]            # reset the byte buffer to prepare for next packet
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
        #rdt.rdt_1_0_send('MSG_FROM_CLIENT')
        rdt.rdt_2_1_send('MSG_FROM_CLIENT')
        sleep(2)
        #print(rdt.rdt_1_0_receive())
        print(rdt.rdt_2_1_receive)
        rdt.disconnect()


    else:
        sleep(1)
        #print(rdt.rdt_1_0_receive())
        #rdt.rdt_1_0_send('MSG_FROM_SERVER')
        print(rdt.rdt_2_1_receive)
        rdt.rdt_2_1_send('MSG_FROM_SERVER')
        rdt.disconnect()
