import time
import datetime
import threading
import numpy as np
import pandas as pd
import pickle

import xgboost as xgb

from scapy.all import *

from keras.models import load_model

def IN_Dir(): return 0
def OUT_Dir(): return 1

MAC = '00:50:56:b2:9c:08'
#MAC = '00:0c:29:6d:29:60'
threshold = 3.0
feature = ['outPkts','inPkts', 'outByts', 'inByts',
           'outData', 'outDataByts', 'inData', 'inDataByts',
           'outPkts/s','inPkts/s','outByts/s','inByts/s','byts/s', 'pkts/s',
           'outPktLenMax', 'outPktLenMin', 'outPktLenMean', 'inPktLenMax', 'inPktLenMin', 'inPktLenMean',
           'Label']
columns = ['outPkts', 'inPkts', 'outByts', 'inByts', 'outData', 'outDataByts', 'inData', 'inDataByts', 
           'outPkts/s', 'inPkts/s', 'outByts/s', 'inByts/s', 'byts/s', 'pkts/s',
           'outPktLenMax' , 'outPktLenMin', 'outPktLenMean', 'inPktLenMax', 'inPktLenMin', 'inPktLenMean',
           'FIN', 'SYN', 'RST', 'PSH', 'ACK', 'URG', 'ECE', 'CWR']

# TCP Flags
# [FIN, SYN, RST, PSH, ACK, URG, ECE, CWR]
tcp_flags = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80]
# SSH message Types
# [Disconnect, key init, new keys, unknown]
SSH_MESSAGE_TYPES = [0x01, 0x14, 0x15, 0xff]

flow_list = []

para_mean = None
para_max = None
para_min = None

# each flow record information
class Flow:
    def __init__(self, start, end, src, dst, sp, dp, proto, inPkts, outPkts, inByts, outByts, inData, outData, inDataByts, outDataByts,
                 inPktLenMax, inPktLenMin, inPktLenMean, outPktLenMax, outPktLenMin, outPktLenMean, 
                 flags, inOutFlags):
        self.key = hash((src, dst, sp, dp,proto))
        self.start = start
        self.end = end
        self.src = src
        self.dst = dst
        self.sp = sp
        self.dp = dp
        self.proto = proto
        self.inPkts = inPkts
        self.outPkts = outPkts
        self.inByts = inByts
        self.outByts = outByts
        self.inData = inData
        self.outData = outData
        self.inDataByts = inDataByts
        self.outDataByts = outDataByts
        self.inPktLenMax = inPktLenMax
        self.outPktLenMax = outPktLenMax
        self.inPktLenMin = inPktLenMin
        self.outPktLenMin = outPktLenMin
        self.inPktLenMean = inPktLenMean
        self.outPktLenMean = outPktLenMean
        self.flags = flags
        self.inOutFlags = inOutFlags 

    # compare timestamp to check if the incomming packet is in the timeout range
    def is_pkt_in_threshold(self, pkt_timestamp):
        diff = abs(self.start - pkt_timestamp)
        if(diff >= threshold):
            return False
        else:
            return True

    # add packet to flow
    # modify 8 fields(inPkts, outPkts, inByts, outByts, inData, outData, inDataByts, outDataByts)
    def flow_calculate(self, direc, byts, dataByts, flow):
        self.end = flow.end
        if direc == IN_Dir():
            self.inPkts += 1
            self.inByts += byts
            self.inData += flow.inData
            self.inDataByts += dataByts
            self.inPktLenMax = find_max(self.inPktLenMax, flow.inPktLenMax)
            self.inPktLenMin = find_max(self.inPktLenMin, flow.inPktLenMin)
            self.inPktLenMean = cal_mean(self.inPktLenMean, self.inPkts, flow.inPktLenMean)
        else:
            self.outPkts += 1
            self.outByts += byts
            self.outData += flow.outData
            self.outDataByts += dataByts
            self.outPktLenMax = find_max(self.outPktLenMax, flow.outPktLenMax)
            self.outPktLenMin = find_max(self.outPktLenMin, flow.outPktLenMin)
            self.outPktLenMean = cal_mean(self.outPktLenMean, self.outPkts, flow.outPktLenMean)

    def modify_key(self, newkey):
        self.key = newkey

    def update_flags(self, flags, in_out):
        for i in range(len(tcp_flags)):
            if(flags[i] != 0):
                self.flags[i] = 1
        for i in range(len(in_out)):
            if(in_out[i] != 0):
                self.inOutFlags[i] = 1
            # calculate count
            # self.flags[i] += flags[i]


def find_max(a, b):
    if(a > b):
        return a
    else:
        return b

def find_min(a, b):
    if(a > b):
        return b
    else:
        return a

def cal_mean(oMean, count, val):
    return ((oMean * (count - 1)) + val) / count

# determine the direction of packet
def get_packet_direction(pkt):
    if pkt[Ether].src != MAC:
        return IN_Dir()
    else:
        return OUT_Dir()

# use hash key to check if new flow has exist flow record
def find_key(flow, key):
    op_new_key = hash((flow.dst, flow.src, flow.dp, flow.sp, flow.proto))
    if(flow.key == key):
        return True
    if(op_new_key == key):
        flow.modify_key(op_new_key)
        return True 
    return False;

# find new packet flow is exist in flow list or not
# if yes then calculate the packet count and bytes
def find_and_cal_flow_info(newflow, direc, byts, dataByts):
    for flow in flow_list:
        # same flow has the same key
        # if the incoming packet flow has same 5-tuple with previous flow
        value = find_key(newflow, flow.key)
        if(value):
            # and also check the incoming packet timestamp is in threshold
            if(flow.is_pkt_in_threshold(flow.start)):
                # then calculte the bytes and count
                flow.flow_calculate(direc, byts, dataByts, newflow)
                flow.update_flags(newflow.flags, newflow.inOutFlags)
                return True
    return False

# calculate duration
def cal_duration(start, end):
    return (end - start)

# calculate the number of packets and bytes go through per second
def cal_persecond_pktbyts(pkt, dur):
    if dur == 0:
        return 0
    else:
        return round(pkt / dur, 2)

# port transfermation
# type:
#   - 1~1023: well-known port
#   - 1024~49151: registered port
#   - 49152~65535: dynamic port
def trans_port(port):
    x, y, z = 0, 0, 0
    if port < 1024:
        x = 1
    elif(port >= 1024 and port < 49152 ):
        y = 1
    else:
        z = 1
    return x, y, z

def read_para(file):
    with open(f'{file}.txt' .format(file = file), 'r') as file:
        line = file.readline()
        data = []
        while line:
            data.append(float(line.rstrip()))
            line = file.readline()

        ser = pd.Series(data, index = feature[:len(feature)-1])
        return ser

# create a thread to pop up the timeout flow
# check flow_list
def thread_popup_timeout_flow():
    # pop up flow
    print('start thread')
    while(1):
        now = time.time()
        for flow in flow_list:
            flag = flow.is_pkt_in_threshold(now)
            if(not flag):
                flow_list.remove(flow)
                duration = cal_duration(flow.start, flow.end)
                inPktss = cal_persecond_pktbyts(flow.inPkts, duration)
                outPktss = cal_persecond_pktbyts(flow.outPkts, duration)
                inBytss = cal_persecond_pktbyts(flow.inByts, duration)
                outBytss = cal_persecond_pktbyts(flow.outByts, duration)
                pktss = inPktss + outPktss
                bytss = inBytss + outBytss
                srcPort = trans_port(flow.sp)
                dstPort = trans_port(flow.dp)

                print('------------------------------------------------------------------------------------')
                #print('time: {}' .format(datetime.datetime.now().time()))
                print('src\t\tdst\t\tsport\tdport\tprotocol')
                print('{}\t{}\t{}\t{}\t{}' .format(flow.src, flow.dst, flow.sp, flow.dp, flow.proto))
                print('duration\tsrc port\tdst port')
                print('{}\t{}\t{}' .format(round(duration, 10), srcPort, dstPort)) 
                print('inPkts\toutPkts\tinByts\toutByts\tinData\toutData\tinDataByts\toutDataByts')
                print('{}\t{}\t{}\t{}\t{}\t{}\t{}\t\t{}' .format(flow.inPkts, flow.outPkts, flow.inByts, flow.outByts, 
                                                                 flow.inData, flow.outData, flow.inDataByts, flow.outDataByts))
                print('inPkts/s\toutPkts/s\tinByts/s\toutByts/s\tpkts/s\tbyts/s')
                print('{}\t\t{}\t\t{}\t{}\t{}\t{}' .format(inPktss, outPktss, inBytss, outBytss, pktss, bytss)) 
                print('inPktLenMax\tinPktLenMin\tinPktLenMean\toutPktLenMax\toutPktLenMin\toutPktLenMean')
                print('{}\t\t{}\t\t{}\t{}\t{}\t{}' .format(flow.inPktLenMax, flow.inPktLenMin, flow.inPktLenMean, flow.outPktLenMax, flow.outPktLenMin, flow.outPktLenMean)) 
                print('FIN\tSYN\tRST\tPSH\tACK\tURG\tECE\tCWR')
                print('{}' .format(flow.flags)) 
                print('outPSH\tinPSH\toutURG\toutURG')
                print('{}' .format(flow.inOutFlags)) 
                
                data = [flow.outPkts, flow.inPkts, flow.outByts, flow.inByts, flow.outData, flow.outDataByts, 
                        flow.inData, flow.inDataByts, outPktss, inPktss, outBytss, inBytss, bytss, pktss,
                        flow.outPktLenMax , flow.outPktLenMin, flow.outPktLenMean, flow.inPktLenMax, flow.inPktLenMin, flow.inPktLenMean,
                        flow.flags[0], flow.flags[1], flow.flags[2], flow.flags[3], flow.flags[4], flow.flags[5], flow.flags[6], flow.flags[7]]
                
                df = pd.DataFrame([data])
                df.to_csv('output.csv', mode = 'a', index = False, header = False)

               # norm_data = (data - para_mean) / (para_max - para_min)
               # cnn_norm_data = norm_data.values.reshape(1, len(feature)-1, 1)
               # extract_data = cnn.predict(cnn_norm_data)
               # extract_data = pd.DataFrame(extract_data,
               #                             columns=['0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '10', '11', '12', '13', '14', '15', '16', '17', '18', '19', '20', '21', '22', '23', '24', '25', '26', '27', '28', '29', '30', '31'])
               # xgb_input = xgb.DMatrix(extract_data)
               # pred = xgb_model.predict(xgb_input)
               # print('result: {}' .format(pred))

def cal_ssh_len(payload):
    sshlen = 0
    power = 6
    for i in range(4):
        val = payload[i]
        val = val * pow(16, power)
        power = power - 2
        sshlen += val
    return sshlen

def packet_callback(packet):
    #packet.show()
    now = time.time()
    # packet information
    src = packet[IP].src
    dst = packet[IP].dst
    sp = packet[TCP].sport
    dp = packet[TCP].dport
    proto = packet[IP].proto
    byts = packet[IP].len
    
    direc = get_packet_direction(packet)
    
    flag_arr = [0, 0, 0, 0, 0, 0, 0, 0]
    in_out_flags = [0, 0, 0, 0]
    F = packet[TCP].flags
    for i in range(len(flag_arr)):
        if F & tcp_flags[i]:
            flag_arr[i] = 1
            if(tcp_flags[i] == 0x08):
                if(direc == OUT_Dir):
                    in_out_flags[0] = 1
                else:
                    in_out_flags[1] = 1
            elif(tcp_flags[i] == 0x20):
                if(direc == OUT_Dir):
                    in_out_flags[2] = 1
                else:
                    in_out_flags[3] = 1

    # check the direction of packet(in/out) and show the payload size
    inPkts = 0
    outPkts = 0
    inByts = 0
    outByts = 0
    inPktLen = 0
    outPktLen = 0
    datacount = 0
    appdata = 0
    if(direc == IN_Dir()):
        inPkts += 1
        inByts = packet[IP].len
        inPktLen = inByts
    else:
        outPkts += 1
        outByts = packet[IP].len
        outPktLen = outByts
    
    if isinstance(packet[TCP].payload, SSLv2):
        print('ssl')
    elif isinstance(packet[TCP].payload, TLS):
        # TLS info
        count = 0
        tlspkt = packet[TLS]
        tls_len = len(tlspkt)
        # TLS record
        while tls_len > 0:
            if isinstance(tlspkt[count], TLS):
                tls_len -= 5
                tls_len -= tlspkt[count].deciphered_len
                
                # if TLS record is belong to application_data(type=23)
                # then calculate the application data size
                if tlspkt[count].type == 23:
                    appdata += tlspkt[count].deciphered_len
                    datacount += 1

            elif isinstance(tlspkt[count], Raw):
                tls_len -= len(packet[TLS][count])
                
            count += 1

    else:
        if (packet[TCP].sport == 22 or packet[TCP].dport == 22):
            plen = len(packet[TCP].payload) 
            if isinstance(packet[TCP].payload, Padding):
                pass
            elif isinstance(packet[TCP].payload, Raw):
                sshlen = cal_ssh_len(packet[TCP].payload.load)
                ssh_type = packet[TCP].payload.load[5]
                if ssh_type == 0x01: # disconnect
                    pass
                elif ssh_type == 0x14: # key exchange initial
                    pass
                elif ssh_type == 0x15: # new key
                    pass
                else:
                    payload = packet[TCP].payload.load[0:4]
                    if payload.decode('cp437').startswith('SSH-'): # ssh start
                        pass
                    else: # encypted data
                        datacount = 1
                        appdata = plen 
    # check the direction of packet(in/out) and show the encrypted data size
    inData = 0
    outData = 0
    inDataByts = 0
    outDataByts = 0
    
    if(direc == IN_Dir()):
        inData = datacount
        inDataByts = appdata
    else:
        outData = datacount 
        outDataByts = appdata

    pktFlow = Flow(now, now, src, dst, sp, dp, proto,
                   inPkts, outPkts, inByts, outByts, 
                   inData, outData, inDataByts, outDataByts,
                   inPktLen, inPktLen, inPktLen, outPktLen, outPktLen, outPktLen,
                   flag_arr, in_out_flags)
   

    if not flow_list:
        flow_list.append(pktFlow)
    else:
        found = find_and_cal_flow_info(pktFlow, direc, byts, appdata)
        if(not found):
            flow_list.append(pktFlow)


load_layer("tls")
if __name__ == '__main__': 
    print('load model')
    cnn = load_model('CNN.h5')
    xgb_model = xgb.Booster(model_file='xgb_model.model')
    print('load parameter')
    para_mean = read_para('mean_para')
    para_max = read_para('max_para')
    para_min = read_para('min_para')
    print(para_mean)
    print(para_max)
    print(para_min)
    # Create a new csv output file to save flow information for training dataset
    print('Ouput file is prepared: output.csv')
    df = pd.DataFrame([columns])
    df.to_csv('output.csv', header = False, index = False)

    popup_thread = threading.Thread(target = thread_popup_timeout_flow)
    popup_thread.start()
    #sniff(iface="ens33", prn=packet_callback, lfilter= lambda x: TLS in x, store=0, count=0)
    sniff(iface="ens160", prn=packet_callback, lfilter= lambda x: TCP in x and not IPv6 in x, store=0, count=0)
