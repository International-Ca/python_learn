from socket import *
import struct
import json
import random
import threading
import global_val
import logging
import time
import ctypes
import binascii

global_val._init()
global_val.setvalue('inverse_version_select', 0)
global_val.setvalue('payload_type_select', 0)
global_val.setvalue('payload_length_select', 0)
global_val.setvalue('EID_select', 0)
global_val.setvalue('VIN_select', 0)
global_val.setvalue('tester_logic_addr_select', 0)
global_val.setvalue('DUT_Function_addressing_select', 0)
global_val.setvalue('tcp_client_select', 0)


def print_hex(bytes):
    l = [hex(int(i)) for i in bytes]
    print(" ".join(l))


def transform_bytes(str):
    k = [int(ord(i)) for i in str]
    return ((bytes(k)))


class DoIP():
    def __init__(self):
        try:
            with open('config_ipv6.json', 'r') as fs:
                doip_config = json.load(fs)
        except IOError as e:
            print(e)
        print(doip_config)

        self._ip_ver = doip_config['ip_ver']
        self._version = doip_config['version']
        self._ecu_ip_addr = doip_config['ecu_ip_addr']
        self._ecu_logic_addr = int(doip_config['ecu_logic_addr'], 16)
        self._ecu_Fun_addr = int(doip_config['ecu_Fun_addr'], 16)
        self._tester_ip_addr = doip_config['tester_ip_addr']
        self._tester_ini_ip_addr = doip_config['tester_ini_ip_addr']
        self._tester_logic_addr = int(doip_config['tester_logic_addr'], 16)
        self._tester_logic_addr_1 = int(doip_config['tester_logic_addr_1'], 16)

    def ip_ver_init(self):
        if self._ip_ver == 4:
            self._ipv4_init()
        elif self._ip_ver == 6:
            self._ipv6_init()
        else:
            print("Error _ip_ver:%d" % self._ip_ver)
            exit()
        print('DoIP init success: vesion:0x%x' % self._version)

    def _ipv4_init(self):
        # 第一个tcp socket
        self._tcp_client = socket(family=AF_INET, type=SOCK_STREAM)
        self._tcp_client.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
        src_port = random.randint(49153, 65535)
        self._tcp_client.bind((self._tester_ip_addr, src_port))
        # 第二个tcp socket
        self._tcp_client1 = socket(family=AF_INET, type=SOCK_STREAM)
        self._tcp_client1.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
        src_port1 = random.randint(49153, 65535)
        self._tcp_client1.bind((self._tester_ip_addr, src_port1))

        self._udp_client = socket(family=AF_INET, type=SOCK_DGRAM)
        self._udp_client.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
        self._udp_client.bind((self._tester_ip_addr, 13400))

    def _ipv6_init(self):
        self._tcp_client = socket(family=AF_INET6, type=SOCK_STREAM)
        self._tcp_client.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
        src_port = random.randint(49153, 65535)
        self._tcp_client.bind((self._tester_ip_addr, src_port))
        # 第二个tcp socket
        self._tcp_client1 = socket(family=AF_INET6, type=SOCK_STREAM)
        self._tcp_client1.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
        src_port1 = random.randint(49153, 65535)
        self._tcp_client1.bind((self._tester_ip_addr, src_port1))

        self._udp_client = socket(family=AF_INET6, type=SOCK_DGRAM)
        self._udp_client.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
        self._udp_client.bind((self._tester_ip_addr, 13400))

    # 车辆识别请求报文0x0001
    def send_vehicle_identification_request(self):
        payload = bytes()
        data = self.doip_serialize(self._version, 0x0001, payload)
        self._udp_client.sendto(data, (self._ecu_ip_addr, 13400))
        logging.info('DoIP vehicle Identification Request:')
        l = [hex(int(i)) for i in data]
        logging.info("send vehicle identification request:" + " ".join(l))

    def receive_vehicle_identification(self):
        self._udp_client.settimeout(5)
        recv_data, addr = self._udp_client.recvfrom(1024)
        l = [hex(int(i)) for i in recv_data]
        logging.info("receive vehicle data is:" + " ".join(l))
        return l

    def vir_no_payload(self):
        logging.warning("VIR without Payload")
        self.send_vehicle_identification_request()
        rec_data = self.receive_vehicle_identification()
        if rec_data[2] == '0x0' and rec_data[3] == '0x4':
            logging.info('vehicle identified OK')
            return True
        else:
            logging.error('vehicle identified Failed')
            return False

    # 具有EID的车辆请求报文0x0002
    def send_EID_vehicle_request(self, EID):
        payload = bytes()
        if global_val.getvalue('EID_select') == 1:
            # 发送错误的EID
            payload = bytes([1, 1, 1, 1, 1, 1])
        else:
            for i in range(6):
                payload = payload + int(EID[i], 16).to_bytes(1, byteorder="big")
        data = self.doip_serialize(self._version, 0x0002, payload)
        self._udp_client.sendto(data, (self._ecu_ip_addr, 13400))
        logging.info('DoIP vehicle Identification Request:')
        l = [hex(int(i)) for i in data]
        logging.info("send vehicle identification request:" + " ".join(l))

    def receive_EID_vehicle_request(self):
        self._udp_client.settimeout(5)
        recv_data, addr = self._udp_client.recvfrom(13400)
        l = [hex(int(i)) for i in recv_data]
        logging.info("receive vehicle data is:" + " ".join(l))
        return l

    # 诊断电源模式请求报文0x4003
    def send_power_mode_information_request(self):
        payload = bytes()
        data = self.doip_serialize(self._version, 0x4003, payload)
        self._udp_client.sendto(data, (self._ecu_ip_addr, 13400))
        logging.info('DoIP Power Mode Information Request:')
        l = [hex(int(i)) for i in data]
        logging.info("send power mode information request:" + " ".join(l))

    def receive_power_mode_infomation_request(self):
        self._udp_client.settimeout(5)
        recv_data, addr = self._udp_client.recvfrom(1024)
        logging.info("receive power mode data is:")
        l = [hex(int(i)) for i in recv_data]
        logging.info("receive power mode data is:" + " ".join(l))
        return l

    # 具有VIN码的车辆识别请求报文0x0003
    def send_VIN_recognition_request(self, VIN):
        payload = bytes()
        if global_val.getvalue('VIN_select') == 1:
            payload = bytes([1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1])
        else:
            for i in range(17):
                payload = payload + int(VIN[i], 16).to_bytes(1, byteorder="big")
        data = self.doip_serialize(self._version, 0x0003, payload)
        self._udp_client.sendto(data, (self._ecu_ip_addr, 13400))
        logging.info("DoIP vin recognition request:")
        l = [hex(int(i)) for i in data]
        logging.info("Send vin recognition request:" + " ".join(l))

    def receive_VIN_recognition_request(self):
        self._udp_client.settimeout(5)
        recv_data, addr = self._udp_client.recvfrom(1024)
        l = [hex(int(i)) for i in recv_data]
        logging.info("receive response from vin request data:" + " ".join(l))
        return l

    def connect_to_server(self):
        if global_val.getvalue('tcp_client_select') == 1:
            self._tcp_client1.connect((self._ecu_ip_addr, 13400))
        else:
            self._tcp_client.connect((self._ecu_ip_addr, 13400))

    # 路由激活请求0x0005
    def send_routing_activation_request(self, activation_type, reserved_by_oem):
        # self.connect_to_server()
        if global_val.getvalue('tester_logic_addr_select') == 1:
            payload = bytes([0xFF, 0xFF])
        elif global_val.getvalue('tester_logic_addr_select') == 2:
            payload = bytes([0x0E, 0x01])
        elif global_val.getvalue('tester_logic_addr_select') == 3:
            payload = self._tester_logic_addr_1.to_bytes(2, byteorder="big")
            logging.warning(payload)
        else:
            payload = self._tester_logic_addr.to_bytes(2, byteorder="big")
        payload += activation_type.to_bytes(1, byteorder="big")
        payload += bytes([0x00, 0x00, 0x00, 0x00])
        payload += reserved_by_oem.to_bytes(4, byteorder="big")
        data = self.doip_serialize(self._version, 0x0005, payload)
        if global_val.getvalue('tcp_client_select') == 1:  # 第二个socket发数据
            self._tcp_client1.send(data)
        else:
            self._tcp_client.send(data)  # 第一个socket发数据
        logging.info('DoIP Routing Activation Request:')
        l = [hex(int(i)) for i in data]
        logging.info("Send Routing Activation Request:" + " ".join(l))

    def receive_routing_activation(self):
        if global_val.getvalue('tcp_client_select') == 1:  # 第二个socket收数据
            self._tcp_client1.settimeout(5)
            recv_data_head = self._tcp_client1.recv(8)
            l = [format((int(i)), "x") for i in recv_data_head]
            buf = l[4].zfill(2) + l[5].zfill(2) + l[6].zfill(2) + l[7].zfill(2)
            data_length = int(buf, 16)
            recv_data_payload = self._tcp_client1.recv(data_length)
            recv_data = recv_data_head + recv_data_payload
        else:  # 第一个socket收数据
            self._tcp_client.settimeout(5)
            recv_data_head = self._tcp_client.recv(8)
            l = [format((int(i)), "x") for i in recv_data_head]
            buf = l[4].zfill(2) + l[5].zfill(2) + l[6].zfill(2) + l[7].zfill(2)
            data_length = int(buf, 16)
            recv_data_payload = self._tcp_client.recv(data_length)
            recv_data = recv_data_head + recv_data_payload
        l = [hex(int(i)) for i in recv_data]
        logging.info("receive routing activation data is:" + " ".join(l))
        return l

    def routing_activation_request(self, activation_type, reserved_by_oem):
        logging.warning("Start Routing Activation Test")
        self.send_routing_activation_request(activation_type, reserved_by_oem)

        rec_data_replay = self.receive_routing_activation()
        if rec_data_replay[12] == '0x10':
            logging.info('routing activation OK')
            return True
        else:
            logging.error('routing activation Failed')
            return False

    def second_address_routing_activation_request(self, activation_type, reserved_by_oem):
        logging.warning("Start Routing Activation Test")
        global_val.setvalue("tester_logic_addr_select", 3)
        self.send_routing_activation_request(activation_type, reserved_by_oem)
        global_val.setvalue("tester_logic_addr_select", 0)
        rec_data_replay = self.receive_routing_activation()
        if rec_data_replay[12] == '0x2':
            logging.info('routing activation OK')
            return True
        else:
            logging.error('routing activation Failed')
            return False

    def invalid_action_type_test(self, activation_type, reserved_by_oem):
        self.send_routing_activation_request(activation_type, reserved_by_oem)
        rec_data = self.receive_routing_activation()
        if (len(rec_data) < 12):
            return False
        if rec_data[12] == '0x6':
            logging.info('Invalid Activation Type Test OK')
            return True
        else:
            logging.error('Invalid Activation Type Test Failed')
            return False

    # 在线检查请求0x0007
    def send_alive_request(self):
        payload = bytes()
        data = self.doip_serialize(self._version, 0x0007, payload)
        self._tcp_client.sendto(data, (self._ecu_ip_addr, 13400))
        logging.info('DoIP alive Request:')
        l = [hex(int(i)) for i in data]
        logging.info("send alive request:" + " ".join(l))

    def receive_alive_request_tcp(self):
        self._tcp_client.settimeout(5)
        recv_data_head = self._tcp_client.recv(8)
        l = [format((int(i)), "x") for i in recv_data_head]
        buf = l[4].zfill(2) + l[5].zfill(2) + l[6].zfill(2) + l[7].zfill(2)
        data_length = int(buf, 16)
        recv_data_payload = self._tcp_client.recv(data_length)
        recv_data = recv_data_head + recv_data_payload
        logging.info("receive alive request is:")
        l = [hex(int(i)) for i in recv_data]
        logging.info("receive alive request is:" + " ".join(l))
        return l

    def receive_alive_response(self):
        self._udp_client.settimeout(5)
        recv_data, addr = self._udp_client.recvfrom(1024)
        logging.info("receive alive data is:")
        l = [hex(int(i)) for i in recv_data]
        logging.info("receive alive data is:" + " ".join(l))
        return l

    # 发送在线检查响应0x0008
    def send_alive_response(self):
        payload = bytes([0x0E, 0x80])
        data = self.doip_serialize(self._version, 0x0008, payload)
        self._tcp_client.sendto(data, (self._ecu_ip_addr, 13400))
        logging.info('send DoIP alive response:')
        l = [hex(int(i)) for i in data]
        logging.info("send alive response:" + " ".join(l))

    # DoIP实体状态请求0x4001
    def send_doip_entity_status_request(self):
        payload = bytes()
        data = self.doip_serialize(self._version, 0x4001, payload)
        self._udp_client.sendto(data, (self._ecu_ip_addr, 13400))
        logging.info('DoIP Entity Status Request:')
        l = [hex(int(i)) for i in data]
        logging.info("send Entity Status request:" + " ".join(l))

    def receive_doip_entity_status_response(self):
        self._udp_client.settimeout(5)
        recv_data, addr = self._udp_client.recvfrom(1024)
        logging.info("receive Entity Status data is:")
        l = [hex(int(i)) for i in recv_data]
        logging.info("receive Entity Status data is:" + " ".join(l))
        return l

    # 诊断报文0x8001
    def send_diagnostic_message(self, uds_msg):
        if global_val.getvalue('DUT_Function_addressing_select') == 0:
            DUT_address = self._ecu_logic_addr.to_bytes(2, byteorder="big")
        else:
            DUT_address = self._ecu_Fun_addr.to_bytes(2, byteorder="big")

        if global_val.getvalue('tester_logic_addr_select') == 3:
            Tester_address = self._tester_logic_addr_1.to_bytes(2, byteorder="big")
        else:
            Tester_address = self._tester_logic_addr.to_bytes(2, byteorder="big")

        logic_addr_field = Tester_address + DUT_address
        payload = logic_addr_field + bytes.fromhex(uds_msg)
        if global_val.getvalue('payload_type_select') == 1:
            data = self.doip_serialize(self._version, 0xFFFF, payload)
        else:
            data = self.doip_serialize(self._version, 0x8001, payload)
        data = data
        self._tcp_client.send(data)
        logging.info('DoIP Diagnostic Message:')
        l = [hex(int(i)) for i in data]
        logging.info("Send Diagnostic Message:" + " ".join(l))

    def send_diagnostic_message_nolog(self, uds_msg):
        if global_val.getvalue('DUT_Function_addressing_select') == 0:
            logic_addr_field = self._tester_logic_addr.to_bytes(2, byteorder="big") + self._ecu_logic_addr.to_bytes(2,
                                                                                                                    byteorder="big")
        else:
            logic_addr_field = self._tester_logic_addr.to_bytes(2, byteorder="big") + self._ecu_Fun_addr.to_bytes(2,
                                                                                                                  byteorder="big")

        payload = logic_addr_field + bytes.fromhex(uds_msg)
        if global_val.getvalue('payload_type_select') == 1:
            data = self.doip_serialize(self._version, 0xFFFF, payload)
        else:
            data = self.doip_serialize(self._version, 0x8001, payload)
        data = data
        self._tcp_client.send(data)
        l = [hex(int(i)) for i in data]

    def diag_session_control(self, payload):
        payload = '10' + payload
        self.send_diagnostic_message(payload)

    def receive_diagnostic_data(self):
        recv_data_head = self._tcp_client.recv(8)
        l = [format((int(i)), "x") for i in recv_data_head]
        buf = l[4].zfill(2) + l[5].zfill(2) + l[6].zfill(2) + l[7].zfill(2)
        data_length = int(buf, 16)
        recv_data_payload = self._tcp_client.recv(data_length)
        recv_data = recv_data_head + recv_data_payload
        l = [hex(int(i)) for i in recv_data]
        logging.info("Receive Diagnostic Data:" + " ".join(l))
        return l

    def receive_diagnostic_data_nolog(self):
        recv_data_head = self._tcp_client.recv(8)
        l = [format((int(i)), "x") for i in recv_data_head]
        buf = l[4].zfill(2) + l[5].zfill(2) + l[6].zfill(2) + l[7].zfill(2)
        data_length = int(buf, 16)
        recv_data_payload = self._tcp_client.recv(data_length)
        recv_data = recv_data_head + recv_data_payload
        l = [hex(int(i)) for i in recv_data]
        return l

    def diag_message(self, payload):
        logging.warning("Start Diagnostic Converisation")
        self.diag_session_control(payload)
        rec_data = self.receive_diagnostic_data()
        if rec_data[12]=="0x0":
            self.receive_diagnostic_data()
        return rec_data

    def send_multi_diagnostic_message(self):
        uds_msg = '1001'
        if global_val.getvalue('DUT_Function_addressing_select') == 0:
            logic_addr_field = self._tester_logic_addr.to_bytes(2, byteorder="big") + self._ecu_logic_addr.to_bytes(2,
                                                                                                                    byteorder="big")
        else:
            logic_addr_field = self._tester_logic_addr.to_bytes(2, byteorder="big") + self._ecu_Fun_addr.to_bytes(2,
                                                                                                                  byteorder="big")

        payload = logic_addr_field + bytes.fromhex(uds_msg)
        if global_val.getvalue('payload_type_select') == 1:
            data = self.doip_serialize(self._version, 0xFFFF, payload)
        else:
            data = self.doip_serialize(self._version, 0x8001, payload)
        data = data * 110
        self._tcp_client.send(data)
        logging.info('DoIP Diagnostic Message:')
        l = [hex(int(i)) for i in data]
        logging.info("Send Diagnostic Message:" + " ".join(l))

    def multi_diag_message(self):
        self.send_multi_diagnostic_message()
        rec_data = self.receive_diagnostic_data()
        return rec_data

    def ecu_reset(self, payload):
        payload = '11' + payload
        self.send_diagnostic_message(payload)

    def tester_present(self, payload):
        payload = '3E' + payload
        self.send_diagnostic_message(payload)

    def clear_diag_info(self, payload):
        payload = '14' + payload
        self.send_diagnostic_message(payload)

    def read_dtc_info(self, payload):
        payload = '19' + payload
        self.send_diagnostic_message(payload)

    def write_data_by_id(self, payload):
        payload = '2E' + payload
        self.send_diagnostic_message(payload)

    def read_data_by_id(self, payload):
        payload = '22' + payload
        self.send_diagnostic_message(payload)

    def security_access_request(self, typ, data):
        payload = '27' + typ + data
        self.send_diagnostic_message(payload)

    def communication_control_request(self, payload):
        payload = '28' + payload
        self.send_diagnostic_message(payload)

    def route_control(self, payload):
        payload = '31' + payload
        self.send_diagnostic_message(payload)

    def control_dtc_setting(self, payload):
        payload = '85' + payload
        self.send_diagnostic_message(payload)

    def download_request_message(self, payload):
        payload = '34' + payload
        self.send_diagnostic_message(payload)

    def transfer_request_message(self, block, data):
        payload = '36' + block + data
        self.send_diagnostic_message_nolog(payload)

    # 封装DoIP
    def doip_serialize(self, protocol_ver, payload_type, payload):
        protocol_field = protocol_ver.to_bytes(1, byteorder="big")
        inv_protocol_field = (~protocol_ver & 0xFF).to_bytes(1, byteorder="big")
        if global_val.getvalue('inverse_version_select') == 1:
            inv_protocol_field = int(0xFC).to_bytes(1, byteorder="big")
        payload_type_field = payload_type.to_bytes(2, byteorder="big")
        if global_val.getvalue('payload_length_select') == 1:
            length_field = int(0xffffffff).to_bytes(4, byteorder="big")
        elif global_val.getvalue('payload_length_select') == 2:
            length_field = int(0x00032000).to_bytes(4, byteorder="big")
        elif global_val.getvalue('payload_length_select') == 3:
            length_field = int(0x00000100).to_bytes(4, byteorder="big")
        elif global_val.getvalue('payload_length_select') == 4:
            length_field = int(0x00000004).to_bytes(4, byteorder="big")
        else:
            length_field = len(payload).to_bytes(4, byteorder="big")
        message = protocol_field + inv_protocol_field + payload_type_field + length_field + bytes(payload)
        data = struct.pack("%dB" % (len(message)), *message)
        return data

    def fun_timer_callback(self):
        self.tester_present('80')
        global timer
        timer = threading.Timer(1, self.fun_timer_callback)
        timer.start()

    # 测试诊断信息的请求与响应0x8001
    def diag_message_response_test(self):
        rec_data = self.diag_message('01')
        if rec_data[12] == '0x0':
            logging.info("Diag message is positive response")
            return True
        else:
            logging.error("Diag message is negative response")
            return False

    # 测试无效的源地址
    # 测试源地址为 0xffff
    def invalid_source_address_test(self):
        self._tester_logic_addr = 0xFFFF
        rec_data = self.diag_message('01')
        self._tester_logic_addr = 0x0E80
        if len(rec_data) < 12:
            return False
        if rec_data[12] == '0x2':
            logging.info("Invalid_Source_Address Test OK")
            return True
        else:
            logging.error("Invalid_Source_Address Test Failed")
            logging.info("response value:" + ' '.join(rec_data[29:33]))
            return False

    # 测试未知的目标地址
    # 测试目标地址为 0xffff
    def unkown_target_address_test(self):
        self._ecu_logic_addr = 0xFFFF
        rec_data = self.diag_message('01')
        self._ecu_logic_addr = 0x3131
        if rec_data[12] == '0x3':
            logging.info("Diag Message Invalid_DUT_adder Test OK")
            return True
        else:
            logging.error("Diag Message Invalid_DUT_adder Test Failed")
            logging.info("response value:" + ' '.join(rec_data[29:33]))
            return False

    # 测试不对的模式格式(协议版本异常和协议版本取反计算异常)
    def incorrect_pattern_format_test(self):
        self._version = 4  # 协议版本0x04
        self.diag_session_control('01')
        t1 = int(round(time.time() * 1000))
        rec_data = self.receive_diagnostic_data()
        t2 = int(round(time.time() * 1000))
        self._version = 2  # 协议版本0x04

        if t2 - t1 < 2000:
            logging.info('time gap is:%d ms' % (t2 - t1))
            if rec_data[8] == '0x0':
                logging.info("Incorrect Pattern_Format Test OK")
                return True
            else:
                logging.error("return value:" + ' '.join(rec_data[0:4]))
                logging.error("Incorrect Pattern_Format Test Failed")
                return False
        else:
            logging.error('response time is over 2s, %d ms' % (t2 - t1))
            return False

    # 测试未知负载类型
    def unkown_payload_type_test(self):
        global_val.setvalue('payload_type_select', 1)  # 负载类型设置为0xFFFF
        self.diag_session_control('01')
        rec_data = self.receive_diagnostic_data()
        global_val.setvalue('payload_type_select', 0)
        if rec_data[8] == '0x1':
            logging.info("Unknown_Payload_Type Test OK")
            return True
        else:
            logging.error("Unknown_Payload_Type Test Failed")
            return False

    # 测试message太大，通过改变负载长度测试
    def message_too_large_test(self):
        global_val.setvalue('payload_length_select', 1)  # 负载长度设置为0xFFFFFFFF
        self.diag_session_control('01')
        global_val.setvalue('payload_length_select', 0)
        rec_data = self.receive_diagnostic_data()
        if rec_data[8] == '0x2':
            logging.info("Message_Too_Large Test OK")
            return True
        else:
            logging.error("Message_Too_Large Test Failed")
            return False

    # 无效的负载长度测试，通过改变负载长度对VIN和诊断信息的测试
    def invalid_payload_length_VIN_test(self,VIN):
        global_val.setvalue('payload_length_select', 3)  # 负载长度0x00000010
        self.send_VIN_recognition_request(VIN)
        global_val.setvalue('payload_length_select', 0)  # 恢复正常负载长度
        try:
            rec_data = self.receive_VIN_recognition_request()
        except Exception as e:
            logging.error("Response timeout")
            return True
        if rec_data[2] == '0x0' and rec_data[3] == '0x0':
            if rec_data[8] == '0x4':
                logging.info(
                    "Payload Length:" + ' '.join(rec_data[4:8]))
                logging.info("NACK code:" + rec_data[8])
                return True
            else:
                logging.error("NACK code is wrong")
                return False

    def invalid_payload_length_Diag_message_test(self):
        global_val.setvalue('payload_length_select', 4)  # 负载长度0x0000004
        self.diag_session_control('01')
        rec_data = self.receive_diagnostic_data()
        global_val.setvalue('payload_length_select', 0)
        if rec_data[8] == '0x4':
            logging.info("Payload Type:" + ' '.join(rec_data[2:4]))
            logging.info("NACK code:" + rec_data[8])
            logging.info("Diag message is negative response")
            logging.info("Invalid_Payload_length Test OK")
            return True
        else:
            logging.error("Invalid_Payload_length Test Fail")
            return False

    # 带EID的Vehicle Identification Request报文接收测试
    def vir_with_eid_test(self, EID):
        self.send_EID_vehicle_request(EID)
        t1 = int(round(time.time() * 1000))
        rec_data = self.receive_EID_vehicle_request()
        t2 = int(round(time.time() * 1000))
        if t2 - t1 > 2000:
            logging.error("response time over 2s, %d ms" % (t2 - t1))
            return False
        else:
            logging.info("响应时间是：%d ms" % (t2 - t1))
            if rec_data[2] == '0x0' and rec_data[3] == '0x4':
                # 判断读出来的EID与配置中的EID是否一致
                if EID[0:6] == rec_data[27:33]:
                    logging.info("Payload Length:" + rec_data[7])
                    logging.info("VIN value:" + ' '.join(rec_data[8:25]))
                    logging.info("Logical Address:" + ' '.join(rec_data[25:27]))
                    logging.info("EID value:" + ' '.join(rec_data[27:33]))
                    logging.info("GID value:" + ' '.join(rec_data[33:39]))
                    logging.info("Future Action Required:" + rec_data[39])
                    return True
            else:
                logging.error("NO response")
                return False

    # 带VIN的Vehicle Identification Request报文接收测试 确认读出来的VIN与被测设备存储的VIN一致
    def vir_with_vin_test(self, VIN):
        self.send_VIN_recognition_request(VIN)
        try:
            rec_data = self.receive_VIN_recognition_request()
            if rec_data[2] == '0x0' and rec_data[3] == '0x4' and VIN[0:17] == rec_data[8:25]:
                logging.info(
                    "Payload Length:" + rec_data[4] + " " + rec_data[5] + " " + rec_data[6] + " " + rec_data[7])
                logging.info(
                    "VIN value:" + ' '.join(rec_data[8:25]))
                return True
            else:
                logging.error("Response Error")
                return False
        except Exception as e:
            logging.error(e)
            return False

    def vir_with_vin_wrong_length_test(self):

        self.send_VIN_recognition_request()
        try:
            rec_data = self.receive_VIN_recognition_request()
            if rec_data[2] == '0x0' and rec_data[3] == '0x4' and self._VIN[0:17] == rec_data[8:25]:
                logging.info(
                    "Payload Length:" + rec_data[4] + " " + rec_data[5] + " " + rec_data[6] + " " + rec_data[7])
                logging.info(
                    "VIN value:" + ' '.join(rec_data[8:25]))
                return True
            else:
                logging.error("Response Error")
                return False
        except Exception as e:
            logging.error(e)
            return False

    # 带EID的Vehicle Identification Request报文异常接收测试,发送与被测设备存储不一致的EID请求报文
    def vir_with_wrong_eid_test(self):
        global_val.setvalue('EID_select', 1)  # 设置EID为 0x1 0x1 0x1 0x1 0x1 0x1
        self.send_EID_vehicle_request('')
        global_val.setvalue('EID_select', 0)  # 还原EID
        t1 = int(round(time.time() * 1000))
        try:
            rec_data = self.receive_EID_vehicle_request()
            t2 = int(round(time.time() * 1000))
            if t2 - t1 > 2000:
                logging.error("响应超过2s %dms" % (t2 - t1))
            else:
                logging.info("响应时间是：%d ms" % (t2 - t1))
                if rec_data[2] == '0x0' and rec_data[3] == '0x4':
                    logging.error("positive response, test failed")
                    logging.info("Payload Length:" + rec_data[7])
                    logging.info("VIN value:" + ' '.join(rec_data[8:25]))
                    logging.info("Logical Address:" + ' '.join(rec_data[25:27]))
                    logging.info("EID value:" + ' '.join(rec_data[27:33]))
                    logging.info("GID value:" + ' '.join(rec_data[33:39]))
                    logging.info("Future Action Required:" + rec_data[39])
                else:
                    logging.error("NO response")
        except Exception as e:
            logging.info("Response timeout, test OK")
            return True

    # 带VIN的Vehicle Identification Request报文异常接收测试,发送与被测设备存储不一致的EID请求报文
    def vir_with_wrong_vin_test(self):
        global_val.setvalue('VIN_select', 1)  # 设置VIN的值为[1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1]
        self.send_VIN_recognition_request('')
        global_val.setvalue('VIN_select', 0)

        try:
            rec_data = self.receive_VIN_recognition_request()
            if rec_data[2] == '0x0' and rec_data[3] == '0x4':
                logging.error("positive response, test failed")
                if rec_data[8] == '0x4':
                    logging.info(
                        "Payload Length:" + rec_data[4] + " " + rec_data[5] + " " + rec_data[6] + " " + rec_data[7])
                    logging.info("VIN value:" + ' '.join(rec_data[8:25]))
                else:
                    logging.error("Response Error")
                return False
        except Exception as e:
            logging.info("Response timeout, test OK")
            return True

    # Vehicle Announcement流程测试， ECU上电自动发3帧0004报文
    def vehicle_announcement_test(self):
        t = [0, 0, 0]
        for i in range(3):
            msg, addr = self._udp_client.recvfrom(1024)
            t[i] = int(round(time.time() * 1000))
            data = [hex(int(i)) for i in msg]
            logging.info("receive vehicle data is:" + " ".join(data))

        if data[3] == '0x4':
            logging.info("ECU上电产生了车辆声明报文")
            if 480 <= t[2] - t[1] <= 520 and 480 <= t[1] - t[0] <= 520:
                logging.info("车辆声明报文间隔[480,520]ms, 第一次间隔%d ms" % (t[1] - t[0]))
                logging.info("车辆声明报文间隔[480,520]ms, 第二次间隔%d ms" % (t[2] - t[1]))
            else:
                logging.error("车辆声明报文间隔非[480,520]ms, 第一次间隔%d ms" % (t[1] - t[0]))
                logging.error("车辆声明报文间隔非[480,520]ms, 第二次间隔%d ms" % (t[2] - t[1]))

            self.ip_ver_init()
            self.send_VIN_recognition_request()
            T1 = int(round(time.time() * 1000))
            rec_data = self.receive_VIN_recognition_request()
            T2 = int(round(time.time() * 1000))
            if rec_data[3] == '0x4':
                logging.info("带VIN的车辆识别报文正常响应")
                if T2 - T1 < 500:
                    logging.info("带VIN的车辆识别报文响应时间低于500ms, 为%d ms" % (T2 - T1))
                    return True
                else:
                    logging.error("带VIN的车辆识别报文响应时间大于500ms, 为%d ms" % (T2 - T1))
                    return False
            else:
                logging.error("带VIN的车辆识别报文异常响应")
                return False
        else:
            logging.error("ECU上电没有产生车辆声明报文")
            return False

    # 未知的诊断仪逻辑地址测试，手动设置错误的地址，读出返回值是否合理
    def unknown_tester_addr_vir_test(self):
        global_val.setvalue('tester_logic_addr_select', 1)  # 设置诊断仪逻辑地址为0xFFFF
        test_result = self.vir_no_payload()
        global_val.setvalue('tester_logic_addr_select', 0)
        return test_result

    def unknown_tester_addr_routing_test(self):
        global_val.setvalue('tester_logic_addr_select', 1)  # 设置诊断仪逻辑地址为0xFFFF
        self.send_routing_activation_request(0x00, 0x00000000)
        rec_data = self.receive_routing_activation()
        global_val.setvalue('tester_logic_addr_select', 0)

        if rec_data[12] == '0x0':
            logging.info("诊断仪逻辑地址：" + rec_data[8] + " " + rec_data[9])
            logging.info("ECU逻辑地址：" + rec_data[10] + " " + rec_data[11])
            logging.info("Routing Activation test OK")
            return True
        else:
            logging.error("Routing Activation test failed")
        return False

    # SA Registered 测试
    def sa_registered_test(self):
        global_val.setvalue("tcp_client_select", 1)

        self.connect_to_server()
        self.send_routing_activation_request(0x00, 0x00000000)

        global_val.setvalue("tcp_client_select", 0)

        self.receive_alive_request_tcp()

        self.send_alive_response()

        global_val.setvalue("tcp_client_select", 1)

        rec_data = self.receive_routing_activation()

        global_val.setvalue("tcp_client_select", 0)

        if rec_data[12] == '0x3':
            logging.info("诊断仪逻辑地址：" + rec_data[8] + " " + rec_data[9])
            logging.info("ECU逻辑地址：" + rec_data[10] + " " + rec_data[11])
            logging.info("Routing Activation test OK")
            return True
        else:
            logging.error("Routing Activation failed")
            return False

    # 在线检查请求0x0007
    def alive_check_message_test(self):
        global_val.setvalue("tcp_client_select", 1)

        self.connect_to_server()
        self.send_routing_activation_request(0x00, 0x00000000)

        global_val.setvalue("tcp_client_select", 0)

        self.receive_alive_request_tcp()

        self.send_alive_response()

        global_val.setvalue("tcp_client_select", 1)

        rec_data = self.receive_routing_activation()

        global_val.setvalue("tcp_client_select", 0)

        if rec_data[12] == '0x3':
            logging.info("诊断仪逻辑地址：" + rec_data[8] + " " + rec_data[9])
            logging.info("ECU逻辑地址：" + rec_data[10] + " " + rec_data[11])
            logging.info("Routing Activation test OK")
            return True
        else:
            logging.error("Alive Message Check failed")
            return False

    # DoIP实体状态请求0x4001
    def doip_entity_status_request(self):
        self.send_doip_entity_status_request()
        rec_data = self.receive_doip_entity_status_response()

        if rec_data[2] == '0x40' and rec_data[3] == '0x2':
            logging.info("node type:" + rec_data[8])
            logging.info("最大并发TCP_DATA套接字数量:" + rec_data[9])
            logging.info("当前建立的套接字数量:" + rec_data[10])
            data_len = hex((int(rec_data[11], 16) << 24) | (int(rec_data[12], 16) << 16) | (
                    int(rec_data[13], 16) << 8) | (
                               int(rec_data[14], 16)))
            logging.info("最大数据容量:" + data_len.zfill(8))
            logging.info("DoIP Entity status information Test OK")
            return True
        else:
            logging.error("DoIP Entity status information Test failed")
            return False

    # 电源模式诊断信息测试
    def diag_power_mode_message_test(self):
        self.send_power_mode_information_request()
        rec_data = self.receive_power_mode_infomation_request()
        if rec_data[8] == '0x1':
            logging.info("Power mode is ready")
            logging.info("Diagnostic Power Mode Test OK")
            return True
        elif rec_data[8] == '0x0':
            logging.error("Power mode is NO ready")
            return False
        else:
            logging.error("Diagnostic Power Mode Test failed")
            return False

    # 测试地址是否正确
    def functioning_addressing_test(self):
        global_val.setvalue("DUT_Function_addressing_select", 1)
        self.diag_session_control('01')
        global_val.setvalue("DUT_Function_addressing_select", 0)
        t1 = int(round(time.time() * 1000))
        rec_data = self.receive_diagnostic_data()
        t2 = int(round(time.time() * 1000))

        if t2 - t1 < 2000:
            logging.info('time gap is:%d ms' % (t2 - t1))
            if rec_data[12] == '0x0':
                logging.info("Source Address:" + ' '.join(rec_data[8:10]))
                logging.info("Source Address:" + ' '.join(rec_data[10:12]))
                logging.info("Correct Address Test OK")
                return True
            else:
                logging.error("Correct Address Test Failed")
                return False
        else:
            logging.error('response time is over 2s, %d ms' % (t2 - t1))
            return False

    # 测试设备地址测试
    def another_tester_addressing_test(self):
        global_val.setvalue("tester_logic_addr_select", 3)
        self.diag_session_control('01')
        global_val.setvalue("tester_logic_addr_select", 0)
        t1 = int(round(time.time() * 1000))
        rec_data = self.receive_diagnostic_data()
        t2 = int(round(time.time() * 1000))

        if t2 - t1 < 2000:
            logging.info('time gap is:%d ms' % (t2 - t1))
            if rec_data[12] == '0x0':
                logging.info("Source Address:" + ' '.join(rec_data[8:10]))
                logging.info("Source Address:" + ' '.join(rec_data[10:12]))
                logging.info("Correct Address Test OK")
                return True
            else:
                logging.error("Correct Address Test Failed")
                return False
        else:
            logging.error('response time is over 2s, %d ms' % (t2 - t1))
            return False

    # 发送超过1496bytes的多条DoIP诊断消息
    def multi_diag_message_response_test(self):
        rec_data = self.multi_diag_message()
        if rec_data[12] == '0x0':
            logging.info("Diag message is positive response")
            return True
        else:
            logging.error("Diag message is negative response")
            return False

    # Extended session Control
    def diag_session_extended(self):
        logging.warning("Start Session Control - Extended")
        self.diag_session_control("03")
        rec_data_ack = self.receive_diagnostic_data()
        rec_data_replay = self.receive_diagnostic_data()
        if rec_data_ack[12] == "0x0" and rec_data_replay[13] == "0x3":
            logging.info("Extended Session Control OK")
            return True
        else:
            logging.error("Extended Session Control Failed")
            return False

    # EOL session Control
    def diag_session_eol(self):
        logging.warning("Start Session Control - EOL")
        self.diag_session_control("40")
        rec_data_ack = self.receive_diagnostic_data()
        rec_data_replay = self.receive_diagnostic_data()
        if rec_data_ack[12] == "0x0" and rec_data_replay[13] == "0x40":
            logging.info("EOL Session Control OK")
            return True
        else:
            logging.error("EOL Session Control Failed")
            return False

    # Programming session Control
    def diag_session_programming(self):
        logging.warning("Start Session Control - Programming")
        self.diag_session_control("02")
        rec_data_ack = self.receive_diagnostic_data()
        rec_data_replay = self.receive_diagnostic_data()
        if rec_data_ack[12] == "0x0" and rec_data_replay[13] == "0x2":
            logging.info("Programming Session Control OK")
            return True
        else:
            logging.error("Programming Session Control Failed")
            return False

    # ecu重启
    def cECU_reset(self):
        logging.warning("Start cECU Reset.")

        self.ecu_reset('01')

        rec_data_ack = self.receive_diagnostic_data()
        if rec_data_ack[12] != "0x0":
            logging.error("cECU Reset Failed")
            return False

        rec_data_replay = self.receive_diagnostic_data()
        if rec_data_replay[14] == "0x78":
            logging.info("Reply is Pending")
        else:
            return False

        t1 = int(round(time.time() * 1000))
        t2 = t1

        server_address = ('', 13400)
        sock = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP)
        sock.setblocking(False)
        sock.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
        sock.bind(server_address)
        sock.setsockopt(IPPROTO_IPV6, IPV6_MULTICAST_LOOP, 1)
        m_req = struct.pack("16s15s".encode('utf-8'), inet_pton(AF_INET6, "ff02::1"),
                            (chr(0) * 16).encode('utf-8'))
        print(m_req)
        sock.setsockopt(IPPROTO_IPV6, IPV6_JOIN_GROUP, m_req)

        announcement_cnt = 0
        logging.warning("Waiting Announcement...")
        while True:
            time.sleep(0.1)
            try:
                data, address = sock.recvfrom(1024)
                if 'fd53:7cb8:383:2::131' in address:
                    logging.warning('Announcement receive from {}'.format(address))

                    announcement_cnt += 1
            except BlockingIOError:
                t2 = int(round(time.time() * 1000))

            if t2 - t1 > 20000:
                sock.close()
                logging.error("Time Gap {}ms".format(t2 - t1))
                logging.error("Reset Time Out")
                return False

            if announcement_cnt == 3:
                sock.close()
                logging.info("Time Gap {}ms".format(t2 - t1))
                logging.info("Reset OK...")
                break

        self.ip_ver_init()
        self.connect_to_server()

        assert self.vir_no_payload(), "vehicle identified FAILED"

        assert self.routing_activation_request(0x00, 0x00000000), "routing activation FAILED"

        assert self.receive_diagnostic_data()[12:14] == ["0x51", "0x1"], "cECU Reset Failed"

        return True
