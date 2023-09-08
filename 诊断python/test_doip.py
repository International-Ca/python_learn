import time
import pytest
import logging
import re
import os
import subprocess
import sys
from socket import *
import struct

sys.path.append(os.path.dirname(os.path.realpath(__file__)))
import doip
import global_val
from base.pytest_base.testbase import TestBase
from base.utils.control.env import Env
from base.utils.shell.platform.base_cmd import ShellListener
from base.utils.shell.platform.qnx_cmd import Commands


class dcos_mcu_shell_listener(ShellListener):
    def __init__(self, logger, timeout, expect_result=None):
        super().__init__(logger)
        self._logs = []
        self._logs_str = ''
        self.timeout = timeout
        self.start_time = time.time()
        self.result = False
        self.expect_result = expect_result

    def on_stdout(self, stdin, line):
        line = line.encode('utf-8').decode('utf-8')
        # logging.info(line)
        # if self.expect_result and self.expect_result in line:
        #     self.result = True
        self._logs.append(line)
        self._logs_str = self._logs_str + line
        if time.time() - self.start_time > self.timeout:
            return False
        return True

    def get_result(self):
        return self.result

    def get_logs(self):
        return self._logs

    def get_logs_str(self):
        return self._logs_str


class TestDoIP(TestBase):

    def setup(self):
        # SimTestInterface.set_env(self.env)
        # self.env.enterAtMode()
        # logging.info("enter setup")
        time.sleep(1)

    def teardown(self):
        # SimTestInterface.clear_env()
        # self.env.leaveAtMode()
        # logging.info("leave set down")
        time.sleep(1)

    def setup_class(self):
        # self.env = Env()
        # self.cmd = Commands(launch_cfg="/etc/dcoslaunch/tpv1/offline.launch",
        #                     ssh_args=('192.168.1.101', 'root', 'Auto@418', "dji"))
        self.doip = doip.DoIP()
        pass

    # def teardown_class(self):
    # self.env.leaveAtMode()
    # self.env.serialConnection.close()

    # Incorrect Pattern Format Test
    def test_rhp_340594(self, case_id):
        self.describe("Test case {} Incorrect Pattern Format Test ".format(case_id))
        self.doip.ip_ver_init()
        self.doip.connect_to_server()

        assert self.doip.vir_no_payload(), "vehicle identified FAILED"
        self.append_case_step_vp(case_id=case_id, step=1, result='passed', note='vehicle identified ok.')

        assert self.doip.routing_activation_request(0x00, 0x00000000), "routing activation FAILED"
        self.append_case_step_vp(case_id=case_id, step=2, result='passed', note='routing activation OK.')

        assert self.doip.incorrect_pattern_format_test(), "Incorrect Pattern_Format Test Failed"
        self.append_case_step_vp(case_id=case_id, step=3, result='passed', note='Incorrect Pattern_Format Test OK.')

    # Unknown_Payload_Type Test
    def test_rhp_340608(self, case_id):
        self.describe("Test case {} Unknown_Payload_Type Test ".format(case_id))
        self.doip.ip_ver_init()
        self.doip.connect_to_server()

        assert self.doip.vir_no_payload(), "vehicle identified FAILED"
        self.append_case_step_vp(case_id=case_id, step=1, result='passed', note='vehicle identified ok.')

        assert self.doip.routing_activation_request(0x00, 0x00000000), "routing activation FAILED"
        self.append_case_step_vp(case_id=case_id, step=2, result='passed', note='routing activation OK.')

        assert self.doip.unkown_payload_type_test(), "Unknown_Payload_Type Test Failed"
        self.append_case_step_vp(case_id=case_id, step=3, result='passed', note='Unknown_Payload_Type Test OK.')

    # Message_Too_Large Test
    def test_rhp_340609(self, case_id):
        self.describe("Test case {} Message_Too_Large Test ".format(case_id))
        self.doip.ip_ver_init()
        self.doip.connect_to_server()

        assert self.doip.vir_no_payload(), "vehicle identified FAILED"
        self.append_case_step_vp(case_id=case_id, step=1, result='passed', note='vehicle identified ok.')

        assert self.doip.routing_activation_request(0x00, 0x00000000), "routing activation FAILED"
        self.append_case_step_vp(case_id=case_id, step=2, result='passed', note='routing activation OK.')

        assert self.doip.message_too_large_test(), 'Message_Too_Large Test Failed'
        self.append_case_step_vp(case_id=case_id, step=3, result='passed', note='Message_Too_Large Test Failed OK.')

    # Invalid Payload Length Test
    def test_rhp_340611(self, case_id):
        self.describe("Test case {} Invalid Payload Length Test ".format(case_id))
        self.doip.ip_ver_init()
        self.doip.connect_to_server()

        self.doip.send_vehicle_identification_request()
        rec_data = self.doip.receive_vehicle_identification()
        assert rec_data[2] == '0x0' and rec_data[3] == '0x4', "No reponse"  # VIN码目前是固定的，故不做判断
        VIN = rec_data[8:25]

        assert self.doip.invalid_payload_length_VIN_test(VIN), 'NACK Code Wrong'
        self.append_case_step_vp(case_id=case_id, step=1, result='passed', note='NACK Code OK.')

        assert self.doip.vir_no_payload(), "vehicle identified FAILED"
        self.append_case_step_vp(case_id=case_id, step=2, result='passed', note='vehicle identified ok.')

        assert self.doip.routing_activation_request(0x00, 0x00000000), "routing activation FAILED"
        self.append_case_step_vp(case_id=case_id, step=3, result='passed', note='routing activation OK.')

        assert self.doip.invalid_payload_length_Diag_message_test(), 'Invalid_Payload_length Test Fail'
        self.append_case_step_vp(case_id=case_id, step=4, result='passed', note='Invalid_Payload_length Test OK.')

    # VIR_No_payload Test
    def test_rhp_340614(self, case_id):
        self.describe("Test case {} VIR_No_payload Test ".format(case_id))
        self.doip.ip_ver_init()
        self.doip.send_vehicle_identification_request()
        rec_data = self.doip.receive_vehicle_identification()
        assert rec_data[2] == '0x0' and rec_data[3] == '0x4', "No reponse"  # VIN码目前是固定的，故不做判断
        logging.info("Payload Length:" + rec_data[7])
        logging.info("VIN value:" + ' '.join(rec_data[8:25]))
        logging.info("Logical Address:" + ' '.join(rec_data[25:27]))
        logging.info("EID value:" + ' '.join(rec_data[27:33]))
        logging.info("GID value:" + ' '.join(rec_data[33:39]))
        logging.info("Future Action Required:" + rec_data[39])
        self.append_case_step_vp(case_id=case_id, step=1, result='passed', note='VIR_No_payload Test OK.')

    # VIR_request_With_EID Test
    def test_rhp_340619(self, case_id):
        self.describe("Test case {} VIR_request_With_EID Test ".format(case_id))
        self.doip.ip_ver_init()

        self.doip.send_vehicle_identification_request()
        rec_data = self.doip.receive_vehicle_identification()
        assert rec_data[2] == '0x0' and rec_data[3] == '0x4', "No reponse"
        EID = rec_data[27:33]
        assert self.doip.vir_with_eid_test(EID), 'Vir With Eid Test Failed'
        self.append_case_step_vp(case_id=case_id, step=1, result='passed', note='Vir With Eid Test OK.')

    # VIR_request_With_VIN Test
    def test_rhp_340620(self, case_id):
        self.describe("Test case {} VIR_request_With_VIN Test ".format(case_id))
        self.doip.ip_ver_init()

        self.doip.send_vehicle_identification_request()
        rec_data = self.doip.receive_vehicle_identification()
        assert rec_data[2] == '0x0' and rec_data[3] == '0x4', "No reponse"
        VIN = rec_data[8:25]
        logging.warning(VIN)

        assert self.doip.vir_with_vin_test(VIN), 'Vir With Eid Test Failed'
        self.append_case_step_vp(case_id=case_id, step=1, result='passed', note='Vir With VIN Test OK.')

    # VIR with Wrong EID Test
    def test_rhp_340621(self, case_id):
        self.describe("Test case {} VIR with Wrong EID Test".format(case_id))
        self.doip.ip_ver_init()

        assert self.doip.vir_with_wrong_eid_test(), 'Vir With Wrong Eid Test Failed'
        self.append_case_step_vp(case_id=case_id, step=1, result='passed', note='Vir With Wrong EID Test OK.')

    # VIR with Wrong VIN Test
    def test_rhp_340622(self, case_id):
        self.describe("Test case {} VIR with Wrong VIN Test".format(case_id))
        self.doip.ip_ver_init()

        assert self.doip.vir_with_wrong_vin_test(), 'Vir With Wrong VIN Test Failed'
        self.append_case_step_vp(case_id=case_id, step=1, result='passed', note='Vir With Wrong VIN Test OK.')

    # Vehicle Announcement Test
    def test_rhp_340623(self, case_id):
        self.describe("Test case {} Vehicle Announcement Test".format(case_id))
        self.doip.ip_ver_init()
        self.doip.connect_to_server()

        assert self.doip.vir_no_payload(), "vehicle identified FAILED"
        self.append_case_step_vp(case_id=case_id, step=1, result='passed', note='vehicle identified ok.')

        assert self.doip.routing_activation_request(0x00, 0x00000000), "routing activation FAILED"
        self.append_case_step_vp(case_id=case_id, step=2, result='passed', note='routing activation OK.')

        assert self.doip.diag_session_extended(), "Extended Session Control Failed"
        self.append_case_step_vp(case_id=case_id, step=3, result='passed', note='Extended Session Control OK.')

        assert self.doip.diag_session_programming(), "Programming Session Control Failed"
        self.append_case_step_vp(case_id=case_id, step=4, result='passed', note='Programming Session Control OK.')

        assert self.doip.cECU_reset(), "Vehicle Announcement Failed"
        self.append_case_step_vp(case_id=case_id, step=5, result='passed', note='Vehicle Announcement OK.')

        assert self.doip.vir_no_payload(), 'Vir With Eid Test Failed'
        self.append_case_step_vp(case_id=case_id, step=6, result='passed', note='Vir With VIN Test OK.')

    # Routing Activation Pass Test
    def test_rhp_340624(self, case_id):
        self.describe("Test case {} Routing Activation Pass Test ".format(case_id))
        self.doip.ip_ver_init()
        self.doip.connect_to_server()

        assert self.doip.vir_no_payload(), "vehicle identified FAILED"
        self.append_case_step_vp(case_id=case_id, step=1, result='passed', note='vehicle identified ok.')

        assert self.doip.routing_activation_request(0x00, 0x00000000), "routing activation pass FAILED"
        self.append_case_step_vp(case_id=case_id, step=2, result='passed', note='routing activation PASS.')

    # Unknown Source Address Test
    def test_rhp_340627(self, case_id):
        self.describe("Test case {} Unknown Source Address Test ".format(case_id))
        self.doip.ip_ver_init()
        self.doip.connect_to_server()

        assert self.doip.unknown_tester_addr_vir_test(), "vehicle identified FAILED"
        self.append_case_step_vp(case_id=case_id, step=1, result='passed', note='vehicle identified ok.')

        assert self.doip.unknown_tester_addr_routing_test(), "Routing Activation failed,unknown tester addr routing test failed"
        self.append_case_step_vp(case_id=case_id, step=2, result='passed', note='unknown tester addr routing test ok.')

    # Mismatch Source Address Test
    def test_rhp_340629(self, case_id):
        self.describe("Test case {} Mismatch Source Address Test ".format(case_id))
        self.doip.ip_ver_init()
        self.doip.connect_to_server()

        assert self.doip.vir_no_payload(), "vehicle identified FAILED"
        self.append_case_step_vp(case_id=case_id, step=1, result='passed', note='vehicle identified ok.')

        assert self.doip.routing_activation_request(0x00, 0x00000000), "routing activation pass FAILED"
        self.append_case_step_vp(case_id=case_id, step=2, result='passed', note='routing activation PASS.')

        assert self.doip.second_address_routing_activation_request(0x00, 0x00000000), "routing activation pass FAILED"
        self.append_case_step_vp(case_id=case_id, step=3, result='passed', note='routing activation PASS.')

    # SA Registered Test
    def test_rhp_340630(self, case_id):
        self.describe("Test case {} SA Registered Test".format(case_id))
        self.doip.ip_ver_init()
        self.doip.connect_to_server()

        assert self.doip.vir_no_payload(), "vehicle identified FAILED"
        self.append_case_step_vp(case_id=case_id, step=1, result='passed', note='vehicle identified ok.')

        assert self.doip.routing_activation_request(0x00, 0x00000000), "routing activation FAILED"
        self.append_case_step_vp(case_id=case_id, step=2, result='passed', note='routing activation OK.')

        assert self.doip.sa_registered_test(), "SA Registered FAILED"
        self.append_case_step_vp(case_id=case_id, step=3, result='passed', note='SA Registered OK.')

    # Invalid Activation Type Test
    def test_rhp_340631(self, case_id):
        self.describe("Test case {} Invalid Activation Type Test".format(case_id))
        self.doip.ip_ver_init()
        self.doip.connect_to_server()

        assert self.doip.vir_no_payload(), "vehicle identified FAILED"
        self.append_case_step_vp(case_id=case_id, step=1, result='passed', note='vehicle identified ok.')

        assert self.doip.invalid_action_type_test(0xFF, 0x00000000), "Invalid Activation Type Test FAILED"
        self.append_case_step_vp(case_id=case_id, step=2, result='passed', note='Invalid Activation Type Test OK.')

    # Diag Message Request and Positive Response
    def test_rhp_347571(self, case_id):
        self.describe("Test case {} Diag Message Request and Positive Response".format(case_id))
        self.doip.ip_ver_init()
        self.doip.connect_to_server()

        assert self.doip.vir_no_payload(), "vehicle identified FAILED"
        self.append_case_step_vp(case_id=case_id, step=1, result='passed', note='vehicle identified ok.')

        assert self.doip.routing_activation_request(0x00, 0x00000000), "routing activation FAILED"
        self.append_case_step_vp(case_id=case_id, step=2, result='passed', note='routing activation OK.')

        assert self.doip.diag_message_response_test(), "Diag message response failed"
        self.append_case_step_vp(case_id=case_id, step=3, result='passed', note='Diag message is positive response.')

    # Invalid Source Address Test
    def test_rhp_340634(self, case_id):
        self.describe("Test case {} Invalid Source Address Test ".format(case_id))
        self.doip.ip_ver_init()
        self.doip.connect_to_server()

        assert self.doip.vir_no_payload(), "vehicle identified FAILED"
        self.append_case_step_vp(case_id=case_id, step=1, result='passed', note='vehicle identified ok.')

        assert self.doip.routing_activation_request(0x00, 0x00000000), "routing activation FAILED"
        self.append_case_step_vp(case_id=case_id, step=2, result='passed', note='routing activation OK.')

        assert self.doip.invalid_source_address_test(), 'Invalid_Source_Address Test Failed'
        self.append_case_step_vp(case_id=case_id, step=3, result='passed', note='Invalid_Source_Address Test OK')

    # Unknown Target Address Test
    def test_rhp_340635(self, case_id):
        self.describe("Test case {} Unknown Target Address Test ".format(case_id))
        self.doip.ip_ver_init()
        self.doip.connect_to_server()

        assert self.doip.vir_no_payload(), "vehicle identified FAILED"
        self.append_case_step_vp(case_id=case_id, step=1, result='passed', note='vehicle identified ok.')

        assert self.doip.routing_activation_request(0x00, 0x00000000), "routing activation FAILED"
        self.append_case_step_vp(case_id=case_id, step=2, result='passed', note='routing activation OK.')

        assert self.doip.unkown_target_address_test(), 'Invalid_DUT_adder Test Failed'
        self.append_case_step_vp(case_id=case_id, step=3, result='passed', note='Invalid_DUT_adder Test OK.')

    # Alive Check Message Test
    def test_rhp_340636(self, case_id):
        self.describe("Test case {} Alive Check Message Test".format(case_id))
        self.doip.ip_ver_init()
        self.doip.connect_to_server()

        assert self.doip.vir_no_payload(), "vehicle identified FAILED"
        self.append_case_step_vp(case_id=case_id, step=1, result='passed', note='vehicle identified ok.')

        assert self.doip.routing_activation_request(0x00, 0x00000000), "routing activation FAILED"
        self.append_case_step_vp(case_id=case_id, step=2, result='passed', note='routing activation OK.')

        assert self.doip.alive_check_message_test(), "Alive Check Message Test Failed"
        self.append_case_step_vp(case_id=case_id, step=3, result='passed', note='Alive Check Message Test OK.')

    # DoIP Entity Status Information Message
    def test_rhp_340637(self, case_id):
        self.describe("Test case {} DoIP Entity Status Information Message".format(case_id))
        self.doip.ip_ver_init()

        assert self.doip.vir_no_payload(), "vehicle identified FAILED"
        self.append_case_step_vp(case_id=case_id, step=1, result='passed', note='vehicle identified ok.')

        assert self.doip.doip_entity_status_request(), "DoIP Entity status information Test failed"
        self.append_case_step_vp(case_id=case_id, step=2, result='passed',
                                 note='DoIP Entity status information Test ok.')

    # Diagnostic Power Mode Information Message Test
    def test_rhp_340638(self, case_id):
        self.describe("Test case {} Diagnostic Power Mode Information Message Test".format(case_id))
        self.doip.ip_ver_init()
        self.doip.connect_to_server()

        assert self.doip.vir_no_payload(), "vehicle identified FAILED"
        self.append_case_step_vp(case_id=case_id, step=1, result='passed', note='vehicle identified ok.')

        assert self.doip.diag_power_mode_message_test(), "Diagnostic Power Mode Test failed"
        self.append_case_step_vp(case_id=case_id, step=2, result='passed', note='Diagnostic Power Mode Test OK.')

    # T_TCP_General_Inactivity Test
    # 验证DUT通信停止后TCP_General_Inactivity是否满足需求规范要求，测试时长较长
    # 等待时长 t<5.5mins 器件均为积极响应，t大于等于5.5mins（330s）将产生否定响应
    # 预计此项测试时长在25.5 mins
    # 测试环境板子休眠间隔小于等待时间
    def test_rhp_340641(self, case_id):
        self.describe("Test case {} T_TCP_General_Inactivity Test".format(case_id))
        timer = 180
        self.doip.ip_ver_init()
        try:
            for i in range(10):
                logging.warning("-----LOOPING TIME = %d------" % i)

                assert self.doip.vir_no_payload(), "vehicle identified FAILED"
                self.append_case_step_vp(case_id=case_id, step=1, result='passed', note='vehicle identified ok.')

                self.doip.connect_to_server()

                assert self.doip.routing_activation_request(0x00, 0x00000000), "routing activation FAILED"
                self.append_case_step_vp(case_id=case_id, step=2, result='passed', note='routing activation OK.')

                assert self.doip.diag_message_response_test(), "Diag message response failed"
                self.append_case_step_vp(case_id=case_id, step=3, result='passed',
                                         note='Diag message is positive response.')

                logging.warning("--Waiting Time = %ds--" % timer)
                time.sleep(timer)
                timer = timer + 30

                assert self.doip.diag_message_response_test(), "Diag message response failed"
                self.append_case_step_vp(case_id=case_id, step=3, result='passed',
                                         note='Diag message is positive response.')

                self.doip._tcp_client.close()
                self.doip._ipv6_init()
        except Exception as e:
            logging.warning(e)

        if (timer - 30) >= 300:
            logging.info("Connection lost in %ds" % (timer - 30))
            self.append_case_step_vp(case_id=case_id, step=4, result='passed', note='T_TCP_General_Inactivity Test ok.')
        else:
            logging.error("Connection lost in %ds" % (timer - 30))
            assert (timer - 30) >= 300, "T_TCP_General_Inactivity Test Failed"

    # T_TCP_Initial_Inactivity Test
    def test_rhp_340646(self, case_id):
        self.describe("Test case {} T_TCP_Initial_Inactivity Test".format(case_id))
        self.doip.ip_ver_init()
        self.doip.connect_to_server()
        timer = 1

        assert self.doip.vir_no_payload(), "vehicle identified FAILED"
        self.append_case_step_vp(case_id=case_id, step=1, result='passed', note='vehicle identified ok.')

        try:
            for j in range(8):
                logging.info("等待时长%f 秒" % (timer))
                time.sleep(timer)
                timer = timer + 0.2
                assert self.doip.routing_activation_request(0x00, 0x00000000), "routing activation FAILED"
                self.append_case_step_vp(case_id=case_id, step=2, result='passed', note='routing activation OK.')
                self.doip._tcp_client.close()
                self.doip._ipv6_init()
                self.doip.connect_to_server()
        except Exception as e:
            logging.error(e)
            if (timer - 0.2) >= 2:
                logging.info("没有收到响应报文的等待时间为%s秒,小于2秒有响应" % (timer - 0.2))
                self.append_case_step_vp(case_id=case_id, step=3, result='passed',
                                         note='T_TCP_Initial_Inactivity Test ok.')
            else:
                logging.error("没有收到响应报文的等待时间为%s秒" % (timer - 0.2))
                assert e == '', "T_TCP_Initial_Inactivity Test Failed"

    # T_TCP_Alive_Check Test
    # Two sockets,when both of them are connected ,the one connected before will be lost if no alive response received
    def test_rhp_340650(self, case_id):
        self.describe("Test case {} T_TCP_Alive_Check Test".format(case_id))
        timer = 0.1
        self.doip.ip_ver_init()
        try:
            for i in range(10):
                logging.warning("-----LOOPING TIME = %d------" % i)
                assert self.doip.vir_no_payload(), "vehicle identified FAILED"
                self.append_case_step_vp(case_id=case_id, step=1, result='passed', note='vehicle identified ok.')

                self.doip.connect_to_server()

                assert self.doip.routing_activation_request(0x00, 0x00000000), "routing activation FAILED"
                self.append_case_step_vp(case_id=case_id, step=2, result='passed', note='routing activation OK.')

                global_val.setvalue("tcp_client_select", 1)

                self.doip.connect_to_server()
                self.doip.send_routing_activation_request(0x00, 0x00000000)

                global_val.setvalue("tcp_client_select", 0)

                # trigger alive check request
                self.doip.receive_alive_request_tcp()

                time.sleep(timer)
                logging.warning("Waiting Time = %fs" % timer)
                timer = timer + 0.05

                self.doip.send_alive_response()

                global_val.setvalue("tcp_client_select", 1)

                rec_data = self.doip.receive_routing_activation()

                global_val.setvalue("tcp_client_select", 0)

                assert rec_data[12] == '0x3' or rec_data[12] == '0x10', "routine active ok"

                assert self.doip.diag_message_response_test(), "Diag message response failed"
                self.append_case_step_vp(case_id=case_id, step=3, result='passed',
                                         note='Diag message is positive response.')

                self.doip._tcp_client.close()

                self.doip._tcp_client1.close()

                self.doip._ipv6_init()

        except Exception as e:
            logging.warning(e)
            if (timer - 0.05) >= float(0.45):
                logging.info("Connection lost in %fs" % (timer - 0.05))
                self.append_case_step_vp(case_id=case_id, step=2, result='passed', note='T_TCP_Alive_Check Test ok.')
            else:
                logging.error("Connection lost in %fs" % (timer - 0.05))
                assert (timer - 0.05) >= float(0.45), "T_TCP_Alive_Check Test Failed"

    # Functioning Addressing Test
    def test_rhp_341089(self, case_id):
        self.describe("Test case {}  Functioning Addressing Test".format(case_id))
        self.doip.ip_ver_init()
        self.doip.connect_to_server()

        assert self.doip.vir_no_payload(), "vehicle identified FAILED"
        self.append_case_step_vp(case_id=case_id, step=1, result='passed', note='vehicle identified ok.')

        assert self.doip.routing_activation_request(0x00, 0x00000000), "routing activation FAILED"
        self.append_case_step_vp(case_id=case_id, step=2, result='passed', note='routing activation OK.')

        assert self.doip.functioning_addressing_test(), " Functioning Addressing Test Failed"
        self.append_case_step_vp(case_id=case_id, step=3, result='passed', note='Functioning Addressing Test OK.')
    
    # GID_Verify Test
    def test_rhp_341141(self, case_id):
        self.describe("Test case {} GID_Verify Test ".format(case_id))
        self.doip.ip_ver_init()
        self.doip.send_vehicle_identification_request()
        rec_data = self.doip.receive_vehicle_identification()
        assert rec_data[33:39] == ['0x1', '0x1', '0x1', '0x1', '0x1', '0x1'], "No reponse"  # VIN码目前是固定的，故不做判断
        logging.info("Payload Length:" + rec_data[7])
        logging.info("VIN value:" + ' '.join(rec_data[8:25]))
        logging.info("Logical Address:" + ' '.join(rec_data[25:27]))
        logging.info("EID value:" + ' '.join(rec_data[27:33]))
        logging.info("GID value:" + ' '.join(rec_data[33:39]))
        logging.info("Future Action Required:" + rec_data[39])
        self.append_case_step_vp(case_id=case_id, step=1, result='passed', note='VIR_No_payload Test OK.')

    # VIR_No_payload Test  *N
    def test_rhp_341145(self, case_id):
        self.describe("Test case {} VIR_No_payload Test ".format(case_id))
        self.doip.ip_ver_init()
        self.doip.connect_to_server()

        assert self.doip.vir_no_payload(), "vehicle identified FAILED"
        self.append_case_step_vp(case_id=case_id, step=1, result='passed', note='vehicle identified ok.')

        assert self.doip.routing_activation_request(0x00, 0x00000000), "routing activation FAILED"
        self.append_case_step_vp(case_id=case_id, step=2, result='passed', note='routing activation OK.')

        assert self.doip.multi_diag_message_response_test(), "Diag message response failed"
        self.append_case_step_vp(case_id=case_id, step=3, result='passed', note='Diag message is positive response.')

    # cECU reset
    def test_rhp_341365(self, case_id):
        self.describe("Test case {} cECU reset Test ".format(case_id))
        self.doip.ip_ver_init()
        self.doip.connect_to_server()

        assert self.doip.vir_no_payload(), "vehicle identified FAILED"
        self.append_case_step_vp(case_id=case_id, step=1, result='passed', note='vehicle identified ok.')

        assert self.doip.routing_activation_request(0x00, 0x00000000), "routing activation FAILED"
        self.append_case_step_vp(case_id=case_id, step=2, result='passed', note='routing activation OK.')

        assert self.doip.diag_session_extended(), "Extended Session Control Failed"
        self.append_case_step_vp(case_id=case_id, step=3, result='passed', note='Extended Session Control OK.')

        assert self.doip.diag_session_programming(), "Programming Session Control Failed"
        self.append_case_step_vp(case_id=case_id, step=4, result='passed', note='Programming Session Control OK.')

        self.doip.ecu_reset('01')
        t1 = int(round(time.time() * 1000))

        rec_data_ack = self.doip.receive_diagnostic_data()
        t2 = int(round(time.time() * 1000))

        if t2 - t1 < 7450:
            logging.info('Time Gap = %d <7450ms' % (t2 - t1))
        else:
            logging.error('Time Gap = %d > 7450ms' % (t2 - t1))

        assert rec_data_ack[12] == '0x0' and t2 - t1 < 7450, "Reset Diag message is negative response"
        self.append_case_step_vp(case_id=case_id, step=5, result='passed',
                                 note='Reset Diag message is positive response.')

        rec_data_replay = self.doip.receive_diagnostic_data()

        assert rec_data_replay[14] == '0x78', "Reset Diag message is negative response"
        self.append_case_step_vp(case_id=case_id, step=6, result='passed',
                                 note='Reset Diag message is positive response.')

        logging.info("Reset Diag message is positive response.")

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

        while True:
            time.sleep(0.5)
            try:
                data, address = sock.recvfrom(1024)
                if 'fd53:7cb8:383:2::131' in address:
                    logging.warning('recevied {} bytes from {}'.format(len(data), address))
                    announcement_cnt += 1
            except BlockingIOError:
                t2 = int(round(time.time() * 1000))
                logging.warning("no message")

            if t2 - t1 > 20000:
                sock.close()
                logging.error("Reset Time Out")
                return False

            if announcement_cnt == 3:
                sock.close()
                logging.info("Reset OK...")
                break
        self.append_case_step_vp(case_id=case_id, step=7, result='passed', note='cECU Reset ok')
        try:
            assert self.doip.routing_activation_request(0x00, 0x00000000), "routing activation FAILED"
            route_not_alive = False
            logging.error("routing activation Pass")
        except Exception as e:
            route_not_alive = True
            logging.error(e)

        assert route_not_alive, "Route still alive after reset"
        self.append_case_step_vp(case_id=case_id, step=8, result='passed', note='routing activation Failed.')

        self.doip.ip_ver_init()
        self.doip.connect_to_server()

        assert self.doip.routing_activation_request(0x00, 0x00000000), "routing activation FAILED"
        self.append_case_step_vp(case_id=case_id, step=9, result='passed', note='routing activation OK.cecu reset pass')

    # Another Tester Address Test
    def test_rhp_347509(self, case_id):
        self.describe("Test case {} Another Tester Address Test".format(case_id))
        self.doip.ip_ver_init()
        self.doip.connect_to_server()

        assert self.doip.vir_no_payload(), "vehicle identified FAILED"
        self.append_case_step_vp(case_id=case_id, step=1, result='passed', note='vehicle identified ok.')

        global_val.setvalue("tester_logic_addr_select", 3)

        assert self.doip.routing_activation_request(0x00, 0x00000000), "routing activation FAILED"
        self.append_case_step_vp(case_id=case_id, step=2, result='passed', note='routing activation OK.')

        assert self.doip.another_tester_addressing_test(), " Functioning Addressing Test Failed"
        self.append_case_step_vp(case_id=case_id, step=3, result='passed', note='Functioning Addressing Test OK.')


    # Tcp Numbert Test
    def test_rhp_355406(self, case_id):
        self.describe("Test case {} Tcp Number Test".format(case_id))
        self.doip.ip_ver_init()
        self.doip.connect_to_server()

        global_val.setvalue('tcp_client_select', 1)

        self.doip.connect_to_server()

        global_val.setvalue('tcp_client_select', 0)

        assert self.doip.vir_no_payload(), "vehicle identified FAILED"
        self.append_case_step_vp(case_id=case_id, step=1, result='passed', note='vehicle identified ok.')

        assert self.doip.routing_activation_request(0x00, 0x00000000), "routing activation FAILED"
        self.append_case_step_vp(case_id=case_id, step=2, result='passed', note='routing activation OK.')


