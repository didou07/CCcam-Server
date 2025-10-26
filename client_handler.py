import os
import time
import hashlib
from typing import Dict
from socket_handler import SocketHandler
from crypto import CCcamCrypto

class ClientHandler:
    """Handle individual client connections"""
    
    MSG_CLI_DATA = 0x00
    MSG_CW_ECM = 0x01
    MSG_KEEPALIVE = 0x06
    MSG_NEW_CARD = 0x07
    MSG_SRV_DATA = 0x08
    MSG_NEW_CARD_SIDINFO = 0x0F
    MSG_CW_NOK2 = 0xFF

    def __init__(self, sock, addr, server, logger, config):
        self.sock_handler = SocketHandler(sock, logger)
        self.sock = sock
        self.addr = addr
        self.server = server
        self.log = logger
        self.config = config

        self.encrypt = CCcamCrypto()
        self.decrypt = CCcamCrypto()

        self.username = None
        self.account = None
        self.ecm_processor = None

        self.running = True
        self.session_start = time.time()

        self.extended_mode = False
        self.cccam220 = False
        self.sleepsend = False

        self.ecm_count = 0
        self.ecm_found = 0
        self.keepalive_sent = 0
        self.keepalive_recv = 0

    def log_msg(self, component: str, level: str, msg: str):
        """OSCam-style logging"""
        if self.username:
            client_id = self.username
        else:
            client_id = "anonymous"

        thread_id = f"{(id(self) & 0xFFFFFFFF):08X}"

        level_char = 'c'
        if component in ['main', 'server']:
            level_char = 's'
        elif component in ['reader', 'emu', 'ecm']:
            level_char = 'r'

        full_msg = f"{thread_id} {level_char}   ({component}) {msg}"
        if level == "error":
            self.log.error(full_msg)
        elif level == "warning":
            self.log.warning(full_msg)
        else:
            if self.log.is_debug():
                self.log.debug(full_msg)
            else:
                self.log.info(full_msg)

    def log_hex(self, component: str, label: str, data: bytes, max_lines: int = 100):
        """Hex dump for debugging"""
        if not self.log.is_debug():
            return

        if label:
            self.log_msg(component, "debug", f"{label}:")
        for i in range(0, min(len(data), max_lines * 16), 16):
            chunk = data[i:i+16]
            hex_str = ' '.join(f"{b:02X}" for b in chunk)
            self.log_msg(component, "debug", f"  {hex_str}")

    def send_msg(self, cmd: int, payload: bytes = b''):
        """Send encrypted CCcam message"""
        length = len(payload)
        msg = bytearray(4 + length)
        msg[0] = 0x00
        msg[1] = cmd
        msg[2] = (length >> 8) & 0xFF
        msg[3] = length & 0xFF
        if length > 0:
            msg[4:] = payload
        
        try:
            self.encrypt.crypt(msg, 1)
            self.sock_handler.send_data(bytes(msg))
        except Exception as e:
            self.log_msg("cccam", "warning", f"send_msg error: {e}")
            self.running = False

        if self.log.is_debug():
            self.log_msg("cccam", "debug", "send:")
            self.log_hex("cccam", "", msg)

    def xor_seed(self, buf: bytearray):
        """XOR seed for authentication"""
        for i in range(8):
            buf[8 + i] = (i * buf[i]) & 0xFF
            if i < 5:
                buf[i] ^= b'CCcam'[i]

    def authenticate(self) -> bool:
        """Authenticate client"""
        try:
            seed = bytearray(os.urandom(16))
            self.sock_handler.send_data(seed)

            self.xor_seed(seed)
            hash_buf = bytearray(hashlib.sha1(seed).digest())

            self.encrypt.init(hash_buf)
            self.encrypt.crypt(seed, 0)

            self.decrypt.init(seed)
            self.decrypt.crypt(hash_buf, 0)

            recv_hash = self.sock_handler.recv_exact(20)
            if not recv_hash:
                return False
            recv_hash = bytearray(recv_hash)
            self.decrypt.crypt(recv_hash, 0)
            if recv_hash != hash_buf:
                self.log_msg("cccam", "info", "login failed: hash mismatch")
                return False

            recv_usr = self.sock_handler.recv_exact(20)
            if not recv_usr:
                return False
            recv_usr = bytearray(recv_usr)
            self.decrypt.crypt(recv_usr, 0)
            username = bytes(recv_usr).rstrip(b'\x00').decode('utf-8', errors='ignore')

            account = None
            for acc in self.server.users:
                if acc.username == username:
                    account = acc
                    break

            if not account or not account.enabled:
                self.log_msg("cccam", "info", f"login failed: invalid user '{username}'")
                return False

            pwd_buf = bytearray(account.password.encode())
            self.decrypt.crypt(pwd_buf, 1)

            recv_pwd = self.sock_handler.recv_exact(6)
            if not recv_pwd:
                return False
            recv_pwd = bytearray(recv_pwd)
            self.decrypt.crypt(recv_pwd, 0)
            if bytes(recv_pwd[1:6]) != b'Ccam\x00':
                self.log_msg("cccam", "info", "login failed: wrong password")
                return False

            self.username = username
            self.account = account
            self.ecm_processor = self.server.get_ecm_processor(account)

            if not self.ecm_processor:
                self.log_msg("cccam", "info", "login failed: no ECM processor")
                return False

            ack = bytearray(20)
            ack[0:6] = b'CCcam\x00'
            self.encrypt.crypt(ack, 1)
            self.sock_handler.send_data(bytes(ack))

            self.log_msg("cccam", "info", f"authenticated (user '{self.username}', au=off)")
            return True

        except Exception as e:
            self.log_msg("cccam", "error", f"Auth error: {e}")
            return False

    def handle_client_data(self, payload: bytes):
        """Handle client data message"""
        if len(payload) >= 61:
            try:
                partner = payload[29:61].rstrip(b'\x00').decode('ascii', errors='ignore')
                node_id_hex = self.server.node_id.hex().upper()
                self.log_msg("cccam", "info", f"client '{self.username}' ({node_id_hex}) running v{partner}")

                if '[EXT' in partner or ',EXT' in partner:
                    self.extended_mode = True
                    self.log_msg("cccam", "info", "extended ECM mode")
                if '[SID' in partner or ',SID' in partner:
                    self.cccam220 = True
                    self.log_msg("cccam", "info", "extra SID mode")
                if '[SLP' in partner or ',SLP' in partner:
                    self.sleepsend = True
                    self.log_msg("cccam", "info", "sleepsend")
            except Exception:
                pass

    def send_server_info(self):
        """Send server information to client"""
        node_id = self.server.node_id
        version = self.config.version
        build = self.config.build

        partner_string = f"PARTNER: CCcam Server {version}-{build} [EXT,SID,SLP]"

        data = bytearray(72)
        data[0:8] = node_id
        data[8:14] = version.encode()[:6].ljust(6, b'\x00')
        data[40:47] = build.encode()[:7].ljust(7, b'\x00')
        self.send_msg(self.MSG_SRV_DATA, bytes(data))
        self.send_msg(0xFE, partner_string.encode())

    def send_cards(self):
        """Send available cards to client"""
        if not self.ecm_processor:
            return
        cards = self.ecm_processor.get_all_cards()
        for idx, card in enumerate(cards):
            self._send_card(idx, card)
        self.log_msg("cccam", "info", f"shared {len(cards)} cards")

    def _send_card(self, idx: int, card: Dict):
        """Send single card information"""
        caid = card["caid"]
        providers = card.get("providers", [0])
        share_id = 0x64 + idx
        msg_type = self.MSG_NEW_CARD_SIDINFO if self.cccam220 else self.MSG_NEW_CARD

        size = 4 + 4 + 2 + 1 + 1 + 8 + 1 + (len(providers) * 4) + 1 + 8
        data = bytearray(size)
        pos = 0
        data[pos:pos+4] = share_id.to_bytes(4, 'big'); pos += 4
        data[pos:pos+4] = share_id.to_bytes(4, 'big'); pos += 4
        data[pos:pos+2] = caid.to_bytes(2, 'big'); pos += 2
        data[pos] = 0x00; pos += 1
        data[pos] = 0x0A; pos += 1
        pos += 8
        data[pos] = len(providers); pos += 1
        for prov in providers:
            data[pos:pos+4] = prov.to_bytes(4, 'big'); pos += 4
        data[pos] = 0x01; pos += 1
        data[pos:pos+8] = self.server.node_id
        self.send_msg(msg_type, bytes(data))

    def handle_ecm(self, payload: bytes):
        """Handle ECM request"""
        if len(payload) < 13:
            return

        caid = int.from_bytes(payload[0:2], 'big')
        srvid = int.from_bytes(payload[10:12], 'big')
        ecm_len = payload[12]
        ecm = payload[13:13+ecm_len] if len(payload) >= 13+ecm_len else payload[13:]

        self.ecm_count += 1
        self.log_msg("cccam", "info", f"ECM request from client: caid {caid:04X} srvid {srvid:04X}({srvid}) prid 000000")
        self.log_hex("ecm", "get cw for ecm", ecm)

        start = time.time()
        cw, reader_label = self.ecm_processor.process_ecm(caid, srvid, ecm, self.account.group) if self.ecm_processor else (None, None)
        ms = (time.time() - start) * 1000

        if cw and len(cw) == 16:
            self.ecm_found += 1
            self.log_msg("ecm", "info", f"{self.username} ({caid:04X}:{srvid:04X}): found (by {reader_label}) ({ms:.0f} ms)")
            self.log_hex("ecm", "cw", cw)
            self._send_cw_ok(caid, srvid, cw)
        else:
            self.log_msg("ecm", "info", f"{self.username} ({caid:04X}:{srvid:04X}): not found ({ms:.0f} ms)")
            self._send_cw_nok(caid, srvid)

    def _send_cw_ok(self, caid: int, srvid: int, cw: bytes):
        """Send successful CW response"""
        resp = bytearray(20)
        resp[0:2] = caid.to_bytes(2, 'big')
        resp[2:4] = srvid.to_bytes(2, 'big')
        resp[4:20] = cw
        self.send_msg(self.MSG_CW_ECM, bytes(resp))

    def _send_cw_nok(self, caid: int, srvid: int):
        """Send failed CW response"""
        resp = bytearray(4)
        resp[0:2] = caid.to_bytes(2, 'big')
        resp[2:4] = srvid.to_bytes(2, 'big')
        self.send_msg(self.MSG_CW_NOK2, bytes(resp))

    def handle(self):
        """Main client handler loop"""
        try:
            self.sock.settimeout(None)

            if not self.authenticate():
                return

            if not self.server.check_connection_limit(self.account):
                self.log_msg("cccam", "info", "connection limit reached")
                return

            self.server.register_client(self.username)

            while self.running:
                header = self.sock_handler.recv_exact(4)
                if not header:
                    break

                header = bytearray(header)
                self.decrypt.crypt(header, 0)
                cmd = header[1]
                length = (header[2] << 8) | header[3]

                payload = b''
                if length > 0:
                    payload = self.sock_handler.recv_exact(length)
                    if not payload:
                        break
                    payload = bytearray(payload)
                    self.decrypt.crypt(payload, 0)

                self.log_msg("cccam", "debug", f"parse_msg={cmd}")

                if cmd == self.MSG_CLI_DATA:
                    self.handle_client_data(bytes(payload))
                    self.send_msg(self.MSG_CLI_DATA, b'')
                    self.send_server_info()
                    self.send_cards()

                elif cmd == self.MSG_KEEPALIVE:
                    self.keepalive_recv += 1
                    self.log_msg("cccam", "info", "keepalive")
                    self.send_msg(self.MSG_KEEPALIVE, b'')

                elif cmd == self.MSG_CW_ECM:
                    self.handle_ecm(bytes(payload))

                elif cmd == 0xFE:
                    pass

                else:
                    if self.log.is_debug():
                        self.log_msg("cccam", "debug", f"parse_msg={cmd} (unknown)")

        except Exception as e:
            self.log_msg("cccam", "error", f"Handler error: {e}")

        finally:
            self.running = False
            self.sock_handler.close()

            if self.username:
                self.server.unregister_client(self.username)
                dur = time.time() - self.session_start
                if self.log.is_debug():
                    self.log_msg("cccam", "info", f"connection closed by remote server, n=-1.")
                else:
                    self.log_msg("cccam", "info", f"disconnected: reason close")
