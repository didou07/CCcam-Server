from typing import Optional, List

try:
    from Crypto.Cipher import DES3
    TVCAS_AVAILABLE = True
except ImportError:
    TVCAS_AVAILABLE = False
    print("Warning: pycryptodome not installed. TVCAS reader disabled.")
    print("Install: pip install pycryptodome")

MASTER_KEY_SIZE = 32
BLOCK_SIZE = 8


class TVCASReader:
    """TVCAS protocol reader for ECM decryption"""
    
    def __init__(self, label: str, master_key: str, caid_list: list, group: int = 1, logger=None):
        self.label = label
        self.protocol = "tvcas"
        self.caid_list = caid_list
        self.group = group
        self.log = logger
        self.enabled = TVCAS_AVAILABLE
        
        if not TVCAS_AVAILABLE:
            self.master_key = None
            return
        
        # Parse master key (remove colons and spaces)
        clean_key = master_key.replace(":", "").replace(" ", "").strip()
        
        if len(clean_key) != 64:
            raise ValueError(f"Master key must be 64 hex chars, got {len(clean_key)}")
        
        try:
            self.master_key = bytes.fromhex(clean_key)
        except ValueError as e:
            raise ValueError(f"Invalid hex in master key: {e}")
        
        if len(self.master_key) != MASTER_KEY_SIZE:
            raise ValueError(f"Master key must be {MASTER_KEY_SIZE} bytes")
        
        if self.log:
            self.log.info(f"TVCAS reader '{label}' initialized (CAIDs: {self._format_caids()})")
    
    def _format_caids(self) -> str:
        """Format CAID list for display"""
        if not self.caid_list:
            return "ALL"
        return ",".join(f"{c:04X}" for c in self.caid_list[:5])
    
    def prepare_3des_key(self, key_part: bytes) -> bytes:
        """Prepare 24-byte 3DES key from 16-byte key part"""
        full_key = bytearray(24)
        full_key[0:16] = key_part[0:16]
        full_key[16:24] = key_part[0:8]
        return bytes(full_key)
    
    def decrypt_3des_ecb(self, encrypted_data: bytes, key_part: bytes) -> Optional[bytes]:
        """Decrypt data using 3DES ECB mode"""
        if not TVCAS_AVAILABLE:
            return None
        
        try:
            full_key = self.prepare_3des_key(key_part)
            cipher = DES3.new(full_key, DES3.MODE_ECB)
            
            # Pad data to block size
            padded_len = ((len(encrypted_data) + BLOCK_SIZE - 1) // BLOCK_SIZE) * BLOCK_SIZE
            padded_data = encrypted_data.ljust(padded_len, b'\x00')
            
            decrypted = cipher.decrypt(padded_data)
            return decrypted[:len(encrypted_data)]
        except Exception as e:
            if self.log:
                self.log.error(f"TVCAS decrypt error: {e}")
            return None
    
    def process_ecm(self, caid: int, srvid: int, ecm: bytes) -> Optional[bytes]:
        """
        Process ECM and return CW (control word)
        ECM format: [table][6 bytes header][encrypted payload]
        """
        if not self.enabled or not self.master_key:
            return None
        
        # Check CAID filter
        if self.caid_list and caid not in self.caid_list:
            return None
        
        if len(ecm) < 7:
            if self.log:
                self.log.debug(f"TVCAS ECM too short: {len(ecm)} bytes")
            return None
        
        table = ecm[0]
        encrypted_payload = ecm[7:]
        
        if len(encrypted_payload) < 20:
            if self.log:
                self.log.debug(f"TVCAS payload too short: {len(encrypted_payload)} bytes")
            return None
        
        # Select key part based on table
        if table == 0x81:
            key_part = self.master_key[16:32]
        else:
            key_part = self.master_key[0:16]
        
        # Decrypt payload
        decrypted = self.decrypt_3des_ecb(encrypted_payload, key_part)
        if not decrypted or len(decrypted) < 20:
            return None
        
        # Extract CW (control word)
        cw = bytearray(16)
        cw[0:8] = decrypted[4:12]
        cw[8:16] = decrypted[12:20]

        
        if self.log:
            self.log.debug(f"TVCAS decrypt success: {caid:04X}:{srvid:04X} table={table:02X}")
        
        return bytes(cw)
    
    def get_cards(self) -> List[dict]:
        """Get available cards"""
        cards = []
        for caid in self.caid_list:
            cards.append({"caid": caid, "providers": [0], "srvid": 0})
        return cards
