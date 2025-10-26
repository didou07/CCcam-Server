import os
import socket
import threading
from typing import List, Dict, Optional
from logger import Logger
from ecm_processor import ECMProcessor
from client_handler import ClientHandler
from config import ServerConfig, UserAccount, ReaderConfig
from readers import ECMBinReader, TVCASReader, TVCAS_AVAILABLE, EmulatorReader

class CCcamServer:
    """Main CCcam Server"""
    
    def __init__(self, config: ServerConfig, users: List[UserAccount], readers: List[ReaderConfig]):
        self.config = config
        self.users = users
        self.reader_configs = readers
        self.log = Logger("CCcam", config.log_level)
        
        if config.nodeid:
            try:
                self.node_id = bytes.fromhex(config.nodeid.replace(":", ""))[:8].ljust(8, b'\x00')
            except:
                self.node_id = os.urandom(8)
        else:
            self.node_id = os.urandom(8)
        
        self.connections: Dict[str, int] = {}
        self.lock = threading.Lock()
        self.ecm_processors: Dict[str, ECMProcessor] = {}
        
        self.log.info("=" * 70)
        self.log.info(f"CCcam Server v{config.version} Build {config.build}")
        self.log.info(f"NodeID: {self.node_id.hex().upper()}")
        self.log.info(f"Users: {len(users)}")
        self.log.info(f"Readers: {len(readers)}")
        self.log.info("=" * 70)
        
        self.initialize_readers()
    
    def initialize_readers(self):
        """Initialize all configured readers"""
        self.log.info("Initializing readers...")
        
        for reader_cfg in self.reader_configs:
            try:
                if reader_cfg.protocol == "ecmbin":
                    reader = ECMBinReader(
                        self.config.ecm_folder,
                        15,
                        23,
                        reader_cfg.caid_list,
                        self.log
                    )
                    self._register_reader(reader, reader_cfg.group)
                
                elif reader_cfg.protocol == "tvcas":
                    if not TVCAS_AVAILABLE:
                        self.log.warning(f"TVCAS reader '{reader_cfg.label}' skipped: pycryptodome not installed")
                        continue
                    
                    if not reader_cfg.key:
                        self.log.error(f"TVCAS reader '{reader_cfg.label}' missing key")
                        continue
                    
                    reader = TVCASReader(
                        reader_cfg.label,
                        reader_cfg.key,
                        reader_cfg.caid_list,
                        reader_cfg.group,
                        self.log
                    )
                    self._register_reader(reader, reader_cfg.group)
                
                elif reader_cfg.protocol == "emu":
                    reader = EmulatorReader(
                        reader_cfg.label,
                        reader_cfg.caid_list,
                        {},
                        reader_cfg.group,
                        self.log
                    )
                    self._register_reader(reader, reader_cfg.group)
                
                else:
                    self.log.warning(f"Unknown protocol: {reader_cfg.protocol}")
            
            except Exception as e:
                self.log.error(f"Failed to initialize reader '{reader_cfg.label}': {e}")
        
        self.log.info(f"Readers initialized: {sum(len(p.readers) for p in self.ecm_processors.values())}")
    
    def _register_reader(self, reader, group: int):
        """Register reader to appropriate ECM processor"""
        key = f"group_{group}"
        if key not in self.ecm_processors:
            self.ecm_processors[key] = ECMProcessor(self.log)
        self.ecm_processors[key].add_reader(reader)
    
    def get_ecm_processor(self, account: UserAccount) -> Optional[ECMProcessor]:
        """Get ECM processor for user account"""
        key = f"group_{account.group}"
        return self.ecm_processors.get(key)
    
    def check_connection_limit(self, account: UserAccount) -> bool:
        """Check if user can connect"""
        if account.max_connections == 0:
            return True
        with self.lock:
            current = self.connections.get(account.username, 0)
            return current < account.max_connections
    
    def register_client(self, username: str):
        """Register connected client"""
        with self.lock:
            self.connections[username] = self.connections.get(username, 0) + 1
            self.log.info(f"{username}: Connections: {self.connections[username]}")
    
    def unregister_client(self, username: str):
        """Unregister disconnected client"""
        with self.lock:
            if username in self.connections:
                self.connections[username] -= 1
                if self.connections[username] <= 0:
                    del self.connections[username]
    
    def handle_client(self, sock, addr):
        """Handle client connection"""
        handler = ClientHandler(sock, addr, self, self.log, self.config)
        handler.handle()
    
    def start(self):
        """Start server"""
        os.makedirs(self.config.ecm_folder, exist_ok=True)
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((self.config.host, self.config.port))
        srv.listen(self.config.max_clients)
        
        self.log.info("=" * 70)
        self.log.info(f"Listening on {self.config.host}:{self.config.port}")
        self.log.info("Ready for connections")
        self.log.info("=" * 70)
        
        try:
            while True:
                sock, addr = srv.accept()
                sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                self.log.info(f"New connection from {addr[0]}:{addr[1]}")
                t = threading.Thread(target=self.handle_client, args=(sock, addr), daemon=True)
                t.start()
        except KeyboardInterrupt:
            self.log.info("\nShutdown requested")
        finally:
            srv.close()
            self.log.info("Server stopped")
