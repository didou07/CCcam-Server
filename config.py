import os
import configparser
from dataclasses import dataclass, field
from typing import List, Dict, Tuple


@dataclass
class ServerConfig:
    host: str = "0.0.0.0"
    port: int = 12340
    version: str = "2.0.11"
    build: str = "2892"
    max_clients: int = 100
    ecm_folder: str = "./ecm"
    log_folder: str = "./logs"
    log_level: str = "INFO"
    nodeid: str = ""


@dataclass
class UserAccount:
    username: str
    password: str
    enabled: bool = True
    max_connections: int = 0
    caid_list: List[int] = field(default_factory=list)
    group: int = 1
    keepalive: int = 1
    ecm_start: int = 15
    ecm_end: int = 23


@dataclass
class ReaderConfig:
    label: str
    protocol: str
    caid_list: List[int] = field(default_factory=list)
    group: int = 1
    key: str = ""
    ident_map: Dict = field(default_factory=dict)
    device: str = ""
    disablecrccws: int = 0


class ConfigManager:
    """Manage configuration files (OSCam-compatible)"""
    
    def __init__(self, config_file: str = "cccam.cfg"):
        self.config_file = config_file
        self.server_config = ServerConfig()
        self.users = []
        self.readers = []
    
    def load(self) -> Tuple[ServerConfig, List[UserAccount], List[ReaderConfig]]:
        """Load configuration"""
        print(f"\nLoading configuration from: {self.config_file}")
        
        if not os.path.exists(self.config_file):
            print(f"Config file not found, creating: {self.config_file}")
            self.create_default()
        
        config = configparser.ConfigParser()
        config.read(self.config_file, encoding='utf-8')
        
        # Load server config
        if "server" in config:
            s = config["server"]
            self.server_config.host = s.get("host", "0.0.0.0")
            self.server_config.port = int(s.get("port", "12340"))
            self.server_config.max_clients = int(s.get("max_clients", "100"))
            self.server_config.ecm_folder = s.get("ecm_folder", "./ecm")
            self.server_config.log_folder = s.get("log_folder", "./logs")
            self.server_config.log_level = s.get("log_level", "INFO")
            self.server_config.nodeid = s.get("nodeid", "")
        
        # Load users
        self.users = []
        for section in config.sections():
            if section.startswith("user:"):
                username = section[5:]
                u = config[section]
                
                caid_str = u.get("caid", "")
                caid_list = self._parse_caid_list(caid_str)
                
                user = UserAccount(
                    username=username,
                    password=u.get("password", ""),
                    enabled=u.get("enabled", "yes").lower() in ["yes", "true", "1"],
                    max_connections=int(u.get("max_connections", "0")),
                    caid_list=caid_list,
                    group=int(u.get("group", "1")),
                    keepalive=int(u.get("keepalive", "1")),
                    ecm_start=int(u.get("ecm_start", "15")),
                    ecm_end=int(u.get("ecm_end", "23"))
                )
                self.users.append(user)
        
        # Load readers
        self.readers = []
        for section in config.sections():
            if section.startswith("reader:"):
                label = section[7:]
                r = config[section]
                
                protocol = r.get("protocol", "ecmbin")
                caid_str = r.get("caid", "")
                caid_list = self._parse_caid_list(caid_str)
                
                reader = ReaderConfig(
                    label=label,
                    protocol=protocol,
                    caid_list=caid_list,
                    group=int(r.get("group", "1")),
                    key=r.get("key", ""),
                    device=r.get("device", ""),
                    disablecrccws=int(r.get("disablecrccws", "0"))
                )
                self.readers.append(reader)
        
        print(f"Configuration loaded successfully")
        print(f"  Server: {self.server_config.host}:{self.server_config.port}")
        print(f"  Users: {len(self.users)}")
        print(f"  Readers: {len(self.readers)}")
        
        return self.server_config, self.users, self.readers
    
    def _parse_caid_list(self, caid_str: str) -> List[int]:
        """Parse CAID list from string"""
        caid_list = []
        if caid_str.strip():
            for c in caid_str.split(","):
                c = c.strip()
                if c:
                    try:
                        caid_list.append(int(c, 16))
                    except:
                        pass
        return caid_list
    
    def create_default(self):
        """Create default configuration"""
        config = configparser.ConfigParser()
        
        config["server"] = {
            "host": "0.0.0.0",
            "port": "12340",
            "max_clients": "100",
            "ecm_folder": "./ecm",
            "log_folder": "./logs",
            "log_level": "INFO",
            "nodeid": ""
        }
        
        config["user:test"] = {
            "password": "test",
            "enabled": "yes",
            "max_connections": "0",
            "caid": "0603,0B01,0500,0604",
            "group": "1",
            "keepalive": "1",
            "ecm_start": "15",
            "ecm_end": "23"
        }
        
        config["reader:binary"] = {
            "protocol": "ecmbin",
            "caid": "0500,0604,0603,0B01",
            "group": "1"
        }
        
        config["reader:tvcas1"] = {
            "protocol": "tvcas",
            "caid": "0500,0604,0D00,0E00,1010,1801,2600,2602,2610,0603",
            "group": "1",
            "key": "9F3C17A2B5D0481E6A7B92F4C8E05D13A1B9E4F276C3058D4ACF19B08273DE5F"
        }
        
        with open(self.config_file, 'w', encoding='utf-8') as f:
            f.write("# CCcam Server Configuration (OSCam-style)\n\n")
            config.write(f)
