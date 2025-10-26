import os
import glob
from typing import List, Dict, Tuple, Optional

class ECMBinReader:
    """Binary ECM file reader"""
    
    def __init__(self, folder: str, ecm_start: int, ecm_end: int, 
                 caid_filter: List[int], logger):
        self.folder = folder
        self.ecm_start = ecm_start
        self.ecm_end = ecm_end
        self.ecm_size = ecm_end - ecm_start
        self.caid_filter = caid_filter
        self.log = logger
        self.protocol = "ecmbin"
        self.label = "binary"
        
        self.db: Dict[Tuple[int, int], List[Tuple[bytes, bytes]]] = {}
        self.providers: Dict[int, set] = {}
        self.cards: List[Dict] = []
        
        self.load()
    
    def load(self):
        """Load all binary ECM files"""
        os.makedirs(self.folder, exist_ok=True)
        self.db.clear()
        self.providers.clear()
        self.cards.clear()
        
        files = glob.glob(os.path.join(self.folder, "*.bin"))
        self.log.info(f"Loading ECM database from {self.folder}")
        
        for filepath in files:
            self._load_file(filepath)
        
        self._build_cards()
        total = sum(len(v) for v in self.db.values())
        self.log.info(f"Database: {len(self.cards)} cards, {len(self.db)} keys, {total} CW entries")
    
    def _load_file(self, filepath: str):
        """Load single binary file"""
        filename = os.path.basename(filepath)
        if "@" not in filename or not filename.endswith(".bin"):
            return
        
        try:
            base = filename[:-4]
            caid_str, rest = base.split("@", 1)
            caid = int(caid_str, 16)
            
            if self.caid_filter and caid not in self.caid_filter:
                return
            
            provider = 0
            if ":" in rest:
                prov_str, sid_str = rest.split(":", 1)
                provider = int(prov_str, 16)
                srvid = int(sid_str, 16)
            else:
                srvid = int(rest, 16)
            
            with open(filepath, "rb") as f:
                data = f.read()
            
            entry_size = self.ecm_size + 16
            if len(data) % entry_size != 0:
                return
            
            entries = []
            for i in range(len(data) // entry_size):
                off = i * entry_size
                ecm_slice = data[off:off + self.ecm_size]
                cw = data[off + self.ecm_size:off + entry_size]
                entries.append((ecm_slice, cw))
            
            key = (caid, srvid)
            self.db[key] = entries
            
            if caid not in self.providers:
                self.providers[caid] = set()
            if provider:
                self.providers[caid].add(provider)
            
            if self.log.is_debug():
                self.log.debug(f"Loaded {filename}: {len(entries)} entries")
        except Exception as e:
            self.log.error(f"Error loading {filename}: {e}")
    
    def _build_cards(self):
        """Build card list from database"""
        seen = set()
        for (caid, srvid) in self.db.keys():
            if caid in seen:
                continue
            seen.add(caid)
            providers = list(self.providers.get(caid, [0]))
            self.cards.append({"caid": caid, "providers": providers, "srvid": srvid})
    
    def process_ecm(self, caid: int, srvid: int, ecm: bytes) -> Optional[bytes]:
        """Find CW for given ECM"""
        if self.caid_filter and caid not in self.caid_filter:
            return None
        if len(ecm) < self.ecm_end:
            return None
        
        ecm_slice = ecm[self.ecm_start:self.ecm_end]
        
        key = (caid, srvid)
        if key in self.db:
            for stored_ecm, cw in self.db[key]:
                if stored_ecm == ecm_slice:
                    return cw
        
        for (db_caid, db_srvid), entries in self.db.items():
            if db_caid == caid:
                for stored_ecm, cw in entries:
                    if stored_ecm == ecm_slice:
                        return cw
        return None
    
    def get_cards(self) -> List[Dict]:
        """Get available cards"""
        return self.cards
