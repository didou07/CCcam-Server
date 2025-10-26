from typing import List, Tuple, Optional

class ECMProcessor:
    """Process ECM requests across multiple readers"""
    
    def __init__(self, logger):
        self.log = logger
        self.readers: List = []
    
    def add_reader(self, reader):
        """Add a reader to the processor"""
        self.readers.append(reader)
        self.log.info(f"Added reader: {reader.label} ({reader.protocol})")
    
    def process_ecm(self, caid: int, srvid: int, ecm: bytes, user_group: int = 1) -> Tuple[Optional[bytes], Optional[str]]:
        """
        Process ECM through available readers
        Returns: (cw, reader_label) or (None, None)
        """
        for reader in self.readers:
            if hasattr(reader, 'group') and reader.group != user_group:
                continue
            
            try:
                cw = reader.process_ecm(caid, srvid, ecm)
                if cw and len(cw) == 16:
                    return cw, reader.label
            except Exception as e:
                self.log.error(f"Reader {reader.label} error: {e}")
        
        return None, None
    
    def get_all_cards(self) -> List[dict]:
        """Get all available cards from all readers"""
        all_cards = []
        seen = set()
        
        for reader in self.readers:
            try:
                cards = reader.get_cards()
                for card in cards:
                    caid = card['caid']
                    if caid not in seen:
                        seen.add(caid)
                        all_cards.append(card)
            except Exception as e:
                self.log.error(f"Error getting cards from {reader.label}: {e}")
        
        return all_cards
