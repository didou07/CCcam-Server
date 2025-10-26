import os
import sys
import logging
from datetime import datetime

class Logger:
    """OSCam-style logger"""
    
    def __init__(self, name: str, level: str = "INFO"):
        self.level = level.upper()
        self.logger = logging.getLogger(name)
        self.logger.setLevel(logging.DEBUG)
        self.logger.handlers.clear()
        
        console = logging.StreamHandler(sys.stdout)
        console.setLevel(getattr(logging, self.level))
        fmt = logging.Formatter('%(asctime)s %(message)s', datefmt='%Y/%m/%d %H:%M:%S')
        console.setFormatter(fmt)
        self.logger.addHandler(console)
        
        try:
            os.makedirs("./logs", exist_ok=True)
            log_file = f"./logs/cccam_{datetime.now().strftime('%Y%m%d')}.log"
            fh = logging.FileHandler(log_file, encoding='utf-8')
            fh.setLevel(logging.DEBUG)
            fh.setFormatter(fmt)
            self.logger.addHandler(fh)
        except:
            pass
    
    def is_debug(self):
        return self.level == "DEBUG"
    
    def info(self, msg): 
        self.logger.info(msg)
    
    def debug(self, msg): 
        if self.is_debug():
            self.logger.debug(msg)
    
    def warning(self, msg): 
        self.logger.warning(msg)
    
    def error(self, msg): 
        self.logger.error(msg)
