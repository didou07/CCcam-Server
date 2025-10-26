from typing import Optional

class SocketHandler:
    """Handle socket operations"""
    
    def __init__(self, sock, logger):
        self.sock = sock
        self.log = logger
        self.running = True
    
    def recv_exact(self, size: int) -> Optional[bytes]:
        """Receive exact number of bytes"""
        data = b''
        while len(data) < size and self.running:
            try:
                chunk = self.sock.recv(size - len(data))
                if not chunk:
                    return None
                data += chunk
            except Exception:
                return None
        return data if len(data) == size else None
    
    def send_data(self, data: bytes):
        """Send data through socket"""
        if not self.running:
            return
        try:
            self.sock.sendall(data)
        except Exception as e:
            self.running = False
            raise
    
    def close(self):
        """Close socket"""
        self.running = False
        try:
            self.sock.close()
        except:
            pass
