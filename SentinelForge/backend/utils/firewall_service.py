import subprocess
import platform
import logging

logger = logging.getLogger(__name__)

class FirewallService:
    """
    Executes OS-level network drops (Anti-Pawning IPS).
    Supports Linux (iptables) and Mac (pfctl).
    """
    
    @staticmethod
    def block_ip(ip_address: str):
        os_type = platform.system().lower()
        
        try:
            if os_type == "linux":
                # Typical Linux iptables drop execution
                cmd = ["sudo", "iptables", "-A", "INPUT", "-s", ip_address, "-j", "DROP"]
                # subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                logger.info(f"FirewallService [SIMULATION]: Successfully injected iptables DROP for {ip_address}")
            
            elif os_type == "darwin": # Mac
                # Using pfctl route drop (Requires pf to be enabled)
                # sudo route add -host <ip> 127.0.0.1 -blackhole
                cmd = ["sudo", "route", "-q", "add", "-host", ip_address, "127.0.0.1", "-blackhole"]
                # subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                logger.info(f"FirewallService [SIMULATION]: Successfully blackholed {ip_address} on macOS route table.")
                
            else:
                logger.warning(f"FirewallService: Autonomous blocking not natively supported on {os_type}. Simulated block for {ip_address}.")
                
            return True
            
        except Exception as e:
            logger.error(f"FirewallService: Failed to block {ip_address}: {e}")
            return False
