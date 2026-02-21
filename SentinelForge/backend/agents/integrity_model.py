import asyncio
import os
import time
from .base_agent import BaseAgent

try:
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler
except ImportError:
    Observer = None
    FileSystemEventHandler = object

class CanaryHandler(FileSystemEventHandler):
    def __init__(self, agent_ref):
        self.agent = agent_ref
        
    def _trigger_alert(self, event, action="Modified"):
        try:
            filename = os.path.basename(event.src_path)
            message = f"[RANSOMWARE THREAT] Integrity Violation! Canary Trap '{filename}' was suddenly {action}."
            
            # Route alert back into the main AsyncIO event loop
            loop = asyncio.get_running_loop()
            asyncio.run_coroutine_threadsafe(
                self.agent.emit_alert(message),
                loop
            )
        except Exception:
            pass

    def on_modified(self, event):
        if not event.is_directory:
            self._trigger_alert(event, "Encrypted/Modified")
            
    def on_deleted(self, event):
        if not event.is_directory:
            self._trigger_alert(event, "Deleted")

class IntegrityModel(BaseAgent):
    """
    Ransomware "Canary" Traps.
    Drops bait files on the disk. If any local process attempts to encrypt or delete them, 
    it immediately flags an active Ransomware encryption event.
    """
    def __init__(self, event_queue: asyncio.Queue):
        super().__init__(name="FIM", event_queue=event_queue)
        self.canary_dir = os.path.join(os.getcwd(), "SentinelForge-Vault")
        self.observer = None

    async def _deploy_canaries(self):
        if not os.path.exists(self.canary_dir):
            os.makedirs(self.canary_dir, exist_ok=True)
            
        bait_files = [
            "passwords_backup.txt",
            "crypto_wallet.dat",
            "tax_returns_2025.pdf"
        ]
        
        for bait in bait_files:
            filepath = os.path.join(self.canary_dir, bait)
            if not os.path.exists(filepath):
                with open(filepath, "w") as f:
                    f.write("SentinelForge decoy payload. Do not modify.\n" * 10)
        
        # Don't await emit_info here because the asyncio loop might not be ready during startup_event
        print(f"Deployed {len(bait_files)} Ransomware Canary Traps to {self.canary_dir}.")

    async def start(self):
        await super().start()
        
        if not Observer:
            await self.emit_info("watchdog not installed. Ransomware Canaries unavailable.")
            return

        try:
            await self._deploy_canaries()
            
            event_handler = CanaryHandler(self)
            self.observer = Observer()
            self.observer.schedule(event_handler, self.canary_dir, recursive=False)
            self.observer.start()
            await self.emit_info(f"Integrity Guard active. Monitoring Honey-Files for mass encryption.")
        except Exception as e:
            await self.emit_info(f"Failed to deploy Ransomware Canaries: {e}")

    async def _monitor(self):
        # The watchdog Observers run on their own sync thread, we just keep this async loop alive
        while self.is_active:
            await asyncio.sleep(60.0)
            
    async def run_manual_audit(self):
        # Already launched via start()
        pass

    async def stop(self):
        await super().stop()
        if self.observer:
            self.observer.stop()
            self.observer.join()
