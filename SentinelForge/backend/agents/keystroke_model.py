import asyncio
import time
from .base_agent import BaseAgent

try:
    from pynput import keyboard
except ImportError:
    keyboard = None

class KeystrokeModel(BaseAgent):
    """
    Anti-Rubber Ducky (Hardware Injection) Defense.
    Calculates Characters Per Second (CPS) globally. If CPS exceeds human limits (>50), 
    it flags a malicious BadUSB script injection in progress.
    """
    def __init__(self, event_queue: asyncio.Queue):
        super().__init__(name="KEYS", event_queue=event_queue)
        self.keystrokes = []
        self.listener = None
        self.cps_threshold = 50.0 # 50 chars per sec is faster than 600 words per minute

    def _on_press(self, key):
        if not self.is_active:
            return
            
        current_time = time.time()
        self.keystrokes.append(current_time)
        
        # Keep only the last 2 seconds of keystrokes to calculate CPS in a sliding window
        self.keystrokes = [t for t in self.keystrokes if current_time - t <= 2.0]
        
        # Calculate CPS
        if len(self.keystrokes) > self.cps_threshold * 2: # More than 100 keys in 2 seconds
            # Only trigger an alert once every few seconds to avoid spamming the SOC loop
            if len(self.keystrokes) % 25 == 0: 
                cps = len(self.keystrokes) / 2.0
                try:
                    # In asyncio, we must use run_coroutine_threadsafe since pynput provides its own sync thread
                    loop = asyncio.get_running_loop()
                    asyncio.run_coroutine_threadsafe(
                        self.emit_alert(f"[HARDWARE THREAT] Impossible typing speed detected ({cps:.1f} CPS). Potential BadUSB / Rubber Ducky Injection active!"),
                        loop
                    )
                except Exception:
                    pass
        elif len(self.keystrokes) == 10:
            # Just a tiny benign heuristic trace for the dashboard to show it works
            try:
                loop = asyncio.get_running_loop()
                asyncio.run_coroutine_threadsafe(
                    self.emit_info(f"Keystroke dynamics nominal. Current speed: {(len(self.keystrokes) / 2.0):.1f} CPS"),
                    loop
                )
            except Exception:
                pass


    async def start(self):
        await super().start()
        if keyboard:
            await self.emit_info("Hardware Keystroke Dynamics monitor active. Tracking CPS for USB injections.")
            self.listener = keyboard.Listener(on_press=self._on_press)
            self.listener.start()
        else:
            await self.emit_info("pynput not installed. Anti-Rubber Ducky protection unavailable.")

    async def _monitor(self):
        # Driven by the pynput sync listener thread, not an asyncio sleep loop
        while self.is_active:
            await asyncio.sleep(60.0)

    async def run_manual_audit(self):
        # Already launched via start()
        pass

    def stop(self):
        super().stop()
        if self.listener:
            self.listener.stop()
