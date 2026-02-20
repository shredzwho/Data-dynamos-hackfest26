import asyncio
import psutil
from .base_agent import BaseAgent

class MemoryModel(BaseAgent):
    """
    Monitors LIVE System RAM and specific Process Memory pools using psutil.
    """
    def __init__(self, event_queue: asyncio.Queue):
        super().__init__(name="MEM", event_queue=event_queue)

    async def _monitor(self):
        await self.emit_info("Hardware Memory hooks attached via psutil. Tracking live allocations...")
        while self.is_active:
            # Poll every 10 seconds
            await asyncio.sleep(10.0)
            
            try:
                mem = psutil.virtual_memory()
                
                # Fetch top memory intensive process
                procs = []
                for p in psutil.process_iter(['pid', 'name', 'memory_percent']):
                    if p.info['memory_percent'] is not None:
                        procs.append(p)
                
                if procs:
                    top_proc = sorted(procs, key=lambda p: p.info['memory_percent'], reverse=True)[0]
                    top_name = top_proc.info['name']
                    top_mem = top_proc.info['memory_percent']
                else:
                    top_name = "Unknown"
                    top_mem = 0.0

                if mem.percent > 90.0:
                    await self.emit_alert(f"CRITICAL RAM EXHAUSTION: Usage at {mem.percent}%. Highest consumer: {top_name} ({top_mem:.1f}%)")
                elif mem.percent > 75.0:
                    await self.emit_info(f"High RAM usage threshold reached: {mem.percent}%. Top Process: {top_name}")
                else:
                    await self.emit_info(f"RAM pool stable at {mem.percent}%. ({top_name} leads at {top_mem:.1f}%)")
                    
            except Exception as e:
                await self.emit_info(f"Memory telemetry error: {str(e)}")
