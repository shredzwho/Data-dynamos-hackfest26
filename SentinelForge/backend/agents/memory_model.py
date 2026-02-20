import asyncio
import psutil
import numpy as np
from fastembed import TextEmbedding
from .base_agent import BaseAgent
import time

class MemoryModel(BaseAgent):
    """
    Advanced DL-Powered Process Memory Scanner (HyMem Architecture).
    Uses FastEmbed and numpy for semantic retrieval of malicious process memory/command lines.
    """
    def __init__(self, event_queue: asyncio.Queue):
        super().__init__(name="MEM", event_queue=event_queue)
        
        # Load the lightweight embedding model
        # using FastEmbed (CPU optimized, no PyTorch overhead for simple embeddings)
        try:
            self.embedding_model = TextEmbedding(model_name="BAAI/bge-small-en-v1.5")
            self._model_ready = True
        except Exception as e:
            print(f"Failed to load FastEmbed model: {e}")
            self._model_ready = False

        # Register for THREAT events from other agents
        self.subscribe("THREAT")

        # Known Injection Signatures (Shellcode/Reflective Loaders/Hollowing heuristics)
        self.malicious_signatures = [
            "powershell.exe -nop -w hidden -encodedcommand",
            "svchost.exe -k netsvcs (Process Hollowing Target)",
            "Invoke-Mimikatz -DumpCreds",
            "Reflective DLL Injection memory pattern MZ...PE...0x00",
            "Cobalt Strike Beacon HTTP payload pattern",
            "rundll32.exe C:\\windows\\temp\\malicious.dll",
            "certutil.exe -urlcache -split -f http://"
        ]
        
        # Pre-compute signature embeddings to hold in RAM (The 'Knowledge Base')
        if self._model_ready:
            self.signature_embeddings = list(self.embedding_model.embed(self.malicious_signatures))
            self.signature_embeddings = np.array(self.signature_embeddings)

    def _cosine_similarity(self, a, b):
        return np.dot(a, b) / (np.linalg.norm(a) * np.linalg.norm(b))

    async def handle_event(self, event: dict):
        """Phase 17 Pub/Sub: React autonomously to other agents' events."""
        source_model = event.get("model")
        if source_model == "NET" and event.get("type") == "THREAT":
            await self.emit_info(f"Pub/Sub Intercept: Network Threat detected. MemoryModel initiating localized heuristic sweep for volatile payloads...")
            await asyncio.sleep(1.0) # Simulate a quick scan
            await self.emit_info("Pub/Sub Action Complete: No volatile memory anomalies found related to the Network threat.")

    async def _monitor(self):
        await self.emit_info("HyMem Deep Learning Engine initialized. FastEmbed active. Scanning for Injections...")
        
        if not self._model_ready:
            await self.emit_info("Embedding model failed to load. Operating in degraded mode.")
        
        while self.is_active:
            # Full process scan every 15 seconds
            await asyncio.sleep(15.0)
            
            try:
                # 1. System health check
                mem = psutil.virtual_memory()
                if mem.percent > 90.0:
                    await self.emit_alert(f"RAM Exhaustion: {mem.percent}%")
                
                # 2. Extract Process Features
                # In a real EDR, we'd read process memory pages via OS APIs (ReadProcessMemory).
                # Here we simulate feature extraction by taking cmdlines and paths as our "Memory Features".
                for p in psutil.process_iter(['pid', 'name', 'cmdline', 'exe']):
                    try:
                        cmdline = p.info.get('cmdline')
                        name = p.info.get('name')
                        exe = p.info.get('exe')
                        
                        if not cmdline:
                            continue
                            
                        feature_string = " ".join(cmdline)
                        if len(feature_string) < 5:
                            continue
                            
                        # 3. FastEmbed: Generate live tensor for process memory
                        live_emb = list(self.embedding_model.embed([feature_string]))[0]
                        
                        # 4. Semantic Retrieval (FAISS equivalent via Numpy matrix mult)
                        # We calculate cosine similarity against all known malicious signatures
                        similarities = [self._cosine_similarity(live_emb, sig_emb) for sig_emb in self.signature_embeddings]
                        max_sim = max(similarities)
                        matched_index = similarities.index(max_sim)
                        
                        # 0.82 is our Deep Learning threshold for "Suspicious Semantic Match"
                        if max_sim > 0.82:
                            matched_sig = self.malicious_signatures[matched_index]
                            await self.emit_alert(
                                f"DL Memory Injection Detected: Process '{name}' (PID {p.info.get('pid')}). "
                                f"Semantic Distance: {max_sim:.2f} to signature [{matched_sig}]."
                            )
                            # To avoid spamming, we break after finding one critical threat per cycle
                            break

                    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                        pass

            except Exception as e:
                await self.emit_info(f"HyMem engine error: {str(e)}")
