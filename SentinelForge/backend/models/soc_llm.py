import logging

try:
    from transformers import pipeline
except ImportError:
    pipeline = None

logger = logging.getLogger(__name__)

class SOCSupervisorLLM:
    """
    Local Generative AI model to analyze threat events and output human-readable SOC incident reports.
    """
    def __init__(self):
        self.generator = None
        self.is_loaded = False

    async def start(self):
        import asyncio
        await asyncio.to_thread(self._load_model)

    def _load_model(self):
        if pipeline:
            try:
                # Use a tiny parameter LLM for local speed, avoiding massive VRAM overhead
                logger.info("Initializing Local Generative SOC LLM (HuggingFaceTB/SmolLM-135M)...")
                # Using a very tiny model to avoid exploding the user's hard drive / RAM
                self.generator = pipeline("text-generation", model="HuggingFaceTB/SmolLM-135M", device="cpu")
                self.is_loaded = True
                logger.info("Local Generative SOC LLM Online.")
            except Exception as e:
                logger.warning(f"Failed to load Generative LLM: {str(e)}. Falling back to deterministic SOC heuristics.")
        else:
            logger.warning("Transformers library missing. Falling back to deterministic SOC heuristics.")

    def correlate_threats(self, threat_history: list) -> str:
        """
        Analyzes recent threat events and synthesizes an intelligence report.
        """
        models_involved = list(set([t["model"] for t in threat_history]))
        
        if self.is_loaded and self.generator:
            # Construct a prompt for the local LLM
            prompt = (
                f"As an elite Cybersecurity SOC Analyst, analyze this incident: \n"
                f"Multiple security alerts were triggered within 60 seconds by these SentinelForge AI agents: {', '.join(models_involved)}.\n"
                f"Write a very brief, 2-sentence urgent incident report summarizing the likely attack vector and recommending immediate isolation:\n"
            )
            try:
                # Generate text
                output = self.generator(prompt, do_sample=True, temperature=0.3, max_new_tokens=40)[0]['generated_text']
                # Strip the prompt from the output
                response = output.replace(prompt, "").strip()
                return f"[Generative LLM Insight]: {response}"
            except Exception as e:
                logger.error(f"Generative LLM generation failed: {str(e)}")
                # Fallback to heuristics on error

        # Fallback Heuristics
        if len(models_involved) > 1:
            return f"[Heuristic Insight]: Correlated multi-vector attack detected across {', '.join(models_involved)}. High probability of synchronized intrusion or C2 beaconing. Recommend IP isolation."
        else:
            return f"[Heuristic Insight]: Sustained aggressive anomaly isolated to {models_involved[0]} agent. Potential localized payload execution."

    def answer_admin_query(self, query: str) -> str:
        """
        Answers natural language queries from the Admin's terminal.
        """
        if self.is_loaded and self.generator:
            prompt = (
                f"You are the SentinelForge SOC AI Assistant. Answer the admin's query concisely.\n"
                f"Admin Query: {query}\n"
                f"Answer:"
            )
            try:
                output = self.generator(prompt, do_sample=True, temperature=0.5, max_new_tokens=30)[0]['generated_text']
                response = output.replace(prompt, "").strip()
                return response
            except Exception:
                pass
                
        return f"Simulated Processing of: '{query}'. (Transformers LLM not loaded)."
