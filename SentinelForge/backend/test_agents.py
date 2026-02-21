import asyncio
from agents.integrity_model import IntegrityModel
from agents.keystroke_model import KeystrokeModel

async def main():
    print("Testing FIM and KEYS standalone deployment...")
    evt_queue = asyncio.Queue()
    
    fim = IntegrityModel(evt_queue)
    await fim.start()
    
    keys = KeystrokeModel(evt_queue)
    await keys.start()
    
    print("Agent deployment complete. Running listener for 10 seconds.")
    await asyncio.sleep(10)

if __name__ == "__main__":
    asyncio.run(main())
