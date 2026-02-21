import time

# Create a mock database file
filename = "Login Data"
with open(filename, "w") as f:
    f.write("simulated_credentials")

# Hold the file descriptor open to mimic an Infostealer reading the DB
print(f"Mock Infostealer running. Holding '{filename}' open for 25 seconds...")
f = open(filename, "r")

time.sleep(25)
f.close()
print("Infostealer trace complete.")
