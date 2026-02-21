#!/bin/bash

export STOP_SENTINEL=0

echo -e "\033[1;36m=================================================\033[0m"
echo -e "\033[1;36m       S E N T I N E L F O R G E   I N I T       \033[0m"
echo -e "\033[1;36m=================================================\033[0m"
echo ""

# Function to handle graceful shutdown
cleanup() {
    if [ $STOP_SENTINEL -eq 1 ]; then
        exit 0
    fi
    export STOP_SENTINEL=1
    echo ""
    echo -e "\033[1;33m[!] Shutdown signal received. Terminating SentinelForge...\033[0m"
    
    # Kill the processes
    if [ ! -z "$BACKEND_PID" ]; then
        kill $BACKEND_PID 2>/dev/null
    fi
    
    if [ ! -z "$FRONTEND_PID" ]; then
        kill $FRONTEND_PID 2>/dev/null
    fi
    
    # Clean up any stuck uvicorn or next instances
    kill -9 $(lsof -t -i:8000) 2>/dev/null
    kill -9 $(lsof -t -i:3000) 2>/dev/null

    echo -e "\033[1;32m[+] SentinelForge cleanly shut down.\033[0m"
    exit 0
}

# Trap exit signals
trap cleanup SIGINT SIGTERM

# 1. Kill any existing instances on ports 3000/8000 to prevent startup collisions
echo -e "\033[1;34m[*] Sweeping ports 3000 and 8000 for zombie processes...\033[0m"
kill -9 $(lsof -t -i:8000) 2>/dev/null
kill -9 $(lsof -t -i:3000) 2>/dev/null
sleep 1

# 2. Boot Backend
echo -e "\033[1;34m[*] Booting SentinelForge AI Engine (FastAPI)...\033[0m"
cd backend || exit
if [ ! -d "venv" ]; then
    echo -e "\033[1;31m[-] Error: venv not found in backend/. Run setup first.\033[0m"
    exit 1
fi
source venv/bin/activate
uvicorn main:socket_app --host 127.0.0.1 --port 8000 --reload > /dev/null 2>&1 &
BACKEND_PID=$!
cd ..

# 3. Boot Frontend
echo -e "\033[1;34m[*] Booting React Dashboard (Next.js)...\033[0m"
cd frontend || exit
npm run dev > /dev/null 2>&1 &
FRONTEND_PID=$!
cd ..

echo ""
echo -e "\033[1;32m=================================================\033[0m"
echo -e "\033[1;32m[+] MULTI-MODAL AI SYSTEM ONLINE                 \033[0m"
echo -e "\033[1;32m=================================================\033[0m"
echo -e "\033[1;37m    Dashboard: http://localhost:3000             \033[0m"
echo -e "\033[1;37m    API Base:  http://localhost:8000             \033[0m"
echo -e "\033[1;37m-------------------------------------------------\033[0m"
echo -e "\033[1;33m    [ PRESS CTRL+C TO DEACTIVATE SENTINEL ]      \033[0m"
echo -e "\033[1;32m=================================================\033[0m"

# Wait eternally for trap to trigger
while :
do
    sleep 1
done
