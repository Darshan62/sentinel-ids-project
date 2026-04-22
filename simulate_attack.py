import requests
import random
import time
import sys

def simulate_attack(attack_type, count):
    print(f"🔥 Preparing to inject {count} {attack_type} packets...")
    
    for i in range(count):
        # Pick a random high port and IP suffix
        suffix = random.randint(100, 250)
        
        payload = {
            "type": attack_type,
            "ip_suffix": suffix,
            "port": 80 if "DoS" in attack_type else 22,
            "activity": "🚨 INJECTED: " + attack_type.upper()
        }
        
        try:
            res = requests.post("http://localhost:8000/api/inject_attack", json=payload)
            if res.status_code == 200:
                print(f"[{i+1}/{count}] ✅ Successfully injected {attack_type} from 192.168.1.{suffix}")
            else:
                print(f"[{i+1}/{count}] ❌ Injection API failed. Is fastapi running?")
        except requests.exceptions.ConnectionError:
            print("❌ Error: Could not connect. Make sure 'python api.py' is running!")
            sys.exit(1)
            
        time.sleep(0.5) # Wait half a second before firing the next packet!

if __name__ == "__main__":
    print("Welcome to the Sentinel Demo Attacker!")
    print("1. DDoS Attack Burst")
    print("2. SSH-Patator (Brute Force)")
    print("3. DoS Hulk")
    print("4. Safe Traffic Burst (coming soon)")
    
    choice = input("\nSelect an attack payload to inject (1-3): ")
    
    if choice == "1":
        simulate_attack("DDoS", 10)
    elif choice == "2":
        simulate_attack("SSH-Patator", 5)
    elif choice == "3":
        simulate_attack("DoS Hulk", 15)
    else:
        print("Invalid choice.")
