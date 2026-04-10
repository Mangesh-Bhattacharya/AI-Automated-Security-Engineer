#!/usr/bin/env python3
"""
AI Automated Security Engineer - Main Entry Point
"""
import argparse
import sys
import os
from datetime import datetime
from src.vulnerability_scanner import VulnerabilityScanner
from src.threat_detector import ThreatDetector
from src.log_analyzer import LogAnalyzer
from src.report_generator import ReportGenerator
from src.remediation_engine import RemediationEngine
from src.ai_engine import AISecurityEngine
from src.config_manager import ConfigManager

def banner():
    print("""
    AI Automated Security Engineer v1.0
    Intelligent Vulnerability Detection & Threat Analysis
    """)

def parse_args():
    parser = argparse.ArgumentParser(description="AI Automated Security Engineer")
    parser.add_argument("--target", "-t", help="Target IP, hostname, or URL", default=None)
    parser.add_argument("--log-file", "-l", help="Log file path for analysis", default=None)
    parser.add_argument("--config", "-c", default="config/config.yaml")
    parser.add_argument("--output", "-o", default="reports/")
    parser.add_argument("--mode", "-m", choices=["full","vuln","threat","log"], default="full")
    parser.add_argument("--format", "-f", choices=["json","html","text"], default="html")
    parser.add_argument("--severity", "-s", choices=["critical","high","medium","low","all"], default="all")
    parser.add_argument("--ai-model", choices=["local","openai","huggingface"], default="local")
    parser.add_argument("--verbose", "-v", action="store_true")
    return parser.parse_args()

def main():
    banner()
    args = parse_args()
    config_manager = ConfigManager(args.config)
    config = config_manager.load()
    print(f"[*] Initializing AI Engine (backend: {args.ai_model})...")
    ai_engine = AISecurityEngine(config, backend=args.ai_model)
    ai_engine.initialize()
    print("[+] AI Engine ready")
    os.makedirs(args.output, exist_ok=True)
    results = {"scan_metadata": {"timestamp": datetime.now().isoformat(), "target": args.target, "mode": args.mode}, "vulnerabilities": [], "threats": [], "log_findings": [], "risk_score": 0, "recommendations": []}
    if args.target and args.mode in ["full", "vuln"]:
        print("[*] Starting Vulnerability Scan...")
        scanner = VulnerabilityScanner(config, ai_engine)
        results["vulnerabilities"] = scanner.scan(args.target, args.verbose)
        print(f"[+] Found {len(results['vulnerabilities'])} vulnerabilities")
    if args.target and args.mode in ["full", "threat"]:
        print("[*] Running Threat Detection...")
        detector = ThreatDetector(config, ai_engine)
        results["threats"] = detector.analyze(args.target, args.verbose)
        print(f"[+] Detected {len(results['threats'])} potential threats")
    if args.log_file and args.mode in ["full", "log"]:
        print(f"[*] Analyzing logs: {args.log_file}")
        analyzer = LogAnalyzer(config, ai_engine)
        results["log_findings"] = analyzer.analyze(args.log_file, args.verbose)
    from src.remediation_engine import RemediationEngine
    remediation = RemediationEngine(config, ai_engine)
    results["recommendations"] = remediation.generate_recommendations(results)
    results["risk_score"] = remediation.calculate_risk_score(results)
    print("[*] Generating report...")
    reporter = ReportGenerator(config)
    report_path = reporter.generate(results, args.output, args.format, args.severity)
    print(f"[+] Report saved: {report_path}")
    print(f"\n[SUMMARY] Risk Score: {results['risk_score']}/100 | Vulns: {len(results['vulnerabilities'])} | Threats: {len(results['threats'])}")
    return 0 if results["risk_score"] < 70 else 1

if __name__ == "__main__":
    sys.exit(main())
