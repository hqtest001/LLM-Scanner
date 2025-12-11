#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
LLM Scanner V1.0 - 扫描引擎模块
本地LLM服务未授权访问扫描核心逻辑
"""

import socket
import requests
import ipaddress
import queue
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Tuple

# ============ 配置 ============

# LLM服务配置
LLM_SERVICES = [
    {"name": "Ollama", "ports": [11434], "paths": ["/api/tags", "/api/version"], "identifier": "ollama"},
    {"name": "vLLM", "ports": [8000], "paths": ["/v1/models", "/health"], "identifier": "vllm"},
    {"name": "LM Studio", "ports": [1234], "paths": ["/v1/models"], "identifier": "lmstudio"},
    {"name": "llama.cpp", "ports": [8080], "paths": ["/health", "/v1/models"], "identifier": "llama"},
    {"name": "Mozilla-Llamafile", "ports": [8080], "paths": ["/"], "identifier": "llamafile"},
    {"name": "Jan AI", "ports": [1337], "paths": ["/v1/models"], "identifier": "jan"},
    {"name": "Cortex API", "ports": [1337, 39281], "paths": ["/v1/models"], "identifier": "cortex"},
    {"name": "Local-LLM", "ports": [8000, 8080], "paths": ["/v1/models"], "identifier": "local-llm"},
    {"name": "LiteLLM API", "ports": [4000], "paths": ["/health", "/v1/models"], "identifier": "litellm"},
    {"name": "GPT4All API Server", "ports": [4891], "paths": ["/v1/models"], "identifier": "gpt4all"},
    {"name": "OpenAI Compatible API", "ports": [8000, 8080, 3000, 5000], "paths": ["/v1/models", "/v1/chat/completions"], "identifier": "openai"},
]

# 排除的常用服务端口
EXCLUDED_PORTS = [
    20, 21, 22, 23, 25, 53, 67, 68, 69, 80, 110, 111, 119, 123,
    135, 137, 138, 139, 143, 161, 162, 389, 443, 445, 465, 514,
    515, 548, 554, 587, 631, 636, 873, 902, 993, 995,
    1433, 1434, 1521, 2049, 3306, 3389, 5432, 5900, 5901,
    6379, 8443, 9200, 9300, 27017,
]

# vLLM检测路径
VLLM_PATHS = ["/v1/models", "/health"]

# 全端口扫描范围
PORT_RANGES = [
    (1024, 1500), (3000, 3100), (4000, 5000), (5000, 6000),
    (7000, 9000), (9000, 10000), (10000, 12000), (30000, 40000),
]

# 超时设置
TCP_TIMEOUT = 0.2
HTTP_TIMEOUT = 3


# ============ 扫描引擎 ============

class LLMScanner:
    """LLM服务扫描器"""
    
    def __init__(self):
        self.msg_queue = queue.Queue()  # 消息队列
        self.results = []
        self.open_ports = []
        self.scanning = False
        self.stop_flag = False
        self.progress = 0
        
    def log(self, message: str, level: str = "info"):
        """输出日志到队列"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.msg_queue.put(("log", f"[{timestamp}] {message}", level))
        
    def update_progress(self, value: int):
        """更新进度"""
        self.progress = value
        self.msg_queue.put(("progress", value, None))
            
    def check_port_open(self, ip: str, port: int) -> bool:
        """检查端口是否开放"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(TCP_TIMEOUT)
            result = sock.connect_ex((ip, port))
            sock.close()
            return result == 0
        except:
            return False
            
    def http_get(self, url: str) -> Tuple[bool, str]:
        """发送HTTP GET请求"""
        try:
            response = requests.get(url, timeout=HTTP_TIMEOUT)
            if response.status_code == 200:
                return True, response.text
            return False, ""
        except:
            return False, ""
            
    def is_llm_service(self, response: str, identifier: str) -> bool:
        """判断响应是否为LLM服务"""
        response_lower = response.lower()
        checks = {
            "ollama": lambda r: "ollama" in r or "models" in r,
            "vllm": lambda r: self.is_vllm_response(response),
            "lmstudio": lambda r: "lmstudio" in r or "lm studio" in r,
            "llama": lambda r: "llama" in r or "ggml" in r,
            "llamafile": lambda r: "llamafile" in r or "mozilla" in r,
            "jan": lambda r: "jan" in r or "models" in r,
            "cortex": lambda r: "cortex" in r,
            "local-llm": lambda r: "local" in r and "llm" in r,
            "litellm": lambda r: "litellm" in r or "healthy" in r,
            "gpt4all": lambda r: "gpt4all" in r,
            "openai": lambda r: "model" in r or "openai" in r,
        }
        return checks.get(identifier, lambda r: False)(response_lower)
        
    def is_vllm_response(self, response: str) -> bool:
        """判断响应是否为vLLM服务"""
        r = response.lower()
        if "vllm" in r:
            return True
        if '"data"' in r and '"id"' in r and '"object"' in r:
            return True
        if '"status"' in r and "healthy" in r:
            return True
        if "model" in r and ("object" in r or "models" in r):
            return True
        return False
        
    def scan_ip_services(self, ip: str, ip_progress_base: int, ip_progress_weight: int) -> List[Dict]:
        """扫描单个IP的所有LLM服务"""
        results = []
        total_checks = sum(len(s["ports"]) * len(s["paths"]) for s in LLM_SERVICES)
        check_count = 0
        
        for service in LLM_SERVICES:
            if self.stop_flag:
                break
                
            for port in service["ports"]:
                if self.stop_flag:
                    break
                    
                self.log(f"检测 {ip}:{port} ({service['name']})")
                
                for path in service["paths"]:
                    if self.stop_flag:
                        break
                    
                    check_count += 1
                    sub_progress = int((check_count / total_checks) * ip_progress_weight * 0.5)
                    self.update_progress(ip_progress_base + sub_progress)
                        
                    url = f"http://{ip}:{port}{path}"
                    success, response_text = self.http_get(url)
                    
                    if success and self.is_llm_service(response_text, service["identifier"]):
                        result = {
                            "ip": ip, "port": port, "service": service["name"],
                            "status": "Vulnerable",
                            "vulnerability": f"{service['name']} 未授权访问漏洞",
                            "timestamp": datetime.now().isoformat(),
                            "url": url,
                            "response": response_text[:500] if len(response_text) > 500 else response_text,
                            "details": f"检测到 {service['name']} 服务未授权访问\n风险等级: 高\n建议: 启用认证或限制访问"
                        }
                        results.append(result)
                        self.log(f"[!] 发现漏洞: {service['name']} @ {ip}:{port}", "error")
                        break
                        
        return results
        
    def scan_ports_for_vllm(self, ip: str, ip_progress_base: int, ip_progress_weight: int) -> List[Dict]:
        """全端口扫描检测vLLM"""
        results = []
        open_ports = []
        
        known_ports = set()
        for service in LLM_SERVICES:
            known_ports.update(service["ports"])
            
        total_ports = sum(end - start + 1 for start, end in PORT_RANGES)
        scanned_ports = 0
        
        self.log(f"[{ip}] 全端口扫描开始，共 {total_ports} 个端口待扫描")
        
        for range_idx, (start, end) in enumerate(PORT_RANGES):
            if self.stop_flag:
                break
                
            range_size = end - start + 1
            self.log(f"[{ip}] 扫描端口 {start}-{end} ({range_size}个)")
            
            ports_to_scan = [p for p in range(start, end + 1) 
                           if p not in EXCLUDED_PORTS and p not in known_ports]
            
            with ThreadPoolExecutor(max_workers=100) as executor:
                future_to_port = {executor.submit(self.check_port_open, ip, p): p for p in ports_to_scan}
                for future in as_completed(future_to_port):
                    if self.stop_flag:
                        break
                    scanned_ports += 1
                    sub_progress = int((scanned_ports / total_ports) * ip_progress_weight * 0.5)
                    self.update_progress(ip_progress_base + int(ip_progress_weight * 0.5) + sub_progress)
                    
                    port = future_to_port[future]
                    try:
                        if future.result():
                            open_ports.append(port)
                            self.log(f"[{ip}] 端口 {port} 开放")
                    except:
                        pass
                        
        if open_ports:
            self.open_ports.extend(open_ports)
            self.log(f"[{ip}] 发现 {len(open_ports)} 个开放端口: {open_ports[:10]}{'...' if len(open_ports) > 10 else ''}")
            self.log(f"[{ip}] 开始vLLM服务检测...")
            
            for i, port in enumerate(open_ports):
                if self.stop_flag:
                    break
                    
                for path in VLLM_PATHS:
                    url = f"http://{ip}:{port}{path}"
                    success, response_text = self.http_get(url)
                    
                    if success and self.is_vllm_response(response_text):
                        exists = any(r["ip"] == ip and r["port"] == port for r in results)
                        if not exists:
                            result = {
                                "ip": ip, "port": port, "service": "vLLM",
                                "status": "Vulnerable",
                                "vulnerability": "vLLM 未授权访问漏洞",
                                "timestamp": datetime.now().isoformat(),
                                "url": url,
                                "response": response_text[:500] if len(response_text) > 500 else response_text,
                                "details": f"在端口 {port} 检测到vLLM服务\n风险等级: 高\n检测路径: {path}"
                            }
                            results.append(result)
                            self.log(f"[!] 发现漏洞: vLLM @ {ip}:{port}", "error")
                        break
        else:
            self.log(f"[{ip}] 未发现额外开放端口")
            
        return results
        
    def parse_target(self, target: str, target_type: str) -> List[str]:
        """解析扫描目标"""
        ips = []
        if target_type == "single":
            ips = [target.strip()]
        elif target_type == "range":
            parts = target.split("-")
            if len(parts) == 2:
                try:
                    start_ip = ipaddress.IPv4Address(parts[0].strip())
                    end_ip = ipaddress.IPv4Address(parts[1].strip())
                    current, end = int(start_ip), int(end_ip)
                    while current <= end and len(ips) < 256:
                        ips.append(str(ipaddress.IPv4Address(current)))
                        current += 1
                except:
                    pass
        elif target_type == "cidr":
            try:
                network = ipaddress.IPv4Network(target.strip(), strict=False)
                for i, ip in enumerate(network.hosts()):
                    if i >= 256:
                        break
                    ips.append(str(ip))
            except:
                pass
        return ips
        
    def scan(self, target: str, target_type: str, enable_full_port_scan: bool = False):
        """执行扫描"""
        self.scanning = True
        self.stop_flag = False
        self.results = []
        self.open_ports = []
        self.progress = 0
        
        self.update_progress(0)
        self.log("=" * 40)
        self.log("开始扫描任务")
        
        ips = self.parse_target(target, target_type)
        if not ips:
            self.log("错误: 无效的目标地址", "error")
            self.scanning = False
            self.update_progress(100)
            return []
            
        self.log(f"目标: {target}")
        self.log(f"类型: {target_type}")
        self.log(f"IP数量: {len(ips)}")
        self.log(f"全端口扫描: {'启用' if enable_full_port_scan else '禁用'}")
        self.log("=" * 40)
        
        total_ips = len(ips)
        
        for i, ip in enumerate(ips):
            if self.stop_flag:
                break
            
            ip_progress_base = int((i / total_ips) * 100)
            ip_progress_weight = int(100 / total_ips)
            
            self.log(f"")
            self.log(f">>> 扫描 [{i+1}/{total_ips}] {ip} ({int((i+1)/total_ips*100)}%)")
            self.update_progress(ip_progress_base)
            
            self.log(f"[{ip}] 检测LLM服务...")
            service_results = self.scan_ip_services(ip, ip_progress_base, ip_progress_weight)
            self.results.extend(service_results)
            
            if enable_full_port_scan and not self.stop_flag:
                self.log(f"[{ip}] 启动全端口扫描...")
                vllm_results = self.scan_ports_for_vllm(ip, ip_progress_base, ip_progress_weight)
                self.results.extend(vllm_results)
                
            self.update_progress(ip_progress_base + ip_progress_weight)
                
        self.log("")
        self.log("=" * 40)
        if self.stop_flag:
            self.log("扫描已取消", "warning")
        else:
            if self.results:
                self.log(f"扫描完成! 发现 {len(self.results)} 个漏洞", "error")
            else:
                self.log("扫描完成! 未发现漏洞", "success")
        self.log("=" * 40)
        
        self.update_progress(100)
        self.scanning = False
        self.msg_queue.put(("done", self.results, None))
        return self.results
        
    def stop(self):
        """停止扫描"""
        self.stop_flag = True
        self.log("正在停止扫描...", "warning")

