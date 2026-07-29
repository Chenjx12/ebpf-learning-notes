#!/usr/bin/env python3
"""
k8s_responder.py — 基于 K8s API 的主动响应引擎
对应笔记: docs/Three-扩展/WEEK 4.md

对比 Docker 版 (responder.py):
  Docker SDK                    →  K8s API
  ─────────────────────────────────────────────────
  container.pause()             →  V1DeleteOptions (删除 Pod)
  container.disconnect(network) →  NetworkPolicy (podSelector)
  container.stop()              →  V1DeleteOptions (删除 Pod)
  docker exec kill -9 <pid>     →  Pod 删除 (Pod 内进程一并终止)
  docker.from_env()             →  config.load_incluster_config()

cgroup 路径解析:
  Docker:  /docker/<64-char-id>.scope
  K8s:     /kubepods/<qos>/pod<uid>/<container-id>
"""

import os
import sys
import time
import json
import signal
from datetime import datetime

from kubernetes import client, config


class K8sResponseEngine:
    """K8s 版本的响应引擎 — 用 K8s API 替代 Docker SDK"""

    def __init__(self, responses_file="responses.yaml", namespace="default"):
        self.namespace = namespace
        self.responses = self._load_yaml(responses_file)

        # 加载 K8s 配置 (Pod 内自动用 ServiceAccount token)
        try:
            config.load_incluster_config()
            print("[*] 使用 in-cluster K8s 认证")
        except config.ConfigException:
            config.load_kube_config()
            print("[*] 使用 ~/.kube/config 认证")

        self.v1 = client.CoreV1Api()
        self.net_v1 = client.NetworkingV1Api()
        self.apps_v1 = client.AppsV1Api()

    # ===== 配置加载 =====

    def _load_yaml(self, path):
        import yaml
        with open(path, "r") as f:
            data = yaml.safe_load(f)
        return data.get("responses", []) if data else []

    # ===== 容器/Pod 身份解析 =====

    def _pid_to_pod(self, pid):
        """通过 /proc/<pid>/cgroup 找到 Pod 名称"""
        cgroup_path = f"/proc/{pid}/cgroup"
        if not os.path.exists(cgroup_path):
            # 在容器内, 尝试宿主机挂载路径
            cgroup_path = f"/host/proc/{pid}/cgroup"
            if not os.path.exists(cgroup_path):
                return None, "unknown"

        try:
            with open(cgroup_path, "r") as f:
                for line in f:
                    # K8s cgroup 格式: 0::/kubepods/burstable/pod<uid>/<cid>
                    if "kubepods" in line or "kubelet" in line:
                        # 提取 pod UID
                        parts = line.strip().split("/")
                        for part in parts:
                            if part.startswith("pod"):
                                return part, "pod"
            return None, "host"
        except Exception as e:
            print(f"[WARN] cgroup 读取失败: {e}")
            return None, "unknown"

    def _find_pod_by_cgroup(self, pid):
        """根据 cgroup 信息找到对应的 K8s Pod 对象"""
        pod_uid, _ = self._pid_to_pod(pid)
        if not pod_uid:
            return None

        try:
            pods = self.v1.list_namespaced_pod(self.namespace)
            for pod in pods.items:
                if pod.metadata.uid in pod_uid or pod_uid.startswith(pod.metadata.uid[:12]):
                    return pod
        except client.ApiException as e:
            print(f"[ERROR] K8s API 调用失败: {e}")

        return None

    # ===== 告警处理入口 =====

    def handle_alert(self, alert):
        """处理告警, 查找对应的响应策略并执行"""
        for resp in self.responses:
            if resp.get("alert_id") != alert.get("rule_id"):
                continue

            if not resp.get("auto_respond", False):
                print(f"[INFO] {alert['rule_id']} 未开启自动响应, 仅记录")
                self._audit_log(alert.get("container", "unknown"),
                                "alert_only", str(alert))
                return

            for action in resp.get("actions", []):
                action_type = action.get("type")
                reason = action.get("reason", "")

                if action_type == "isolate_network":
                    self.isolate_pod_network(alert)
                elif action_type == "kill_process":
                    self.kill_pod(alert)
                elif action_type == "pause_container":
                    self.kill_pod(alert)  # K8s 无 pause, 改用删除 Pod
                elif action_type == "log":
                    self.log_only(alert)
                else:
                    print(f"[WARN] 未知响应动作: {action_type}")

    # ===== 响应动作 =====

    def isolate_pod_network(self, alert):
        """通过 NetworkPolicy 隔离 Pod 网络"""
        pid = alert.get("pid", 0)
        pod = self._find_pod_by_cgroup(pid)

        if not pod:
            print(f"[WARN] 未找到 PID {pid} 对应的 Pod, 无法隔离")
            self._audit_log("unknown", "isolate_failed", str(alert))
            return

        pod_name = pod.metadata.name
        policy_name = f"isolate-{pod_name}"

        policy = client.V1NetworkPolicy(
            metadata=client.V1ObjectMeta(name=policy_name, namespace=self.namespace),
            spec=client.V1NetworkPolicySpec(
                pod_selector={"matchLabels": pod.metadata.labels or {"app": pod_name}},
                policy_types=["Ingress", "Egress"],
                ingress=[],
                egress=[]
            )
        )

        try:
            self.net_v1.create_namespaced_network_policy(
                namespace=self.namespace, body=policy)
            print(f"[RESPONSE] 🔒 Pod {pod_name} 网络已隔离 (NetworkPolicy)")
            self._audit_log(pod_name, "isolate_network", f"NetworkPolicy: {policy_name}")
        except client.ApiException as e:
            if e.status == 409:
                print(f"[INFO] Pod {pod_name} 已被隔离 (NetworkPolicy 已存在)")
            else:
                print(f"[ERROR] 隔离失败: {e}")

    def kill_pod(self, alert):
        """删除 Pod (K8s 中最直接的终止方式)"""
        pid = alert.get("pid", 0)
        pod = self._find_pod_by_cgroup(pid)

        if not pod:
            print(f"[WARN] 未找到 PID {pid} 对应的 Pod, 无法终止")
            self._audit_log("unknown", "kill_failed", str(alert))
            return

        pod_name = pod.metadata.name

        try:
            self.v1.delete_namespaced_pod(
                name=pod_name,
                namespace=self.namespace,
                body=client.V1DeleteOptions(grace_period_seconds=0)
            )
            print(f"[RESPONSE] ☠️  Pod {pod_name} 已删除")
            self._audit_log(pod_name, "kill_pod", f"Pod deleted")
        except client.ApiException as e:
            print(f"[ERROR] 删除 Pod 失败: {e}")

    def log_only(self, alert):
        """仅记录日志 (不执行阻断)"""
        pid = alert.get("pid", 0)
        pod = self._find_pod_by_cgroup(pid)
        pod_name = pod.metadata.name if pod else "unknown"
        print(f"[ALERT] {alert.get('rule_id', '?')} — {alert.get('message', '')}")
        self._audit_log(pod_name, "alert", str(alert))

    # ===== 审计日志 =====

    def _audit_log(self, pod_name, action, details):
        log_entry = {
            "timestamp": datetime.now().isoformat(),
            "pod": pod_name,
            "namespace": self.namespace,
            "action": action,
            "details": details[:200]  # 截断防止过长
        }
        print(f"[AUDIT] {json.dumps(log_entry, ensure_ascii=False)}")
