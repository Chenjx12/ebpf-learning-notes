# Makefile — eBPF 检测器容器化 + K8s 部署 (Week 2)
# 对应笔记: docs/Three-扩展/WEEK 2.md

IMAGE      ?= ebpf-detector
TAG        ?= latest
FULL_IMAGE := $(IMAGE):$(TAG)

.PHONY: build push deploy clean logs help

build:
	docker build -t $(FULL_IMAGE) .
	@echo "  ✅ 镜像构建完成: $(FULL_IMAGE)"

push:
	docker tag $(FULL_IMAGE) $(IMAGE):$(TAG)
	docker push $(FULL_IMAGE)

deploy:
	kubectl apply -f configmap.yaml
	kubectl apply -f rbac.yaml
	kubectl apply -f daemonset.yaml
	@echo "  ✅ DaemonSet 部署完成"
	@echo "  kubectl get pods -l app=ebpf-detector"

status:
	kubectl get pods -l app=ebpf-detector -o wide
	kubectl get daemonset ebpf-detector

logs:
	kubectl logs -l app=ebpf-detector --tail=50 -f

clean:
	kubectl delete daemonset ebpf-detector --ignore-not-found
	kubectl delete configmap ebpf-detector-config --ignore-not-found
	kubectl delete serviceaccount ebpf-detector --ignore-not-found
	kubectl delete clusterrole ebpf-detector --ignore-not-found
	kubectl delete clusterrolebinding ebpf-detector --ignore-not-found
	@echo "  🧹 K8s 资源已清理"

help:
	@echo "  make build    构建 Docker 镜像"
	@echo "  make deploy   部署到 K8s"
	@echo "  make status   查看运行状态"
	@echo "  make logs     查看日志"
	@echo "  make clean    清理 K8s 资源"
