.PHONY: start start-awake awake stop status last cycles monitor dashboard enterprise-api pause resume install uninstall team backup restore-drill clean-logs reset-consensus test validate help

UNAME_S := $(shell uname -s 2>/dev/null || echo Unknown)
ENGINE ?= claude
PYTHON ?= python3
DATABASE ?= data/organization.db
BACKUP_DIR ?= backups

# === Quick Start ===

start: ## Start the auto-loop in foreground
	./scripts/core/auto-loop.sh

start-awake: ## Start loop and prevent macOS sleep while running
ifeq ($(UNAME_S),Darwin)
	caffeinate -d -i -s $(MAKE) start
else
	@echo "start-awake is macOS-only (requires caffeinate)."
	@echo "Use 'make start' on Linux/WSL."
	@exit 1
endif

awake: ## Prevent macOS sleep while current loop PID is running
ifeq ($(UNAME_S),Darwin)
	@test -f .auto-loop.pid || (echo "No .auto-loop.pid found. Run 'make start' first."; exit 1)
	@pid=$$(cat .auto-loop.pid); \
	echo "Keeping Mac awake while PID $$pid is running..."; \
	caffeinate -d -i -s -w $$pid
else
	@echo "awake is macOS-only (requires caffeinate)."
	@echo "WSL usually inherits Windows power policy; keep your host from sleeping if needed."
	@exit 1
endif

stop: ## Stop the loop gracefully
	./scripts/core/stop-loop.sh

# === Monitoring and APIs ===

status: ## Show loop status + latest consensus
	./scripts/core/monitor.sh --status

last: ## Show last cycle's full output
	./scripts/core/monitor.sh --last

cycles: ## Show cycle history summary
	./scripts/core/monitor.sh --cycles

monitor: ## Tail live logs (Ctrl+C to exit)
	./scripts/core/monitor.sh

dashboard: ## Start the authenticated local dashboard server
	$(PYTHON) -m dashboard.secure_server

enterprise-api: ## Start the versioned authenticated enterprise API
	$(PYTHON) -m enterprise.api

# === Daemon (macOS launchd / Linux systemd --user) ===

install: ## Install daemon (macOS launchd or Linux/WSL systemd --user)
ifeq ($(UNAME_S),Darwin)
	./scripts/macos/install-daemon.sh
else
	./scripts/wsl/install-wsl-daemon.sh
endif

uninstall: ## Remove daemon (macOS launchd or Linux/WSL systemd --user)
ifeq ($(UNAME_S),Darwin)
	./scripts/macos/install-daemon.sh --uninstall
else
	./scripts/wsl/uninstall-wsl-daemon.sh
endif

pause: ## Pause daemon (no auto-restart)
ifeq ($(UNAME_S),Darwin)
	./scripts/core/stop-loop.sh --pause-daemon
else
	@command -v systemctl >/dev/null 2>&1 || (echo "systemctl not found. Ensure WSL systemd is enabled."; exit 1)
	@systemctl --user stop auto-company.service
	@echo "auto-company.service paused (stopped)."
endif

resume: ## Resume paused daemon
ifeq ($(UNAME_S),Darwin)
	./scripts/core/stop-loop.sh --resume-daemon
else
	@command -v systemctl >/dev/null 2>&1 || (echo "systemctl not found. Ensure WSL systemd is enabled."; exit 1)
	@systemctl --user start auto-company.service
	@echo "auto-company.service resumed (started)."
endif

# === Interactive ===

team: ## Start selected engine interactive session (ENGINE=claude|codex)
	@engine="$$(printf '%s' "$(ENGINE)" | tr '[:upper:]' '[:lower:]')"; \
	if [ "$$engine" != "claude" ] && [ "$$engine" != "codex" ]; then \
		echo "Unsupported ENGINE='$(ENGINE)'. Use ENGINE=claude or codex."; \
		exit 1; \
	fi; \
	cd "$(CURDIR)" && "$$engine"

# === Quality ===

test: ## Run all Python unit tests
	$(PYTHON) -m unittest discover -s tests -p 'test_*.py' -v

validate: ## Validate Python, Bash, JavaScript, and unit tests
	$(PYTHON) -m compileall -q dashboard organization enterprise production tests
	@find scripts -type f -name '*.sh' -print0 | xargs -0 -n1 bash -n
	@if command -v node >/dev/null 2>&1; then \
		find dashboard projects -type f -name '*.js' -print0 | xargs -0 -r -n1 node --check; \
	else \
		echo "node not found; JavaScript syntax validation skipped locally."; \
	fi
	$(MAKE) test

# === Recovery ===

backup: ## Create and verify a consistent database backup
	$(PYTHON) -c 'from production import RecoveryService; import json; service=RecoveryService("$(DATABASE)", "$(BACKUP_DIR)"); manifest=service.create_backup(); service.verify_backup(manifest["backup_id"]); print(json.dumps(manifest, indent=2))'

restore-drill: ## Restore and verify the most recent backup manifest
	$(PYTHON) -c 'from pathlib import Path; from production import RecoveryService; import json; manifests=sorted(Path("$(BACKUP_DIR)").glob("*.json"), key=lambda p:p.stat().st_mtime, reverse=True); assert manifests, "no backup manifests found"; backup_id=manifests[0].stem; print(json.dumps(RecoveryService("$(DATABASE)", "$(BACKUP_DIR)").restore_drill(backup_id), indent=2))'

# === Maintenance ===

clean-logs: ## Remove all cycle logs
	rm -f logs/cycle-*.log logs/auto-loop.log.old
	@echo "Cycle logs cleaned."

reset-consensus: ## Reset consensus to initial Day 0 state (CAUTION)
	@echo "This will reset all company progress. Ctrl+C to cancel."
	@sleep 3
	git checkout -- memories/consensus.md
	@echo "Consensus reset to initial state."

# === Help ===

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-18s\033[0m %s\n", $$1, $$2}'

.DEFAULT_GOAL := help
