PYTHON ?= python3

.PHONY: run init-config

init-config:
	@if [ -f config.json ]; then \
		echo "config.json already exists"; \
		exit 0; \
	fi
	cp config.example.json config.json
	@echo "Created config.json from config.example.json"

run:
	@if [ ! -f config.json ]; then \
		echo "Missing config.json. Run: make init-config"; \
		exit 1; \
	fi
	$(PYTHON) src/btmon.py
