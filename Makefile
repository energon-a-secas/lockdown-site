.DEFAULT_GOAL := help

PORT = 8824

# ── Help ──────────────────────────────────────────────────────────────────────
.PHONY: help
help:
	@echo ""
	@echo "  make serve    Start dev server → http://localhost:$(PORT)"
	@echo "  make kill     Kill this project's HTTP server"
	@echo "  make convex   Run Convex backend"
	@echo "  make test     Run the scanner guard tests"
	@echo ""

# ── Dev server ────────────────────────────────────────────────────────────────
.PHONY: serve
serve:
	@echo "Serving → http://localhost:$(PORT)"
	@if [ -f ../../scripts/serve.py ]; then python3 ../../scripts/serve.py $(PORT); else python3 -m http.server $(PORT); fi

# ── Kill ──────────────────────────────────────────────────────────────────────
.PHONY: kill
kill:
	@lsof -ti :$(PORT) | xargs kill 2>/dev/null && echo "Stopped server on port $(PORT)" || echo "No server running on port $(PORT)"

# ── Convex ────────────────────────────────────────────────────────────────────
.PHONY: convex
convex:
	@npx convex dev

# ── Tests ─────────────────────────────────────────────────────────────────────
.PHONY: test
test:
	@node --experimental-strip-types tests/guard.test.ts
