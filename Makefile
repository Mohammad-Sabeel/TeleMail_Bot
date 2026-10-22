PY := .venv/bin/python

.PHONY: test label sync status bot corpus probe evaluate evaluate-offline clean

test:
	$(PY) -m pytest -q

label:
	$(PY) -m scripts.label

sync:
	$(PY) -m telemail sync

status:
	$(PY) -m telemail status

bot:
	$(PY) -m telemail bot

corpus:
	$(PY) -m scripts.harvest_corpus --per-technique 3 --seed 42

# make probe MODEL=<openrouter-model-id>
probe:
	$(PY) -m scripts.probe_model $(if $(MODEL),--model $(MODEL),)

# Needs no model and no labels.
evaluate-offline:
	$(PY) -m eval.phishing_clf
	$(PY) -m eval.injection_clf
	$(PY) -m eval.t11_headers
	$(PY) -m eval.reliability
	$(PY) -m eval.performance
	$(PY) -m eval.render > results/README.md
	@echo "wrote results/README.md (offline results only)"

# Every number in the report, from one command. Needs a model and >=20 labels.
# Run it twice and diff: anything that moves is non-determinism to explain.
evaluate:
	$(PY) -m eval.triage_metrics
	$(PY) -m eval.run_attacks --delimiters static
	$(PY) -m eval.run_attacks
	# Stage 1: the four invocations behind the published table. They APPEND to
	# results/goal_results.csv (see run_goals._write_merged), they do not replace it.
	$(PY) -m eval.run_goals --source llmail --split dev --limit 30
	$(PY) -m eval.run_goals --source llmail --split dev --cases control
	$(PY) -m eval.run_goals --source fixtures --split dev
	$(PY) -m eval.run_goals --source adaptive --split dev --rounds 2
	$(PY) -m eval.cross_batch
	$(PY) -m eval.phishing_clf
	$(PY) -m eval.injection_clf
	$(PY) -m eval.t11_headers
	$(PY) -m eval.reliability
	$(PY) -m eval.performance $(if $(PRICE_IN),--price-in $(PRICE_IN) --price-out $(PRICE_OUT),)
	$(PY) -m eval.render > results/README.md
	@echo "wrote results/README.md"

clean:
	rm -rf .pytest_cache
	find . -path ./.venv -prune -o -type d -name __pycache__ -exec rm -rf {} +
