PYTHON ?= python

.PHONY: test cov mutate lint demo all
test:
	$(PYTHON) -m pytest
cov:
	$(PYTHON) -m pytest --cov=leakguard --cov-report=term-missing --cov-fail-under=90
mutate:
	mutmut run
	mutmut results
lint:
	ruff check .
demo:
	bash examples/demo.sh
all: lint cov demo
