.PHONY: all setup verify test demo audit teardown

all: setup verify demo

setup:
	@./scripts/setup.sh

verify:
	@./scripts/verify.sh

test:
	@PYTHONPATH=. python3 -m unittest discover -s tests -p "test_*.py"

demo:
	@./scripts/demo.sh

audit:
	@./scripts/audit_anti_hardcoding.sh

teardown:
	@./scripts/teardown.sh
