.PHONY: quick full

quick:
	python3 -m unittest discover -s tests -q
	python3 -m compileall -q agentopsy.py tests
	git diff --check

full:
	python3 -m unittest discover -s tests -v
	pytest -q
	python3 -m compileall -q .
	git diff --check
	python3 agentopsy.py --help
	python3 agentopsy.py --version
