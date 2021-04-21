venv:
	python -m venv .env
	source .env/bin/activate && \
		pip install --upgrade pip \
		pip install -r requirements.txt

	echo "To activate the venv, run 'source .env/bin/activate'"

dist: 
	python -m pip install --upgrade build
	python -m build

clean:
	rm -rf build dist awsenv/*.egg-info