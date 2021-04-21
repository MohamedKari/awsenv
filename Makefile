venv:
	python -m venv .env
	source .env/bin/activate && \
		pip install --upgrade pip \
		pip install -r requirements.txt

	echo "To activate the venv, run 'source .env/bin/activate'"

clean:
	rm -rf build dist awsenv/*.egg-info
	rm -rf awsenv_MohamedKari.egg-info

dist: clean
	python -m pip install --upgrade build
	python -m build

upload: dist
	pip install --upgrade twine
	python -m twine upload --repository pypi dist/*


