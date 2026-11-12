venv:
	virtualenv -p python3 venv
	venv/bin/pip install -r requirements.txt -r dev-requirements.txt

compile-deps:
	venv/bin/pip-compile requirements.in
	venv/bin/pip-compile dev-requirements.in

upgrade-deps:
	venv/bin/pip-compile --upgrade requirements.in
	venv/bin/pip-compile --upgrade dev-requirements.in

update-deps: upgrade-deps

install-service:
	mkdir -p ~/.config/systemd/user
	ln -sf $(CURDIR)/sonzai_x.service ~/.config/systemd/user/
