venv:
	virtualenv -p python3 venv
	venv/bin/pip install -r requirements.txt

install-service:
	mkdir -p ~/.config/systemd/user
	ln -sf $(CURDIR)/sonzai_x.service ~/.config/systemd/user/
