# Atalhos para DogWatch
SHELL := /bin/bash

install:
	sudo ./install.sh

uninstall:
	sudo /opt/dogwatch/dogwatch.sh uninstall || true

enable:
	sudo systemctl enable --now dogwatch.service dogwatch-safelane.service

disable:
	sudo systemctl disable --now dogwatch.service dogwatch-safelane.service || true
	sudo systemctl stop dogwatch.service dogwatch-safelane.service || true

status:
	systemctl status --no-pager dogwatch.service dogwatch-safelane.service || true
	sudo /opt/dogwatch/dogwatch.sh status || true

logs:
	sudo tail -n 200 -f /var/log/dogwatch/dogwatch.log

menu:
	sudo /opt/dogwatch/dogwatch.sh

pkg:
	rm -f dogwatch.tar.gz
	tar -czf dogwatch.tar.gz dogwatch.sh dogwatch.service config.env.example install.sh Makefile README.md
	@echo "Pacote gerado: dogwatch.tar.gz"
