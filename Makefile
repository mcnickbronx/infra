# Короткие команды для частых действий. Подробности — README.md, «Как вносить изменения».
.PHONY: help venv check test-vds

help:
	@echo "make venv      — один раз: инструменты проверок в .venv (версии как в CI)"
	@echo "make check     — все проверки без серверов (как CI), перед каждым коммитом"
	@echo "make test-vds  — по желанию, есть тестовая VDS (TEST_VDS=$(TEST_VDS)): копия движка, проверки, сценарии; ~30 минут"

venv:
	python3 -m venv .venv
	.venv/bin/pip install -q --upgrade pip
	.venv/bin/pip install -q -r requirements-dev.txt

check:
	tools/check.sh

# Тестовый сервер: в его /etc/infra/server.yml — test_server: true (сценарии ломают данные).
# Свой адрес — в окружении (export TEST_VDS=admin@<IP>) или в команде: make test-vds TEST_VDS=admin@<IP>
TEST_VDS ?=

test-vds:
	@[ -n "$(TEST_VDS)" ] || { echo "нужен тестовый сервер: make test-vds TEST_VDS=admin@<IP>" >&2; exit 1; }
	tools/rollout.sh $(TEST_VDS) --scenarios
