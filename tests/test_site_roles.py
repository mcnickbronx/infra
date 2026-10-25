"""site.yml применяет все роли движка и в объявленном порядке: без этой проверки пропавшую строку `- role: …`
не видит ни одна офлайн-проверка (синтаксис, ansible-lint, эталоны берут шаблоны из roles/ напрямую)."""
import importlib.util
import pathlib
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent

# Порядок — комментарии site.yml («Порядок важен», строка роли access); rootless — после project: web/ проектов
# создаёт project, rootless открывает её своим контейнерам
ORDER = [("preflight", "secrets"), ("docker", "traefik"), ("traefik", "crowdsec"), ("base", "access"),
         ("traefik", "access"), ("users", "project"), ("project", "rootless")]


@unittest.skipUnless(importlib.util.find_spec("yaml"), "нужен PyYAML (есть в .venv движка)")
class SiteRoles(unittest.TestCase):
    def test_all_roles_in_order(self):
        import yaml
        listed = [r["role"] for r in yaml.safe_load((ROOT / "site.yml").read_text())[0]["roles"]]
        on_disk = sorted(p.parent.parent.name for p in ROOT.glob("roles/*/tasks/main.yml"))
        self.assertEqual(sorted(listed), on_disk, "роль есть в roles/, но не в site.yml (или наоборот, или дважды)")
        for before, after in ORDER:
            self.assertLess(listed.index(before), listed.index(after), f"{before} должна быть раньше {after}")
