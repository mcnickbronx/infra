"""site.yml перечисляет все роли движка в объявленном порядке, без специального never на записи роли.
Пропавшую строку `- role: …` не видят синтаксис, ansible-lint и эталоны: они берут шаблоны из roles/ напрямую.
Исполнение задач ролей и прочие условия их пропуска эта офлайн-проверка не проверяет."""
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
        roles = yaml.safe_load((ROOT / "site.yml").read_text())[0]["roles"]
        listed = [r["role"] for r in roles]
        on_disk = sorted(p.parent.parent.name for p in ROOT.glob("roles/*/tasks/main.yml"))
        self.assertEqual(sorted(listed), on_disk, "роль есть в roles/, но не в site.yml (или наоборот, или дважды)")
        for before, after in ORDER:
            self.assertLess(listed.index(before), listed.index(after), f"{before} должна быть раньше {after}")
        for role in roles:
            tags = role.get("tags", [])
            if isinstance(tags, str):
                tags = [tag.strip() for tag in tags.split(",")]
            self.assertNotIn("never", tags, f"site.yml: у обязательной роли {role['role']} запрещён тег never")
