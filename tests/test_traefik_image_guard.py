"""Проверка образа предшествует изменениям роли; исполнение image.yml — в invalid.yml."""
import pathlib
import unittest

from ansible.parsing.dataloader import DataLoader

ROOT = pathlib.Path(__file__).resolve().parent.parent


class TraefikImageGuard(unittest.TestCase):
    def test_image_check_is_first_task(self):
        tasks = DataLoader().load_from_file(str(ROOT / "roles/traefik/tasks/main.yml"))
        self.assertIsInstance(tasks, list)
        self.assertTrue(tasks, "роль Traefik не должна быть пустой")
        first = tasks[0]
        self.assertEqual(first.get("ansible.builtin.import_tasks"), "image.yml",
                         "проверка image.yml должна быть первой, до file/template/copy/compose")
        self.assertNotIn("when", first, "проверку образа нельзя пропускать по условию")
