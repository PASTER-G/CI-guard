#!/usr/bin/env python3
"""
Security Scanner for Terraform Plan
Integrates into CI/CD to enforce security checks.
"""

import json
import subprocess
import sys
import argparse
import os
import re
from typing import Dict, Any, List

class TerraformSecurityScanner:
    """
    Класс для сканирования вывода `terraform plan` на наличие небезопасных конфигураций.
    """
    def __init__(self, terraform_dir: str):
        self.vulnerabilities_found = 0
        self.plan_data = None
        self.terraform_dir = os.path.abspath(terraform_dir)
        self.plan_file = os.path.join(self.terraform_dir, "plan.tfplan")

    def run_terraform_command(self, command: List[str]) -> str:
        """Выполняет команду Terraform в указанной директории."""
        try:
            result = subprocess.run(
                command,
                cwd=self.terraform_dir,
                check=True,
                capture_output=True,
                text=True
            )
            return result.stdout
        except subprocess.CalledProcessError as e:
            print(f"Ошибка при выполнении команды Terraform: {e}")
            print(f"Stderr: {e.stderr}")
            sys.exit(1)

    def normalize_json(self, json_str: str) -> str:
        """
        Нормализует JSON, удаляя лишние пробелы и форматирование,
        чтобы обеспечить консистентность между разными средами выполнения.
        """
        try:
            # Парсим и снова сериализуем JSON для нормализации
            parsed_json = json.loads(json_str)
            return json.dumps(parsed_json, separators=(',', ':'))
        except json.JSONDecodeError as e:
            print(f"Не удалось нормализовать JSON: {e}")
            return json_str

    def run_terraform_plan(self) -> str:
        """
        Выполняет команду `terraform plan` и возвращает JSON-вывод.
        Использование JSON гарантирует стабильный и предсказуемый парсинг.
        """
        print("Создание Terraform plan...")
        # -input=false предотвращает интерактивные запросы в CI/CD
        # -out plan.tfplan сохраняет план для последующего применения
        plan_command = ["terraform", "plan", "-input=false", f"-out={self.plan_file}"]
        self.run_terraform_command(plan_command)

        print("Конвертация Terraform plan в JSON...")
        # Конвертируем бинарный план в JSON
        show_command = ["terraform", "show", "-json", self.plan_file]
        plan_json = self.run_terraform_command(show_command)
        
        # Нормализуем JSON для консистентности между разными средами
        normalized_json = self.normalize_json(plan_json)
        print(f"Длина JSON до нормализации: {len(plan_json)} символов")
        print(f"Длина JSON после нормализации: {len(normalized_json)} символов")
        
        return normalized_json

    def parse_plan(self, plan_json: str) -> None:
        """Парсит JSON вывод плана и сохраняет его в атрибуте."""
        try:
            self.plan_data = json.loads(plan_json)
        except json.JSONDecodeError as e:
            print(f"Не удалось распарсить JSON: {e}")
            sys.exit(1)

    def check_insecure_cidr(self, resource: Dict[str, Any]) -> None:
        """
        Проверяет ресурсы на наличие небезопасных правил CIDR (0.0.0.0/0).
        Анализирует JSON в триггерах null_resource.
        """
        if resource['type'] == "null_resource" and 'insecure_sg' in resource.get('name', ''):
            # Получаем значения триггеров
            values = resource.get('values', {})
            triggers = values.get('triggers', {})
            
            # Ищем правило безопасности в триггерах
            rule_json = triggers.get('rule')
            if rule_json:
                try:
                    rule = json.loads(rule_json)
                    cidr = rule.get('cidr', '')
                    port = rule.get('port', '')
                    
                    # Проверяем на небезопасные конфигурации
                    if cidr == "0.0.0.0/0" and port in [22, 3389]:
                        self.report_vulnerability(
                            resource['type'],
                            resource['name'],
                            "INSECURE_CIDR",
                            f"Обнаружено небезопасное правило: порт {port} открыт для всего интернета (0.0.0.0/0)"
                        )
                except json.JSONDecodeError:
                    print(f"Не удалось распарсить JSON в триггерах ресурса {resource['name']}")

    def check_unencrypted_disks(self, resource: Dict[str, Any]) -> None:
        """Проверяет ресурсы на наличие незашифрованных дисков."""
        if resource['type'] == "null_resource" and 'unencrypted' in resource.get('name', ''):
            # Получаем значения триггеров
            values = resource.get('values', {})
            triggers = values.get('triggers', {})
            
            # Ищем конфигурацию диска в триггерах
            config_json = triggers.get('config')
            if config_json:
                try:
                    config = json.loads(config_json)
                    encrypted = config.get('encrypted', True)
                    
                    # Проверяем на незашифрованные диски
                    if not encrypted:
                        self.report_vulnerability(
                            resource['type'],
                            resource['name'],
                            "UNENCRYPTED_DISK",
                            "Обнаружен незашифрованный диск. Требуется включить шифрование."
                        )
                except json.JSONDecodeError:
                    print(f"Не удалось распарсить JSON в триггерах ресурса {resource['name']}")

    def report_vulnerability(self, resource_type: str, resource_name: str, vuln_code: str, message: str) -> None:
        """Увеличивает счетчик уязвимостей и выводит понятное сообщение."""
        self.vulnerabilities_found += 1
        print(f"\n--- SECURITY ALERT ---")
        print(f"Resource: {resource_type}.{resource_name}")
        print(f"Code: {vuln_code}")
        print(f"Message: {message}")
        print("--------------------------\n")

    def scan(self) -> None:
        """Основной метод, запускающий весь процесс сканирования."""
        print(f"Запуск Terraform Security Scanner в директории: {self.terraform_dir}")
        
        # Проверяем, существует ли директория с Terraform-конфигурацией
        if not os.path.exists(self.terraform_dir):
            print(f"Директория {self.terraform_dir} не существует!")
            sys.exit(1)
            
        # Проверяем, есть ли в директории Terraform-файлы
        tf_files = [f for f in os.listdir(self.terraform_dir) if f.endswith('.tf')]
        if not tf_files:
            print(f"В директории {self.terraform_dir} нет .tf файлов!")
            sys.exit(1)
            
        print("Этап 1: Инициализация Terraform...")
        self.run_terraform_command(["terraform", "init"])

        print("Этап 2: Генерация плана Terraform...")
        plan_json = self.run_terraform_plan()

        print("Этап 3: Парсинг плана...")
        self.parse_plan(plan_json)

        print("Этап 4: Сканирование ресурсов на уязвимости...")
        # Проходим по всем ресурсам в плане
        resources = self.plan_data.get('planned_values', {}).get('root_module', {}).get('resources', [])
        for resource in resources:
            self.check_insecure_cidr(resource)
            self.check_unencrypted_disks(resource)
            # Здесь можно добавить другие проверки...

        # Финальный отчет
        print("=" * 50)
        print("SCAN SUMMARY")
        print(f"Проверено ресурсов: {len(resources)}")
        print(f"Найдено уязвимостей: {self.vulnerabilities_found}")
        print("=" * 50)

        if self.vulnerabilities_found > 0:
            print("Сканирование завершено с ошибками. Пайплайн должен быть остановлен.")
            sys.exit(1) # Это "уронит" пайплайн
        else:
            print("Сканирование завершено успешно. Критических уязвимостей не найдено.")
            sys.exit(0)

def main():
    """Точка входа в скрипт."""
    parser = argparse.ArgumentParser(description='Security Scanner for Terraform Plan')
    parser.add_argument('--tf-dir', 
                        default='..', 
                        help='Путь к директории с Terraform-конфигурацией (по умолчанию: . директория)')
    args = parser.parse_args()

    scanner = TerraformSecurityScanner(args.tf_dir)
    scanner.scan()

if __name__ == "__main__":
    main()