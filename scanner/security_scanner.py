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

    def extract_json_from_output(self, output: str) -> str:
        """
        Извлекает чистый JSON из вывода terraform show.
        Использует метод raw_decode для извлечения первого JSON объекта.
        """
        # Удаляем ANSI escape sequences
        ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
        cleaned_output = ansi_escape.sub('', output)
        
        # Ищем начало JSON объекта
        start_idx = cleaned_output.find('{')
        if start_idx == -1:
            print("Не найдено начало JSON объекта в выводе")
            return ""
        
        # Используем raw_decode для извлечения первого JSON объекта
        try:
            decoder = json.JSONDecoder()
            obj, end_idx = decoder.raw_decode(cleaned_output[start_idx:])
            return json.dumps(obj, separators=(',', ':'))
        except json.JSONDecodeError as e:
            print(f"Ошибка при извлечении JSON: {e}")
            # Попробуем найти JSON с помощью регулярного выражения
            json_match = re.search(r'(\{.*\})', cleaned_output, re.DOTALL)
            if json_match:
                return json_match.group(1)
            return ""

    def get_terraform_plan_json(self) -> str:
        """
        Получает полный JSON вывод плана Terraform.
        """
        print("Создание бинарного плана Terraform...")
        
        # Убедимся, что старый план удален
        if os.path.exists(self.plan_file):
            os.remove(self.plan_file)
            
        # Создаем бинарный план
        plan_command = ["terraform", "plan", "-input=false", "-detailed-exitcode", f"-out={self.plan_file}"]
        try:
            # Используем detailed-exitcode, чтобы получить код 2 при изменениях
            result = subprocess.run(
                plan_command,
                cwd=self.terraform_dir,
                capture_output=True,
                text=True
            )
            
            # Код 0 - нет изменений, 1 - ошибка, 2 - есть изменения
            if result.returncode not in [0, 2]:
                print(f"Ошибка при создании плана: {result.stderr}")
                sys.exit(1)
                
        except Exception as e:
            print(f"Ошибка при выполнении terraform plan: {e}")
            sys.exit(1)

        # Проверяем, что план создан
        if not os.path.exists(self.plan_file):
            print("Файл плана не был создан!")
            sys.exit(1)
            
        print("Конвертация бинарного плана в JSON...")
        # Конвертируем бинарный план в JSON
        show_command = ["terraform", "show", "-json", self.plan_file]
        plan_output = self.run_terraform_command(show_command)
        
        # Извлекаем чистый JSON из вывода
        clean_json = self.extract_json_from_output(plan_output)
        
        if not clean_json.strip():
            print("Не удалось извлечь JSON из вывода")
            print(f"Исходный вывод: {plan_output}")
            sys.exit(1)
            
        return clean_json

    def parse_plan(self, plan_json: str) -> None:
        """Парсит JSON вывод плана и сохраняет его в атрибуте."""
        # Сохраняем сырой JSON для отладки
        with open("raw_plan.json", "w") as f:
            f.write(plan_json)
        print("Сырой JSON сохранен в raw_plan.json для отладки")
        
        try:
            self.plan_data = json.loads(plan_json)
            print("✓ JSON успешно распарсен")
        except json.JSONDecodeError as e:
            print(f"Не удалось распарсить JSON: {e}")
            print(f"Первые 500 символов JSON: {plan_json[:500]}")
            sys.exit(1)

    def check_insecure_cidr(self, resource: Dict[str, Any]) -> None:
        """
        Проверяет ресурсы на наличие небезопасных правил CIDR (0.0.0.0/0).
        Анализирует JSON в триггерах null_resource.
        """
        if resource['type'] == "null_resource":
            resource_name = resource.get('name', '')
            if 'insecure_sg' in resource_name:
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
                                resource_name,
                                "INSECURE_CIDR",
                                f"Обнаружено небезопасное правило: порт {port} открыт для всего интернета (0.0.0.0/0)"
                            )
                    except json.JSONDecodeError:
                        print(f"Не удалось распарсить JSON в триггерах ресурса {resource_name}")

    def check_unencrypted_disks(self, resource: Dict[str, Any]) -> None:
        """Проверяет ресурсы на наличие незашифрованных дисков."""
        if resource['type'] == "null_resource":
            resource_name = resource.get('name', '')
            if 'unencrypted' in resource_name:
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
                                resource_name,
                                "UNENCRYPTED_DISK",
                                "Обнаружен незашифрованный диск. Требуется включить шифрование."
                            )
                    except json.JSONDecodeError:
                        print(f"Не удалось распарсить JSON в триггерах ресурса {resource_name}")

    def report_vulnerability(self, resource_type: str, resource_name: str, vuln_code: str, message: str) -> None:
        """Увеличивает счетчик уязвимостей и выводит сообщение."""
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
        plan_json = self.get_terraform_plan_json()
        print(f"Получен JSON длиной {len(plan_json)} символов")

        print("Этап 3: Парсинг плана...")
        self.parse_plan(plan_json)

        print("Этап 4: Сканирование ресурсов на уязвимости...")
        # Проходим по всем ресурсам в плане
        planned_values = self.plan_data.get('planned_values', {})
        root_module = planned_values.get('root_module', {})
        resources = root_module.get('resources', [])
        
        print(f"Найдено ресурсов для анализа: {len(resources)}")
        
        for resource in resources:
            self.check_insecure_cidr(resource)
            self.check_unencrypted_disks(resource)

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