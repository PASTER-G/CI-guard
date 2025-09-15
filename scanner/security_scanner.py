#!/usr/bin/env python3
"""
Security Scanner for Terraform Plan
Integrates into CI/CD to enforce security checks (Shift-Left).
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

    def run_terraform_command(self, command: List[str]) -> str:
        """Выполняет команду Terraform в указанной директории."""
        try:
            result = subprocess.run(
                command,
                cwd=self.terraform_dir,
                check=True,
                capture_output=True,
                text=True,
                timeout=300
            )
            return result.stdout
        except subprocess.CalledProcessError as e:
            print(f"❌ Ошибка при выполнении команды Terraform: {e}")
            print(f"Stderr: {e.stderr}")
            print(f"Stdout: {e.stdout}")
            sys.exit(1)
        except subprocess.TimeoutExpired:
            print(f"❌ Таймаут при выполнении команды: {' '.join(command)}")
            sys.exit(1)

    def run_terraform_plan(self) -> str:
        """
        Выполняет команду `terraform plan` с флагом -json и возвращает JSON-вывод.
        """
        print("✓ Создание Terraform plan в JSON формате...")
        
        # Используем флаг -json для получения вывода напрямую в JSON формате
        plan_command = ["terraform", "plan", "-input=false", "-json"]
        plan_output = self.run_terraform_command(plan_command)
        
        # Извлекаем JSON из потока вывода
        plan_json = self.extract_json_from_stream(plan_output)
        
        if not plan_json:
            print("❌ Не удалось извлечь JSON из вывода")
            print(f"Полный вывод: {plan_output}")
            sys.exit(1)
            
        print(f"✓ Извлечен JSON длиной {len(plan_json)} символов")
        
        # Нормализуем JSON (удаляем лишние пробелы и форматирование)
        normalized_json = self.normalize_json(plan_json)
        print(f"✓ Нормализованный JSON длиной {len(normalized_json)} символов")
        
        return normalized_json

    def extract_json_from_stream(self, output: str) -> str:
        """
        Извлекает JSON из потока вывода terraform plan -json.
        Terraform выводит несколько JSON объектов, нам нужен последний (полный план).
        """
        # Разделяем вывод по строкам и ищем JSON объекты
        lines = output.strip().split('\n')
        json_objects = []
        
        for line in lines:
            line = line.strip()
            if line and (line.startswith('{') and line.endswith('}')):
                try:
                    # Пытаемся парсить каждую строку как JSON
                    json.loads(line)
                    json_objects.append(line)
                except json.JSONDecodeError:
                    # Пропускаем не-JSON строки
                    continue
        
        if not json_objects:
            print("❌ Не найдено JSON в выводе")
            print(f"Вывод: {output}")
            return ""
        
        # Берем последнюю JSON строку, которая должна содержать полный план
        return json_objects[-1]

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
            print(f"❌ Не удалось нормализовать JSON: {e}")
            return json_str

    def parse_plan(self, plan_json: str) -> None:
        """Парсит JSON вывод плана и сохраняет его в атрибуте."""
        try:
            self.plan_data = json.loads(plan_json)
            print("✓ JSON успешно распарсен")
        except json.JSONDecodeError as e:
            print(f"❌ Не удалось распарсить JSON: {e}")
            print(f"Проблема в позиции {e.pos}: {plan_json[max(0, e.pos-50):e.pos+50]}")
            # Сохраняем JSON в файл для отладки
            with open("debug_plan.json", "w") as f:
                f.write(plan_json)
            print("✓ JSON сохранен в файл debug_plan.json для отладки")
            sys.exit(1)

    def parse_plan(self, plan_json: str) -> None:
        """Парсит JSON вывод плана и сохраняет его в атрибуте."""
        try:
            self.plan_data = json.loads(plan_json)
            print("✓ JSON успешно распарсен")
        except json.JSONDecodeError as e:
            print(f"❌ Не удалось распарсить JSON: {e}")
            print(f"Проблема в позиции {e.pos}: {plan_json[max(0, e.pos-50):e.pos+50]}")
            print(f"Полный JSON: {plan_json}")
            sys.exit(1)

    def check_insecure_cidr(self, resource: Dict[str, Any]) -> None:
        """Проверяет ресурсы на наличие небезопасных правил CIDR."""
        if resource['type'] == "null_resource" and 'insecure_sg' in resource.get('name', ''):
            values = resource.get('values', {})
            triggers = values.get('triggers', {})
            
            rule_json = triggers.get('rule')
            if rule_json:
                try:
                    rule = json.loads(rule_json)
                    cidr = rule.get('cidr', '')
                    port = rule.get('port', '')
                    
                    if cidr == "0.0.0.0/0" and port in [22, 3389]:
                        self.report_vulnerability(
                            resource['type'],
                            resource['name'],
                            "INSECURE_CIDR",
                            f"Обнаружено небезопасное правило: порт {port} открыт для всего интернета (0.0.0.0/0)"
                        )
                except json.JSONDecodeError:
                    print(f"⚠️ Не удалось распарсить JSON в триггерах ресурса {resource['name']}")

    def check_unencrypted_disks(self, resource: Dict[str, Any]) -> None:
        """Проверяет ресурсы на наличие незашифрованных дисков."""
        if resource['type'] == "null_resource" and 'unencrypted' in resource.get('name', ''):
            values = resource.get('values', {})
            triggers = values.get('triggers', {})
            
            config_json = triggers.get('config')
            if config_json:
                try:
                    config = json.loads(config_json)
                    encrypted = config.get('encrypted', True)
                    
                    if not encrypted:
                        self.report_vulnerability(
                            resource['type'],
                            resource['name'],
                            "UNENCRYPTED_DISK",
                            "Обнаружен незашифрованный диск. Требуется включить шифрование."
                        )
                except json.JSONDecodeError:
                    print(f"⚠️ Не удалось распарсить JSON в триггерах ресурса {resource['name']}")

    def report_vulnerability(self, resource_type: str, resource_name: str, vuln_code: str, message: str) -> None:
        """Увеличивает счетчик уязвимостей и выводит понятное сообщение."""
        self.vulnerabilities_found += 1
        print(f"\n--- 🔴 SECURITY ALERT ---")
        print(f"Resource: {resource_type}.{resource_name}")
        print(f"Code: {vuln_code}")
        print(f"Message: {message}")
        print("--------------------------\n")

    def scan(self) -> None:
        """Основной метод, запускающий весь процесс сканирования."""
        print(f"🚀 Запуск Terraform Security Scanner в директории: {self.terraform_dir}")
        
        # Проверяем, существует ли директория с Terraform-конфигурацией
        if not os.path.exists(self.terraform_dir):
            print(f"❌ Директория {self.terraform_dir} не существует!")
            sys.exit(1)
            
        # Проверяем, есть ли в директории Terraform-файлы
        tf_files = [f for f in os.listdir(self.terraform_dir) if f.endswith('.tf')]
        if not tf_files:
            print(f"❌ В директории {self.terraform_dir} нет .tf файлов!")
            sys.exit(1)
            
        print("Этап 1: Инициализация Terraform...")
        self.run_terraform_command(["terraform", "init"])

        print("Этап 2: Генерация плана Terraform...")
        plan_json = self.run_terraform_plan()

        print("Этап 3: Парсинг плана...")
        self.parse_plan(plan_json)

        print("Этап 4: Сканирование ресурсов на уязвимости...")
        resources = self.plan_data.get('planned_values', {}).get('root_module', {}).get('resources', [])
        for resource in resources:
            self.check_insecure_cidr(resource)
            self.check_unencrypted_disks(resource)

        # Финальный отчет
        print("=" * 50)
        print("📊 SCAN SUMMARY")
        print(f"Проверено ресурсов: {len(resources)}")
        print(f"Найдено уязвимостей: {self.vulnerabilities_found}")
        print("=" * 50)

        if self.vulnerabilities_found > 0:
            print("❌ Сканирование завершено с ошибками. Пайплайн должен быть остановлен.")
            sys.exit(1)
        else:
            print("✅ Сканирование завершено успешно. Критических уязвимостей не найдено.")
            sys.exit(0)

def main():
    """Точка входа в скрипт."""
    parser = argparse.ArgumentParser(description='Security Scanner for Terraform Plan')
    parser.add_argument('--tf-dir', 
                        default='..', 
                        help='Путь к директории с Terraform-конфигурацией (по умолчанию: родительская директория)')
    args = parser.parse_args()

    scanner = TerraformSecurityScanner(args.tf_dir)
    scanner.scan()

if __name__ == "__main__":
    main()