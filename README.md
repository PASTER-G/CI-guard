# DevOps Project - Security Scanner для Terraform

Этот проект демонстрирует автоматизацию проверки безопасности инфраструктурного кода с использованием Terraform и Python. Security Scanner интегрируется в CI/CD пайплайн и реализует принцип Shift-Left Security.

## Архитектура

- **Язык программирования**: Python 3
- **Инфраструктура**: Terraform
- **CI/CD**: GitHub Actions, GitLab CI
- **Безопасность**: Shift-left security approach

## Структура проекта
```
.
├── .github/
│ └── workflows/
│ └── security-scan.yml # Workflow для GitHub Actions
├── scanner/
│ └── security_scanner.py # Python скрипт для сканирования
├── .gitlab-ci.yml # Конфигурация для GitLab CI
├── main.tf # Пример Terraform конфигурации с уязвимостями
├── requirements.txt # Зависимости Python
├── .gitignore # Игнорируемые файлы Git
└── README.md # Документация
```

## Предварительные требования

- Terraform >= 1.0
- Python >= 3.8

## Использование

### Локальный запуск

1. Клонируйте репозиторий:
```bash
git clone https://github.com/PASTER-G/CI-guard.git
cd CI-guard
```
2. Инициализируйте Terraform:
```bash
terraform init
```
3. Запустите сканер:
```bash
cd scanner
python security_scanner.py --tf-dir=..
```

## Интеграция в CI/CD
### GitHub Actions
Workflow (.github/workflows/security-scan.yml) уже настроен и автоматически запускается при пуше в main и при создании пул-реквеста.

### GitLab CI
Пример файла .gitlab-ci.yml также включен в репозиторий.

## Что сканирует
- Security Groups, разрешающие доступ с 0.0.0.0/0 к портам 22 (SSH) или 3389 (RDP)
- Диски, не шифрованные по умолчанию

## Пример вывода
При обнаружении уязвимостей скрипт выводит:
```
--- SECURITY ALERT ---
Resource: null_resource.insecure_sg_rdp
Code: INSECURE_CIDR
Message: Обнаружено небезопасное правило: порт 3389 открыт для всего интернета (0.0.0.0/0)
--------------------------
```

## Что можно улучшить
- Добавить больше правил для проверки безопасности
- Добавить поддержку облачных провайдеров
- Реализовать отправку уведомлений в Slack/Telegram

## Автор
[PASTER-G](https://github.com/PASTER-G)