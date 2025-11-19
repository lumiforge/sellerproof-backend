#!/bin/bash

# Скрипт для запуска тестов с различными опциями

set -e

# Цвета для вывода
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# URL сервиса по умолчанию
SERVICE_URL="https://xxxj.4b4k4pg5.apigw.yandexcloud.net"

# Функция для вывода цветного текста
print_color() {
    printf "${1}${2}${NC}\n"
}

# Функция для вывода заголовка
print_header() {
    print_color $BLUE "=================================="
    print_color $BLUE "$1"
    print_color $BLUE "=================================="
}

# Функция для вывода успеха
print_success() {
    print_color $GREEN "✅ $1"
}

# Функция для вывода ошибки
print_error() {
    print_color $RED "❌ $1"
}

# Функция для вывода предупреждения
print_warning() {
    print_color $YELLOW "⚠️  $1"
}

# Функция для вывода информации
print_info() {
    print_color $BLUE "ℹ️  $1"
}

# Показать справку
show_help() {
    echo "Использование: $0 [ОПЦИИ]"
    echo ""
    echo "ОПЦИИ:"
    echo "  -h, --help              Показать эту справку"
    echo "  -u, --url URL           URL сервиса (по умолчанию: $SERVICE_URL)"
    echo "  -d, --debug             Запуск с отладочными логами"
    echo "  -v, --verbose           Подробный вывод"
    echo "  -b, --build             Только сборка, без запуска"
    echo "  -c, --clean             Очистка перед сборкой"
    echo "  -t, --timeout SECONDS   Таймаут для тестов (по умолчанию: 30)"
    echo "  --auth-only             Запустить только тесты аутентификации"
    echo "  --video-only            Запустить только тесты видео"
    echo "  --no-color              Отключить цветной вывод"
    echo ""
    echo "ПРИМЕРЫ:"
    echo "  $0                      Запуск всех тестов"
    echo "  $0 -d                   Запуск с отладочными логами"
    echo "  $0 -u https://example.com  Запуск с другим URL"
    echo "  $0 --auth-only          Только тесты аутентификации"
    echo "  $0 --video-only         Только тесты видео"
}

# Парсинг аргументов
BUILD_ONLY=false
CLEAN=false
DEBUG=false
VERBOSE=false
AUTH_ONLY=false
VIDEO_ONLY=false
NO_COLOR=false
TIMEOUT=30

while [[ $# -gt 0 ]]; do
    case $1 in
        -h|--help)
            show_help
            exit 0
            ;;
        -u|--url)
            SERVICE_URL="$2"
            shift 2
            ;;
        -d|--debug)
            DEBUG=true
            shift
            ;;
        -v|--verbose)
            VERBOSE=true
            shift
            ;;
        -b|--build)
            BUILD_ONLY=true
            shift
            ;;
        -c|--clean)
            CLEAN=true
            shift
            ;;
        -t|--timeout)
            TIMEOUT="$2"
            shift 2
            ;;
        --auth-only)
            AUTH_ONLY=true
            shift
            ;;
        --video-only)
            VIDEO_ONLY=true
            shift
            ;;
        --no-color)
            NO_COLOR=true
            RED=''
            GREEN=''
            YELLOW=''
            BLUE=''
            NC=''
            shift
            ;;
        *)
            print_error "Неизвестная опция: $1"
            show_help
            exit 1
            ;;
    esac
done

# Проверка взаимоисключающих опций
if [[ "$AUTH_ONLY" == true && "$VIDEO_ONLY" == true ]]; then
    print_error "Опции --auth-only и --video-only не могут использоваться вместе"
    exit 1
fi

# Основная часть
print_header "Тестовый клиент SellerProof Backend"

print_info "URL сервиса: $SERVICE_URL"
print_info "Таймаут: ${TIMEOUT} секунд"

if [[ "$DEBUG" == true ]]; then
    print_info "Режим отладки: включен"
fi

if [[ "$VERBOSE" == true ]]; then
    print_info "Подробный вывод: включен"
fi

if [[ "$AUTH_ONLY" == true ]]; then
    print_info "Только тесты аутентификации"
elif [[ "$VIDEO_ONLY" == true ]]; then
    print_info "Только тесты видео"
fi

echo ""

# Очистка, если нужно
if [[ "$CLEAN" == true ]]; then
    print_info "Очистка..."
    make clean
    print_success "Очистка завершена"
    echo ""
fi

# Сборка
print_info "Сборка тестового клиента..."
if make build SERVICE_URL="$SERVICE_URL"; then
    print_success "Сборка завершена успешно"
else
    print_error "Ошибка сборки"
    exit 1
fi
echo ""

# Если только сборка, выходим
if [[ "$BUILD_ONLY" == true ]]; then
    print_success "Сборка завершена"
    exit 0
fi

# Подготовка переменных окружения
export SERVICE_URL
export TIMEOUT

if [[ "$DEBUG" == true ]]; then
    export GODEBUG=http2debug=1
fi

if [[ "$VERBOSE" == true ]]; then
    export VERBOSE=1
fi

if [[ "$AUTH_ONLY" == true ]]; then
    export TEST_MODE=auth
elif [[ "$VIDEO_ONLY" == true ]]; then
    export TEST_MODE=video
fi

# Запуск тестов
print_info "Запуск тестов..."
echo ""

if [[ "$DEBUG" == true ]]; then
    ./test-client 2>&1 | tee test.log
else
    ./test-client
fi

# Проверка результата
if [[ ${PIPESTATUS[0]} -eq 0 ]]; then
    print_success "Все тесты завершены успешно!"
else
    print_error "Тесты завершились с ошибками"
    if [[ "$DEBUG" == true ]]; then
        print_info "Подробный лог сохранен в test.log"
    fi
    exit 1
fi