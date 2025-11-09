#!/bin/bash

# ==============================================================================
# Установочный скрипт для проекта syscall-eBPF
#
# Этот скрипт автоматизирует загрузку, сборку и установку пакетов
# 'syscall-inspector' и 'alterator-syscall-inspector'.
# ==============================================================================


BUILD_USER="builder_syscall_ebpf"
REPO="Kirde001/syscall-eBPF"
API_URL="https://api.github.com/repos/$REPO/releases/latest"

set -e
set -o pipefail

info() {
    echo -e "\e[34m[INFO]\e[0m $1"
}

error() {
    echo -e "\e[31m[ERROR]\e[0m $1" >&2
    exit 1
}

success() {
    echo -e "\e[32m[SUCCESS]\e[0m $1"
}

check_root() {
    if [ "$EUID" -ne 0 ]; then
        error "Пожалуйста, запустите этот скрипт от имени root или с помощью sudo."
    fi
}

install_dependencies() {
    info "Обновление списка пакетов..."
    apt-get update

    info "Установка зависимостей для сборки и работы..."
    apt-get install -y rpm-build curl jq python3-module-bcc sqlite3 rpm-build-python3
}

get_latest_release_url() {
    info "Поиск последнего релиза на GitHub..." >&2
    local latest_url
    latest_url=$(curl -s "$API_URL" | jq -r '.tarball_url')

    if [ -z "$latest_url" ] || [ "$latest_url" == "null" ]; then
        error "Не удалось найти URL последнего релиза. Проверьте репозиторий или ваше интернет-соединение." >&2
    fi
    echo "$latest_url"
}

setup_builder() {
    info "Создание временного пользователя-сборщика '$BUILD_USER'..."
    if id "$BUILD_USER" &>/dev/null; then
        info "Пользователь '$BUILD_USER' уже существует. Пропускаем создание."
    else
        useradd -m -s /bin/bash "$BUILD_USER"
    fi

    info "Создание структуры каталогов для RPM..."
    su - "$BUILD_USER" -c "mkdir -p ~/RPM/{SOURCES,SPECS,BUILD,RPMS,SRPMS}"
}

build_rpms() {
    local release_url=$1
    local archive_name="syscall-inspector-1.0.tar.gz"

    info "Загрузка исходного кода с $release_url..."
    curl -L "$release_url" -o "/home/$BUILD_USER/RPM/SOURCES/$archive_name"

    info "Очистка директории сборки..."
    su - "$BUILD_USER" -c "rm -rf ~/RPM/BUILD/*"

    info "Распаковка архива для получения .spec файла..."
    su - "$BUILD_USER" -c "tar -xzvf ~/RPM/SOURCES/$archive_name -C ~/RPM/BUILD"

    info "Определение имени директории..."
    local build_dir_name=$(su - "$BUILD_USER" -c "find ~/RPM/BUILD -mindepth 1 -maxdepth 1 -type d | head -1 | xargs basename")

    if [ -z "$build_dir_name" ]; then
        error "Не удалось определить имя директории в ~/RPM/BUILD"
    fi
    info "Найдена директория: $build_dir_name"

    info "Копирование .spec файла..."
    su - "$BUILD_USER" -c "cp ~/RPM/BUILD/$build_dir_name/packaging/syscall-inspector.spec ~/RPM/SPECS/"

    info "Запуск сборки RPM... Это может занять некоторое время."
    su - "$BUILD_USER" -c "rpmbuild -bb --define '_builddir_name $build_dir_name' ~/RPM/SPECS/syscall-inspector.spec"
}

install_rpms() {
    info "Удаление старых версий (если есть)..."
    rpm -e syscall-inspector alterator-syscall-inspector || true

    info "Установка новых RPM-пакетов..."
    local rpm_path="/home/$BUILD_USER/RPM/RPMS/noarch"
    rpm -Uvh "$rpm_path"/syscall-inspector-*.noarch.rpm "$rpm_path"/alterator-syscall-inspector-*.noarch.rpm

    info "Обновление конфигурации systemd..."
    systemctl daemon-reload

    info "Включение и запуск службы syscall-inspector..."
    systemctl enable --now syscall-inspector.service

    info "Перезапуск служб Alterator..."
    systemctl restart alteratord
    systemctl restart alterator-manager
}

cleanup() {
    info "Очистка: удаление временного пользователя '$BUILD_USER' и его файлов..."
    userdel -r "$BUILD_USER"
}

main() {
    check_root
    install_dependencies
    
    local latest_release_url
    latest_release_url=$(get_latest_release_url)
    
    setup_builder
    build_rpms "$latest_release_url"
    install_rpms
    cleanup

    success "Установка успешно завершена!"
    info "Модуль 'Инспектор Syscall' теперь доступен в Alterator (acc) и веб-интерфейсе."
}

main "$@"
