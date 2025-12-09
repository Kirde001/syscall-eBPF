#!/bin/bash

BUILD_USER="builder_syscall_ebpf"
ARCHIVE_NAME="syscall-inspector-1.0.tar.gz"
DIR_NAME="syscall-inspector-1.0" 

set -e
set -o pipefail

info() { echo -e "\e[34m[INFO]\e[0m $1"; }
error() { echo -e "\e[31m[ERROR]\e[0m $1" >&2; exit 1; }
success() { echo -e "\e[32m[SUCCESS]\e[0m $1"; }

check_root() {
    if [ "$EUID" -ne 0 ]; then
        error "Запускайте скрипт от имени root (sudo)."
    fi
}

install_deps() {
    if ! rpm -q alterator-sh-functions >/dev/null 2>&1; then
        info "Установка alterator-sh-functions..."
        apt-get install -y alterator-sh-functions || info "Не удалось установить через apt, попробуем продолжить..."
    fi
}

setup_builder() {
    info "Подготовка пользователя-сборщика '$BUILD_USER'..."
    if ! id "$BUILD_USER" &>/dev/null; then
        useradd -m -s /bin/bash "$BUILD_USER"
    fi
    
    rm -rf "/home/$BUILD_USER/RPM"
    su - "$BUILD_USER" -c "mkdir -p ~/RPM/{SOURCES,SPECS,BUILD,RPMS,SRPMS}"
}

prepare_sources() {
    info "Упаковка текущей директории в архив..."
    
    tar --exclude='.git' --exclude='install-locally.sh' --exclude='install.sh' \
        --exclude='*.tar.gz' --exclude='*.rpm' \
        --transform "s,^\.,$DIR_NAME," \
        -czf "/tmp/$ARCHIVE_NAME" .

    info "Перемещение исходников сборщику..."
    cp "/tmp/$ARCHIVE_NAME" "/home/$BUILD_USER/RPM/SOURCES/"
    cp "packaging/syscall-inspector.spec" "/home/$BUILD_USER/RPM/SPECS/"
    
    rm "/tmp/$ARCHIVE_NAME"
}

build_rpms() {
    info "Запуск сборки RPM..."
    su - "$BUILD_USER" -c "rpmbuild -bb --define '_builddir_name $DIR_NAME' ~/RPM/SPECS/syscall-inspector.spec"
}

install_rpms() {
    info "Удаление старых версий..."
    rpm -e syscall-inspector alterator-syscall-inspector 2>/dev/null || true

    info "Установка собранных пакетов..."
    local rpm_dir="/home/$BUILD_USER/RPM/RPMS/noarch"
    
    if rpm -Uvh --replacepkgs --replacefiles --nodeps "$rpm_dir"/syscall-inspector-*.rpm "$rpm_dir"/alterator-syscall-inspector-*.rpm; then
        success "RPM пакеты установлены."
    else
        error "Ошибка при установке RPM."
    fi
}

restart_services() {
    info "Перезапуск служб..."
    systemctl daemon-reload
    systemctl enable --now syscall-inspector.service
    
    if systemctl is-active --quiet alteratord; then
        systemctl restart alteratord
    fi
    if systemctl is-active --quiet alterator-manager; then
        systemctl restart alterator-manager
    fi
}

cleanup() {
    info "Очистка временного пользователя..."
    userdel -r "$BUILD_USER"
}

main() {
    check_root
    install_deps
    setup_builder
    prepare_sources
    build_rpms
    install_rpms
    restart_services
    cleanup
    
    success "Установка завершена."
}

main "$@"
