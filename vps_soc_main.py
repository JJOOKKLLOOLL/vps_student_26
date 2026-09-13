import os
import sys

# Добавляем текущую директорию в пути импорта
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

# Импортируем модуль аналитики
try:
    import vps_soc_analyzer as analyzer
except ImportError:
    print("[!] Не найден файл vps_soc_analyzer.py")
    sys.exit(1)


def run_pipeline(ssh_log_path: str, nginx_log_path: str = None) -> None:
    """
    Конвейер Mini-SOC:
      1. Анализ SSH-логов (брутфорс)
      2. Анализ Nginx-логов (подозрительные пути)
      3. Оценка уровня риска
      4. Контроль целостности конфигурации
      5. Сканирование портов
    """
    print("=" * 60)
    print("        АНАЛИЗ ЛОГОВ БЕЗОПАСНОСТИ VPS (Mini-SOC)")
    print("=" * 60)

    # --- Проверка SSH-лога ---
    if not os.path.exists(ssh_log_path):
        print(f"[!] SSH-лог не найден: {ssh_log_path}")
        return
    print(f"[+] SSH-лог: {ssh_log_path}")

    if nginx_log_path and os.path.exists(nginx_log_path):
        print(f"[+] Nginx-лог: {nginx_log_path}")
    else:
        nginx_log_path = None
        print("[i] Nginx-лог не найден — анализ веб-запросов пропущен.")
    print("-" * 60)

    # --- Шаг 1. Анализ SSH-логов (брутфорс) ---
    with open(ssh_log_path, "r", encoding="utf-8", errors="ignore") as f:
        ssh_lines = f.readlines()

    ip_attempts = analyzer.group_by_ip(ssh_lines)
    bf_alerts = analyzer.detect_brute_force(ip_attempts, threshold=5)

    print(f"[1] SSH-анализ:")
    print(f"    Уникальных атакующих IP: {len(ip_attempts)}")
    print(f"    Всего попыток входа:     {sum(ip_attempts.values())}")
    print(f"    Брутфорс-атак (>=5):     {len(bf_alerts)}")
    if bf_alerts:
        print("    Заблокированные IP:")
        for ip in sorted(bf_alerts):
            print(f"      - {ip} ({ip_attempts[ip]} попыток)")
    print("-" * 60)

    # --- Шаг 2. Анализ веб-логов (если есть) ---
    web_alerts_count = 0
    if nginx_log_path:
        with open(nginx_log_path, "r", encoding="utf-8", errors="ignore") as f:
            nginx_lines = f.readlines()

        suspicious = []
        for line in nginx_lines:
            if analyzer.detect_suspicious_paths(line):
                web_alerts_count += 1
                parts = line.split('"')
                request = parts[1] if len(parts) > 1 else line.strip()
                ip = line.split()[0]
                suspicious.append((ip, request))

        print(f"[2] Веб-анализ (Nginx):")
        print(f"    Подозрительных запросов: {web_alerts_count}")
        for ip, req in suspicious:
            print(f"      [ALERT] {ip} → {req}")
        print("-" * 60)

    # --- Шаг 3. Оценка уровня риска ---
    risk = analyzer.calculate_risk_score(len(bf_alerts), web_alerts_count)
    print(f"[3] УРОВЕНЬ РИСКА VPS: {risk}")
    print("-" * 60)

    # --- Шаг 4. Контроль целостности файлов ---
    print("[4] Контроль целостности конфигурации:")
    config_path = "vps_secure_config.conf"

    # Создаём эталонный файл для демонстрации
    with open(config_path, "w") as f:
        f.write("PermitRootLogin no\nPasswordAuthentication no\n")

    hash_before = analyzer.get_file_hash(config_path)
    print(f"    Хеш до:    {hash_before}")

    # Имитируем изменение (в реальной задаче можно проверить другой файл)
    with open(config_path, "a") as f:
        f.write("# modified\n")

    hash_after = analyzer.get_file_hash(config_path)
    print(f"    Хеш после: {hash_after}")

    if hash_before != hash_after:
        print("    [!] Целостность нарушена!")
    else:
        print("    [OK] Файл не изменён.")

    os.remove(config_path)
    print("-" * 60)

    # --- Шаг 5. Сканирование портов ---
    print("[5] Сканирование портов на 127.0.0.1:")
    for port in [22, 80, 443, 8080]:
        is_open = analyzer.is_port_open("127.0.0.1", port, timeout=0.5)
        status = "ОТКРЫТ" if is_open else "ЗАКРЫТ"
        print(f"    - Порт {port}: {status}")
    print("-" * 60)

    print("КОНВЕЙЕР ЗАВЕРШИЛ РАБОТУ.")
    print("=" * 60)


if __name__ == "__main__":
    if len(sys.argv) > 1:
        ssh_path = sys.argv[1]
    else:
        ssh_path = "/home/student/logs/auth.log"

    nginx_path = sys.argv[2] if len(sys.argv) > 2 else None

    run_pipeline(ssh_path, nginx_path)