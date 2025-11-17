import subprocess
import re
import platform
from datetime import datetime
import os
import sys
import json
import time

class WiFiSecurityAnalyzer:
    def __init__(self):
        self.vulnerability_db = self.load_vulnerability_database()
        self.scan_results = []
        self.reports_dir = "1"
        
    def load_vulnerability_database(self):
        return {
            "WEP": {
                "risk_level": "КРИТИЧЕСКИЙ",
                "vulnerabilities": [
                    "Слабые векторы инициализации (IV) позволяют восстановить ключ",
                    "Уязвимость к атакам повторного использования IV",
                    "Отсутствие защиты целостности данных",
                    "Недостаточная длина ключа (40/104 бит)",
                    "Статические ключи шифрования"
                ],
                "attack_tools": [
                    {"name": "aircrack-ng", "description": "Комплексный набор для взлома беспроводных сетей", "url": "https://www.aircrack-ng.org/"},
                    {"name": "wifite", "description": "Автоматизированный инструмент для тестирования Wi-Fi", "url": "https://github.com/kimocoder/wifite2"},
                    {"name": "WEPAttack", "description": "Специализированный инструмент для атак на WEP", "url": "https://sourceforge.net/projects/wepattack/"},
                    {"name": "airreplay-ng", "description": "Генерация трафика для ускорения взлома", "url": "https://www.aircrack-ng.org/doku.php?id=airreplay-ng"}
                ],
                "articles": [
                    {"title": "Полный взлом WEP за 5 минут", "url": "https://www.aircrack-ng.org/doku.php?id=breaking_wep", "type": "Практическое руководство"},
                    {"title": "Уязвимости протокола WEP", "url": "https://en.wikipedia.org/wiki/Wired_Equivalent_Privacy#Security_issues", "type": "Теоретическая основа"},
                    {"title": "Практическое руководство по взлому WEP", "url": "https://www.kali.org/tutorials/wep-wireless-penetration-testing/", "type": "Пошаговая инструкция"}
                ],
                "exploitation_time": "1-10 минут",
                "success_rate": "95%",
                "complexity": "Низкая",
                "attack_scenarios": [
                    "ARP request replay атака для генерации IV",
                    "Fragmentation атака для получения PRGA",
                    "Chopchop атака для расшифровки пакетов",
                    "PTW атака для ускорения взлома"
                ]
            },
            "WPA-TKIP": {
                "risk_level": "ВЫСОКИЙ", 
                "vulnerabilities": [
                    "Уязвимость MIC (Message Integrity Check)",
                    "Возможность инъекции пакетов",
                    "Восстановление временного ключа",
                    "Уязвимость к атакам перебора"
                ],
                "attack_tools": [
                    {"name": "tkiptun-ng", "description": "Специализированная атака на TKIP", "url": "https://www.aircrack-ng.org/doku.php?id=tkiptun-ng"},
                    {"name": "aircrack-ng", "description": "Взлом через перебор handshake", "url": "https://www.aircrack-ng.org/"},
                    {"name": "pyrit", "description": "Высокопроизводительный перебор WPA", "url": "https://github.com/JPaulMora/Pyrit"}
                ],
                "articles": [
                    {"title": "Атаки на протокол TKIP", "url": "https://en.wikipedia.org/wiki/Temporal_Key_Integrity_Protocol#Security_issues", "type": "Теоретическая основа"},
                    {"title": "Beck-Tews атака на WPA-TKIP", "url": "https://link.springer.com/chapter/10.1007/978-3-642-04474-8_3", "type": "Академическое исследование"},
                    {"title": "Ohigashi-Morii атака", "url": "https://ieeexplore.ieee.org/document/5207650", "type": "Научная публикация"}
                ],
                "exploitation_time": "10-60 минут",
                "success_rate": "70%",
                "complexity": "Средняя",
                "attack_scenarios": [
                    "Michael countermeasure exploitation",
                    "ARP poisoning через TKIP",
                    "Beck-Tews инъекция пакетов"
                ]
            },
            "WPA2-CCMP": {
                "risk_level": "СРЕДНИЙ",
                "vulnerabilities": [
                    "KRACK (Key Reinstallation Attacks)",
                    "Уязвимости реализации WPS",
                    "Атаки перебора по словарю",
                    "Уязвимость PMKID",
                    "Оффлайн-атаки на handshake"
                ],
                "attack_tools": [
                    {"name": "aircrack-ng", "description": "Основной инструмент для взлома WPA2", "url": "https://www.aircrack-ng.org/"},
                    {"name": "hashcat", "description": "Высокопроизводительный перебор хешей", "url": "https://hashcat.net/hashcat/"},
                    {"name": "reaver", "description": "Атака на WPS", "url": "https://github.com/t6x/reaver-wps-fork-t6x"},
                    {"name": "bully", "description": "Альтернатива reaver для WPS", "url": "https://github.com/aanarchyy/bully"},
                    {"name": "hcxdumptool", "description": "Захват PMKID", "url": "https://github.com/ZerBea/hcxdumptool"}
                ],
                "articles": [
                    {"title": "KRACK атака на WPA2", "url": "https://www.krackattacks.com/", "type": "Официальный сайт уязвимости"},
                    {"title": "Уязвимости WPS", "url": "https://en.wikipedia.org/wiki/Wi-Fi_Protected_Setup#Security_issues", "type": "Обзор уязвимостей"},
                    {"title": "PMKID атаки", "url": "https://hashcat.net/forum/thread-7717.html", "type": "Форум взломщиков"},
                    {"title": "WPA2 Handshake атаки", "url": "https://www.aircrack-ng.org/doku.php?id=simple_wpa_capture", "type": "Практическое руководство"}
                ],
                "exploitation_time": "2-48 часов",
                "success_rate": "40%",
                "complexity": "Высокая",
                "attack_scenarios": [
                    "Deauth атака для захвата handshake",
                    "Pixie Dust атака на WPS",
                    "PMKID оффлайн атака",
                    "Словарная атака на handshake"
                ]
            },
            "WPA3": {
                "risk_level": "НИЗКИЙ",
                "vulnerabilities": [
                    "Dragonblood атаки понижения",
                    "Утечки информации через timing attacks",
                    "Уязвимости реализации SAE",
                    "Атаки на side channels"
                ],
                "attack_tools": [
                    {"name": "dragonblood", "description": "Набор эксплойтов для WPA3", "url": "https://github.com/vanhoefm/dragonblood"},
                    {"name": "wpa3-cracker", "description": "Инструменты для тестирования WPA3", "url": "https://github.com/zerosum0x0/WPA3Cracker"},
                    {"name": "hostapd-wpe", "description": "Тестирование Enterprise сетей", "url": "https://github.com/OpenSecurityResearch/hostapd-wpe"}
                ],
                "articles": [
                    {"title": "Dragonblood уязвимости WPA3", "url": "https://www.wpad.com/dragonblood/", "type": "Официальный сайт исследования"},
                    {"title": "WPA3 Security Analysis", "url": "https://www.wi-fi.org/discover-wi-fi/security", "type": "Официальная документация"},
                    {"title": "SAE протокол уязвимости", "url": "https://papers.mathyvanhoef.com/dragonblood.pdf", "type": "Научная публикация"}
                ],
                "exploitation_time": "Сложно оценить",
                "success_rate": "15%",
                "complexity": "Очень высокая",
                "attack_scenarios": [
                    "Downgrade до WPA2",
                    "Timing-based side channel атаки",
                    "Resource exhaustion атаки"
                ]
            },
            "OPEN": {
                "risk_level": "КРИТИЧЕСКИЙ",
                "vulnerabilities": [
                    "Полный перехват сетевого трафика",
                    "Man-in-the-Middle атаки",
                    "Создание Evil Twin точек доступа",
                    "Перехват сессий и cookies",
                    "Внедрение malware в трафик"
                ],
                "attack_tools": [
                    {"name": "wireshark", "description": "Анализ сетевого трафика", "url": "https://www.wireshark.org/"},
                    {"name": "ettercap", "description": "MITM атаки и анализ сети", "url": "https://www.ettercap-project.org/"},
                    {"name": "airbase-ng", "description": "Создание fake access points", "url": "https://www.aircrack-ng.org/doku.php?id=airbase-ng"},
                    {"name": "sslstrip", "description": "Downgrade HTTPS соединений", "url": "https://moxie.org/software/sslstrip/"},
                    {"name": "driftnet", "description": "Перехват изображений из трафика", "url": "https://github.com/deiv/driftnet"}
                ],
                "articles": [
                    {"title": "Опасности открытых Wi-Fi сетей", "url": "https://www.kaspersky.ru/blog/open-wi-fi/10481/", "type": "Общедоступная статья"},
                    {"title": "Evil Twin атаки", "url": "https://en.wikipedia.org/wiki/Evil_twin_(wireless_networks)", "type": "Энциклопедия"},
                    {"title": "MITM атаки в открытых сетях", "url": "https://www.acunetix.com/blog/articles/man-in-the-middle-attacks/", "type": "Технический блог"}
                ],
                "exploitation_time": "Мгновенно",
                "success_rate": "100%",
                "complexity": "Очень низкая",
                "attack_scenarios": [
                    "Пассивный сниффинг трафика",
                    "Создание rogue access point",
                    "DNS spoofing атаки",
                    "SSL stripping атаки"
                ]
            },
            "WPS_ENABLED": {
                "risk_level": "ВЫСОКИЙ",
                "vulnerabilities": [
                    "Pixie Dust оффлайн атака", 
                    "Brute-force PIN атаки",
                    "Обход WPS lockout",
                    "Уязвимости реализации WPS"
                ],
                "attack_tools": [
                    {"name": "reaver", "description": "Основной инструмент для WPS атак", "url": "https://github.com/t6x/reaver-wps-fork-t6x"},
                    {"name": "bully", "description": "Альтернатива reaver", "url": "https://github.com/aanarchyy/bully"},
                    {"name": "pixiewps", "description": "Оффлайн атака на WPS", "url": "https://github.com/wiire/pixiewps"},
                    {"name": "wpscrack", "description": "Python-based WPS cracker", "url": "https://github.com/0x90/wpsik"}
                ],
                "articles": [
                    {"title": "Взлом через WPS", "url": "https://en.wikipedia.org/wiki/Wi-Fi_Protected_Setup#Security_issues", "type": "Обзор уязвимостей"},
                    {"title": "Pixie Dust атака", "url": "https://github.com/wiire/pixiewps", "type": "GitHub репозиторий"},
                    {"title": "WPS Brute-force", "url": "https://tools.kali.org/wireless-attacks/reaver", "type": "Kali документация"}
                ],
                "exploitation_time": "2-10 часов",
                "success_rate": "85%",
                "complexity": "Низкая",
                "attack_scenarios": [
                    "Pixie Dust оффлайн взлом",
                    "Brute-force PIN перебор",
                    "WPS lockout обход"
                ]
            }
        }
    
    def run_command(self, cmd):
        try:
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, encoding='cp866', errors='ignore')
            return result.stdout
        except Exception as e:
            print(f"Ошибка выполнения команды: {e}")
            return ""
    
    def ensure_reports_dir(self):
        if not os.path.exists(self.reports_dir):
            os.makedirs(self.reports_dir)
    
    def deep_scan_networks(self):
        print("Глубокое сканирование всех сетей...")
        
        networks_output = self.run_command("netsh wlan show networks mode=bssid")
        
        if not networks_output:
            return []
            
        networks = []
        current_ssid = None
        current_auth = "Неизвестно"
        current_encryption = "Неизвестно"
        max_signal = 0
        bssid_count = 0
        channel_info = "Неизвестно"
        radio_type = "Неизвестно"
        
        for line in networks_output.split('\n'):
            line = line.strip()
            
            if not line:
                continue
            
            if line.startswith('SSID '):
                if current_ssid and current_ssid.strip():
                    networks.append({
                        'SSID': current_ssid,
                        'Authentication': current_auth,
                        'Encryption': current_encryption,
                        'Signal': max_signal,
                        'BSSID_Count': bssid_count,
                        'Channel': channel_info,
                        'Radio_Type': radio_type
                    })
                
                ssid_match = re.match(r'SSID\s+\d+\s*:\s*(.+)', line)
                if ssid_match:
                    current_ssid = ssid_match.group(1)
                    current_auth = "Неизвестно"
                    current_encryption = "Неизвестно"
                    max_signal = 0
                    bssid_count = 0
                    channel_info = "Неизвестно"
                    radio_type = "Неизвестно"
            
            elif 'BSSID' in line:
                bssid_count += 1
            
            elif 'Authentication' in line or 'Аутентификация' in line:
                auth_match = re.search(r':\s*(.+)', line)
                if auth_match and current_ssid:
                    current_auth = auth_match.group(1).strip()
            
            elif 'Encryption' in line or 'Шифрование' in line:
                enc_match = re.search(r':\s*(.+)', line)
                if enc_match and current_ssid:
                    current_encryption = enc_match.group(1).strip()
            
            elif 'Signal' in line or 'Сигнал' in line:
                signal_match = re.search(r'(\d+)%', line)
                if signal_match and current_ssid:
                    signal = int(signal_match.group(1))
                    if signal > max_signal:
                        max_signal = signal
            
            elif 'Channel' in line or 'Канал' in line:
                channel_match = re.search(r':\s*(.+)', line)
                if channel_match and current_ssid:
                    channel_info = channel_match.group(1).strip()
            
            elif 'Radio type' in line or 'Тип радио' in line:
                radio_match = re.search(r':\s*(.+)', line)
                if radio_match and current_ssid:
                    radio_type = radio_match.group(1).strip()
        
        if current_ssid and current_ssid.strip():
            networks.append({
                'SSID': current_ssid,
                'Authentication': current_auth,
                'Encryption': current_encryption,
                'Signal': max_signal,
                'BSSID_Count': bssid_count,
                'Channel': channel_info,
                'Radio_Type': radio_type
            })
        
        unique_networks = []
        seen_ssids = set()
        
        for network in networks:
            if network['SSID'] and network['SSID'] not in seen_ssids:
                unique_networks.append(network)
                seen_ssids.add(network['SSID'])
        
        return unique_networks
    
    def get_network_details(self, ssid):
        if not ssid:
            return "Неизвестно", "Неизвестно", "Неизвестно"
        
        profile_output = self.run_command(f'netsh wlan show profile name="{ssid}"')
        
        auth = "Неизвестно"
        encryption = "Неизвестно"
        connection_mode = "Неизвестно"
        
        if profile_output:
            for line in profile_output.split('\n'):
                line = line.strip()
                if 'Authentication' in line or 'Аутентификация' in line:
                    auth_match = re.search(r':\s*(.+)', line)
                    if auth_match:
                        auth = auth_match.group(1).strip()
                elif 'Encryption' in line or 'Шифрование' in line:
                    enc_match = re.search(r':\s*(.+)', line)
                    if enc_match:
                        encryption = enc_match.group(1).strip()
                elif 'Connection mode' in line or 'Режим подключения' in line:
                    mode_match = re.search(r':\s*(.+)', line)
                    if mode_match:
                        connection_mode = mode_match.group(1).strip()
        
        return auth, encryption, connection_mode
    
    def analyze_security(self, network):
        ssid = network.get('SSID', 'Неизвестно')
        auth = network.get('Authentication', 'Неизвестно')
        encryption = network.get('Encryption', 'Неизвестно')
        
        if auth == "Неизвестно" or encryption == "Неизвестно":
            detailed_auth, detailed_encryption, connection_mode = self.get_network_details(ssid)
            if detailed_auth != "Неизвестно":
                auth = detailed_auth
            if detailed_encryption != "Неизвестно":
                encryption = detailed_encryption
        
        vulnerabilities = []
        risk_level = "НЕИЗВЕСТНО"
        attack_vectors = []
        security_score = 100
        articles = []
        exploitation_info = {}
        security_recommendations = []
        attack_scenarios = []
        
        auth_upper = auth.upper()
        enc_upper = encryption.upper()
        
        if 'WEP' in auth_upper or 'WEP' in enc_upper:
            vuln_info = self.vulnerability_db["WEP"]
            vulnerabilities.extend(vuln_info["vulnerabilities"])
            attack_vectors.extend(vuln_info["attack_tools"])
            articles.extend(vuln_info["articles"])
            risk_level = vuln_info["risk_level"]
            security_score = 10
            exploitation_info = {
                "time": vuln_info["exploitation_time"],
                "success_rate": vuln_info["success_rate"],
                "complexity": vuln_info["complexity"]
            }
            security_recommendations = [
                "Перейти на WPA2 или WPA3",
                "Заменить оборудование, если не поддерживает современные протоколы",
                "Использовать дополнительное шифрование на уровне приложений",
                "Регулярно мониторить сеть на неавторизованные подключения"
            ]
            attack_scenarios = vuln_info["attack_scenarios"]
            
        elif 'WPA2' in auth_upper and 'TKIP' in enc_upper:
            vuln_info = self.vulnerability_db["WPA-TKIP"] 
            vulnerabilities.extend(vuln_info["vulnerabilities"])
            attack_vectors.extend(vuln_info["attack_tools"])
            articles.extend(vuln_info["articles"])
            risk_level = vuln_info["risk_level"]
            security_score = 30
            exploitation_info = {
                "time": vuln_info["exploitation_time"],
                "success_rate": vuln_info["success_rate"],
                "complexity": vuln_info["complexity"]
            }
            security_recommendations = [
                "Перейти на шифрование AES",
                "Отключить поддержку TKIP в настройках роутера",
                "Обновить прошивку роутера",
                "Использовать сложные пароли длиной 15+ символов"
            ]
            attack_scenarios = vuln_info["attack_scenarios"]
            
        elif 'WPA2' in auth_upper:
            vuln_info = self.vulnerability_db["WPA2-CCMP"]
            vulnerabilities.extend(vuln_info["vulnerabilities"])
            attack_vectors.extend(vuln_info["attack_tools"])
            articles.extend(vuln_info["articles"])
            risk_level = vuln_info["risk_level"]
            security_score = 70
            exploitation_info = {
                "time": vuln_info["exploitation_time"],
                "success_rate": vuln_info["success_rate"],
                "complexity": vuln_info["complexity"]
            }
            security_recommendations = [
                "Отключить WPS в настройках роутера",
                "Обновить прошивку для защиты от KRACK атак",
                "Использовать WPA2-Enterprise при возможности",
                "Регулярно менять пароль"
            ]
            attack_scenarios = vuln_info["attack_scenarios"]
            
            if self.check_wps_status(ssid):
                wps_vuln = self.vulnerability_db["WPS_ENABLED"]
                vulnerabilities.extend(wps_vuln["vulnerabilities"])
                attack_vectors.extend(wps_vuln["attack_tools"])
                articles.extend(wps_vuln["articles"])
                risk_level = "ВЫСОКИЙ"
                security_score = 40
                security_recommendations.append("Немедленно отключить WPS в настройках роутера")
                attack_scenarios.extend(wps_vuln["attack_scenarios"])
            
        elif 'WPA3' in auth_upper:
            vuln_info = self.vulnerability_db["WPA3"]
            vulnerabilities.extend(vuln_info["vulnerabilities"])
            attack_vectors.extend(vuln_info["attack_tools"])
            articles.extend(vuln_info["articles"])
            risk_level = vuln_info["risk_level"]
            security_score = 90
            exploitation_info = {
                "time": vuln_info["exploitation_time"],
                "success_rate": vuln_info["success_rate"],
                "complexity": vuln_info["complexity"]
            }
            security_recommendations = [
                "Обновлять прошивку для защиты от Dragonblood атак",
                "Использовать сложные уникальные пароли",
                "Отключить поддержку переходных режимов"
            ]
            attack_scenarios = vuln_info["attack_scenarios"]
            
        elif 'OPEN' in auth_upper or 'OPEN' in enc_upper or encryption == 'None':
            vuln_info = self.vulnerability_db["OPEN"]
            vulnerabilities.extend(vuln_info["vulnerabilities"])
            attack_vectors.extend(vuln_info["attack_tools"])
            articles.extend(vuln_info["articles"])
            risk_level = vuln_info["risk_level"]
            security_score = 0
            exploitation_info = {
                "time": vuln_info["exploitation_time"],
                "success_rate": vuln_info["success_rate"],
                "complexity": vuln_info["complexity"]
            }
            security_recommendations = [
                "Немедленно включить шифрование WPA2/WPA3",
                "Настроить гостевую сеть с изоляцией клиентов",
                "Использовать VPN для всего трафика",
                "Включить фильтрацию по MAC-адресам"
            ]
            attack_scenarios = vuln_info["attack_scenarios"]
        
        signal_strength = network.get('Signal', 0)
        signal_info = []
        
        if signal_strength > 80:
            signal_info.append("Очень сильный сигнал: зона действия распространяется далеко за пределы помещения")
            signal_info.append("Высокая вероятность обнаружения и атаки с большого расстояния")
            security_score -= 10
        elif signal_strength > 60:
            signal_info.append("Сильный сигнал: хорошее покрытие для атакующего")
            security_score -= 5
        elif signal_strength < 20:
            signal_info.append("Слабый сигнал: ограниченная зона для атак")
            security_score += 5
        else:
            signal_info.append("Средний уровень сигнала: стандартная зона покрытия")
    
        vulnerabilities.extend(signal_info)
        
        bssid_count = network.get('BSSID_Count', 1)
        if bssid_count > 1:
            vulnerabilities.append(f"Обнаружено {bssid_count} точек доступа: увеличенная поверхность атаки")
        
        channel = network.get('Channel', 'Неизвестно')
        if channel != 'Неизвестно':
            vulnerabilities.append(f"Работа на канале {channel}: возможны помехи и целевые атаки")
        
        if not security_recommendations:
            security_recommendations = [
                "Использовать сложные пароли длиной не менее 12 символов",
                "Регулярно обновлять прошивку роутера",
                "Отключить WPS если он не используется",
                "Включить фильтрацию по MAC-адресам",
                "Использовать скрытие SSID если возможно"
            ]
        
        if not attack_scenarios:
            attack_scenarios = [
                "Пассивный мониторинг сетевого трафика",
                "Активное сканирование на уязвимости",
                "Тестирование на слабые пароли"
            ]
        
        if not attack_vectors:
            attack_vectors = [
                {"name": "nmap", "description": "Сканер сетевой безопасности", "url": "https://nmap.org/"},
                {"name": "wireshark", "description": "Анализатор сетевого трафика", "url": "https://www.wireshark.org/"}
            ]
        
        if not articles:
            articles = [
                {"title": "Основы безопасности Wi-Fi сетей", "url": "https://www.kaspersky.ru/blog/wi-fi-security/10489/", "type": "Общедоступная статья"},
                {"title": "Руководство по настройке безопасного Wi-Fi", "url": "https://www.wi-fi.org/security", "type": "Официальная документация"}
            ]
        
        if not vulnerabilities:
            vulnerabilities = [
                "Неизвестный тип безопасности - требуется дополнительный анализ",
                "Рекомендуется провести детальное тестирование безопасности"
            ]
        
        security_score = max(0, min(100, security_score))
            
        return {
            'ssid': ssid,
            'authentication': auth,
            'encryption': encryption, 
            'signal_strength': signal_strength,
            'risk_level': risk_level,
            'vulnerabilities': vulnerabilities,
            'attack_vectors': attack_vectors,
            'security_score': security_score,
            'articles': articles,
            'bssid_count': bssid_count,
            'channel': channel,
            'radio_type': network.get('Radio_Type', 'Неизвестно'),
            'exploitation_info': exploitation_info,
            'security_recommendations': security_recommendations,
            'attack_scenarios': attack_scenarios,
            'scan_time': datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }
    
    def check_wps_status(self, ssid):
        wps_common_ssids = ['TP-LINK', 'D-Link', 'ASUS', 'NETGEAR', 'Zyxel', 'Tenda', 'Mercusys', 'RT-']
        return any(wps_ssid in ssid.upper() for wps_ssid in wps_common_ssids)
    
    def generate_security_report(self):
        networks = self.deep_scan_networks()
        analysis_results = []
        
        for network in networks:
            if network['SSID'] and network['SSID'].strip():
                analysis = self.analyze_security(network)
                analysis_results.append(analysis)
        
        if not analysis_results:
            return None
        
        risk_order = {'КРИТИЧЕСКИЙ': 0, 'ВЫСОКИЙ': 1, 'СРЕДНИЙ': 2, 'НИЗКИЙ': 3, 'НЕИЗВЕСТНО': 4}
        analysis_results.sort(key=lambda x: (risk_order.get(x['risk_level'], 999), -x['signal_strength']))
        
        return analysis_results
    
    def generate_html_report(self, analysis_results):
        self.ensure_reports_dir()
        
        total_networks = len(analysis_results)
        critical_count = len([r for r in analysis_results if r['risk_level'] == 'КРИТИЧЕСКИЙ'])
        high_count = len([r for r in analysis_results if r['risk_level'] == 'ВЫСОКИЙ'])
        medium_count = len([r for r in analysis_results if r['risk_level'] == 'СРЕДНИЙ'])
        low_count = len([r for r in analysis_results if r['risk_level'] == 'НИЗКИЙ'])
        
        networks_js = json.dumps(analysis_results, ensure_ascii=False, indent=2)
        
        html_template = f"""
<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <title>Анализ безопасности Wi-Fi сетей</title>
    <style>
        @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@300;400;500;600&display=swap');
        
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        
        body {{
            font-family: 'JetBrains Mono', monospace;
            background: #000000;
            color: #ffffff;
            min-height: 100vh;
            line-height: 1.6;
        }}
        
        .container {{
            max-width: 1400px;
            margin: 0 auto;
            padding: 20px;
        }}
        
        .header {{
            text-align: center;
            padding: 30px 0;
            border-bottom: 1px solid #333;
            margin-bottom: 30px;
        }}
        
        .header h1 {{
            font-size: 2.2em;
            font-weight: 300;
            color: #00ff88;
            margin-bottom: 10px;
            letter-spacing: 1px;
        }}
        
        .developer-link {{
            color: #00ff88;
            text-decoration: none;
            font-size: 0.9em;
            transition: opacity 0.3s;
        }}
        
        .developer-link:hover {{
            opacity: 0.8;
        }}
        
        .networks-container {{
            display: grid;
            grid-template-columns: 1fr;
            gap: 25px;
        }}
        
        .controls {{
            display: flex;
            gap: 15px;
            margin-bottom: 25px;
            flex-wrap: wrap;
            background: #111;
            padding: 20px;
            border-radius: 6px;
            border: 1px solid #222;
        }}
        
        .filter-btn {{
            background: #111;
            border: 1px solid #333;
            color: #fff;
            padding: 8px 16px;
            border-radius: 4px;
            cursor: pointer;
            transition: all 0.3s;
            font-family: inherit;
            font-size: 0.9em;
        }}
        
        .filter-btn:hover {{
            border-color: #00ff88;
        }}
        
        .filter-btn.active {{
            background: #00ff88;
            color: #000;
            border-color: #00ff88;
        }}
        
        .search-box {{
            background: #111;
            border: 1px solid #333;
            color: #fff;
            padding: 8px 12px;
            border-radius: 4px;
            flex-grow: 1;
            min-width: 200px;
            font-family: inherit;
        }}
        
        .stats {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 15px;
            margin-bottom: 30px;
        }}
        
        .stat-card {{
            background: #111;
            padding: 20px;
            border-radius: 6px;
            text-align: center;
            border: 1px solid #222;
            transition: transform 0.3s;
        }}
        
        .stat-card:hover {{
            transform: translateY(-2px);
        }}
        
        .stat-number {{
            font-size: 2em;
            font-weight: 600;
            color: #00ff88;
            margin-bottom: 5px;
        }}
        
        .stat-label {{
            color: #888;
            font-size: 0.8em;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }}
        
        .networks-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(350px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }}
        
        .network-card {{
            background: #111;
            border: 1px solid #222;
            border-radius: 8px;
            padding: 20px;
            cursor: pointer;
            transition: all 0.3s;
            position: relative;
        }}
        
        .network-card:hover {{
            border-color: #00ff88;
            transform: translateY(-2px);
        }}
        
        .network-card.active {{
            border-color: #00ff88;
            background: #1a3a2a;
        }}
        
        .network-header {{
            display: flex;
            justify-content: between;
            align-items: flex-start;
            margin-bottom: 15px;
        }}
        
        .network-ssid {{
            font-weight: 600;
            font-size: 1.1em;
            color: #fff;
            flex-grow: 1;
        }}
        
        .network-risk {{
            font-size: 0.8em;
            padding: 4px 10px;
            border-radius: 12px;
            font-weight: 600;
        }}
        
        .risk-critical {{ background: #ff4444; color: #fff; }}
        .risk-high {{ background: #ff6b35; color: #fff; }}
        .risk-medium {{ background: #ffa726; color: #000; }}
        .risk-low {{ background: #00c853; color: #000; }}
        .risk-unknown {{ background: #757575; color: #fff; }}
        
        .network-details {{
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 10px;
            font-size: 0.85em;
        }}
        
        .detail-item {{
            display: flex;
            justify-content: space-between;
            padding: 5px 0;
            border-bottom: 1px solid #222;
        }}
        
        .detail-label {{
            color: #888;
        }}
        
        .detail-value {{
            color: #fff;
            font-weight: 500;
        }}
        
        .signal-bar {{
            height: 6px;
            background: #333;
            border-radius: 3px;
            margin-top: 5px;
            overflow: hidden;
        }}
        
        .signal-level {{
            height: 100%;
            background: #00ff88;
            border-radius: 3px;
        }}
        
        .network-details-panel {{
            background: #111;
            border: 1px solid #222;
            border-radius: 8px;
            padding: 25px;
            margin-top: 20px;
        }}
        
        .detail-section {{
            margin-bottom: 25px;
        }}
        
        .section-title {{
            color: #00ff88;
            font-size: 1.1em;
            margin-bottom: 15px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            border-left: 3px solid #00ff88;
            padding-left: 10px;
        }}
        
        .security-score {{
            text-align: center;
            padding: 20px;
            background: linear-gradient(135deg, #1a1a1a, #2a2a2a);
            border-radius: 6px;
            border: 1px solid #333;
            margin-bottom: 20px;
        }}
        
        .score-value {{
            font-size: 3em;
            font-weight: 600;
            margin-bottom: 10px;
        }}
        
        .score-excellent {{ color: #00ff88; }}
        .score-good {{ color: #4caf50; }}
        .score-medium {{ color: #ffa726; }}
        .score-poor {{ color: #ff6b35; }}
        .score-critical {{ color: #ff4444; }}
        
        .vuln-list {{
            list-style: none;
        }}
        
        .vuln-item {{
            padding: 12px 15px;
            margin-bottom: 8px;
            background: #2a1a1a;
            border-left: 3px solid #ff4444;
            border-radius: 0 4px 4px 0;
            font-size: 0.9em;
            color: #ccc;
        }}
        
        .exploitation-info {{
            background: #1a1a2a;
            padding: 20px;
            border-radius: 6px;
            margin: 20px 0;
            border-left: 3px solid #ff6b35;
        }}
        
        .info-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin-top: 15px;
        }}
        
        .info-item {{
            background: #2a2a3a;
            padding: 12px;
            border-radius: 4px;
            text-align: center;
        }}
        
        .info-value {{
            font-size: 1.2em;
            font-weight: 600;
            color: #ff6b35;
            margin-bottom: 5px;
        }}
        
        .info-label {{
            color: #aaa;
            font-size: 0.8em;
        }}
        
        .attack-scenarios {{
            background: #2a1a2a;
            padding: 20px;
            border-radius: 6px;
            margin: 20px 0;
            border-left: 3px solid #ff55ff;
        }}
        
        .scenario-list {{
            list-style: none;
        }}
        
        .scenario-item {{
            padding: 10px 15px;
            margin-bottom: 8px;
            background: #3a2a3a;
            border-radius: 4px;
            font-size: 0.9em;
            color: #ddd;
        }}
        
        .tools-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 12px;
            margin-top: 15px;
        }}
        
        .tool-card {{
            background: #1a2a3a;
            padding: 15px;
            border-radius: 6px;
            border: 1px solid #334;
            transition: all 0.3s;
        }}
        
        .tool-card:hover {{
            border-color: #00ff88;
            background: #223a4a;
        }}
        
        .tool-name {{
            color: #00ff88;
            font-weight: 600;
            margin-bottom: 8px;
            font-size: 1em;
        }}
        
        .tool-description {{
            color: #ccc;
            font-size: 0.85em;
            margin-bottom: 10px;
            line-height: 1.4;
        }}
        
        .tool-link {{
            color: #ff6b35;
            text-decoration: none;
            font-size: 0.8em;
            display: inline-block;
            padding: 4px 8px;
            background: #2a2a2a;
            border-radius: 3px;
        }}
        
        .tool-link:hover {{
            text-decoration: underline;
        }}
        
        .articles-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 15px;
            margin-top: 15px;
        }}
        
        .article-card {{
            background: #1a2a2a;
            padding: 18px;
            border-radius: 6px;
            border: 1px solid #334;
            transition: all 0.3s;
        }}
        
        .article-card:hover {{
            border-color: #00ff88;
            background: #223a3a;
        }}
        
        .article-title {{
            color: #00ff88;
            font-weight: 500;
            margin-bottom: 8px;
            font-size: 0.95em;
            line-height: 1.3;
        }}
        
        .article-type {{
            display: inline-block;
            background: #334;
            color: #aaa;
            padding: 2px 8px;
            border-radius: 10px;
            font-size: 0.75em;
            margin-bottom: 10px;
        }}
        
        .article-link {{
            color: #ff6b35;
            text-decoration: none;
            font-size: 0.85em;
            display: inline-block;
            padding: 4px 8px;
            background: #2a2a2a;
            border-radius: 3px;
        }}
        
        .article-link:hover {{
            text-decoration: underline;
        }}
        
        .recommendations {{
            background: #1a2a1a;
            padding: 20px;
            border-radius: 6px;
            margin-top: 20px;
            border-left: 3px solid #00b8d4;
        }}
        
        .recommendation-item {{
            margin-bottom: 10px;
            color: #ccc;
            font-size: 0.9em;
            padding-left: 15px;
            position: relative;
        }}
        
        .recommendation-item:before {{
            content: "→";
            position: absolute;
            left: 0;
            color: #00b8d4;
        }}
        
        .footer {{
            text-align: center;
            margin-top: 40px;
            padding: 25px 0;
            border-top: 1px solid #333;
            color: #666;
            font-size: 0.8em;
        }}
        
        .no-networks {{
            text-align: center;
            padding: 40px;
            color: #666;
            font-size: 1.1em;
        }}
        
        @media (max-width: 768px) {{
            .networks-grid {{
                grid-template-columns: 1fr;
            }}
            
            .tools-grid {{
                grid-template-columns: 1fr;
            }}
            
            .articles-grid {{
                grid-template-columns: 1fr;
            }}
            
            .controls {{
                flex-direction: column;
            }}
            
            .search-box {{
                min-width: auto;
            }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>АНАЛИЗ БЕЗОПАСНОСТИ WI-FI СЕТЕЙ</h1>
            <div>
                <a href="https://t.me/yoxiko" class="developer-link" target="_blank">Разработчик: yoxiko</a>
            </div>
        </div>
        
        <div class="stats">
            <div class="stat-card">
                <div class="stat-number">{total_networks}</div>
                <div class="stat-label">Всего сетей</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">{critical_count}</div>
                <div class="stat-label">Критический риск</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">{high_count}</div>
                <div class="stat-label">Высокий риск</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">{medium_count + low_count}</div>
                <div class="stat-label">Средний/Низкий</div>
            </div>
        </div>
        
        <div class="networks-container">
            <div class="controls">
                <button class="filter-btn active" data-filter="all">Все сети</button>
                <button class="filter-btn" data-filter="critical">Критический</button>
                <button class="filter-btn" data-filter="high">Высокий</button>
                <button class="filter-btn" data-filter="medium">Средний</button>
                <button class="filter-btn" data-filter="low">Низкий</button>
                <input type="text" class="search-box" placeholder="Поиск по имени сети..." id="searchInput">
            </div>
            
            <div class="networks-grid" id="networksGrid">
                <!-- Карточки сетей будут здесь -->
            </div>
            
            <div class="network-details-panel" id="networkDetails">
                <div class="security-score">
                    <div class="section-title">Общая безопасность</div>
                    <div class="score-value score-excellent" id="overallScore">-</div>
                    <div>Выберите сеть для детального анализа</div>
                </div>
            </div>
        </div>
        
        <div class="footer">
            <div>Отчет сгенерирован автоматически</div>
            <div>Используйте только в образовательных целях</div>
        </div>
    </div>

    <script>
        const networksData = {networks_js};
        
        const networksGrid = document.getElementById('networksGrid');
        const networkDetails = document.getElementById('networkDetails');
        const filterButtons = document.querySelectorAll('.filter-btn');
        const searchInput = document.getElementById('searchInput');
        const overallScore = document.getElementById('overallScore');
        
        let currentFilter = 'all';
        let currentSearch = '';
        let selectedNetwork = null;
        
        function getScoreClass(score) {{
            if (score >= 80) return 'score-excellent';
            if (score >= 60) return 'score-good';
            if (score >= 40) return 'score-medium';
            if (score >= 20) return 'score-poor';
            return 'score-critical';
        }}
        
        function getRiskText(risk) {{
            const riskMap = {{
                'КРИТИЧЕСКИЙ': 'critical',
                'ВЫСОКИЙ': 'high', 
                'СРЕДНИЙ': 'medium',
                'НИЗКИЙ': 'low',
                'НЕИЗВЕСТНО': 'unknown'
            }};
            return riskMap[risk] || 'unknown';
        }}
        
        function renderNetworksGrid() {{
            networksGrid.innerHTML = '';
            
            const filteredNetworks = networksData.filter(network => {{
                const matchesFilter = currentFilter === 'all' || 
                                   getRiskText(network.risk_level) === currentFilter;
                const matchesSearch = network.ssid.toLowerCase().includes(currentSearch.toLowerCase());
                return matchesFilter && matchesSearch;
            }});
            
            if (filteredNetworks.length === 0) {{
                networksGrid.innerHTML = '<div class="no-networks">Сети не найдены</div>';
                return;
            }}
            
            filteredNetworks.forEach((network, index) => {{
                const card = document.createElement('div');
                card.className = `network-card ${{selectedNetwork === index ? 'active' : ''}}`;
                card.onclick = () => selectNetwork(index);
                
                const signalWidth = Math.max(10, network.signal_strength); // Минимум 10% для видимости
                
                card.innerHTML = `
                    <div class="network-header">
                        <div class="network-ssid">${{network.ssid}}</div>
                        <div class="network-risk risk-${{getRiskText(network.risk_level)}}">
                            ${{network.risk_level}}
                        </div>
                    </div>
                    
                    <div class="network-details">
                        <div class="detail-item">
                            <span class="detail-label">Сигнал:</span>
                            <span class="detail-value">${{network.signal_strength}}%</span>
                        </div>
                        <div class="detail-item">
                            <span class="detail-label">Безопасность:</span>
                            <span class="detail-value">${{network.security_score}}/100</span>
                        </div>
                        <div class="detail-item">
                            <span class="detail-label">Аутентификация:</span>
                            <span class="detail-value">${{network.authentication}}</span>
                        </div>
                        <div class="detail-item">
                            <span class="detail-label">Шифрование:</span>
                            <span class="detail-value">${{network.encryption}}</span>
                        </div>
                        <div class="detail-item">
                            <span class="detail-label">Канал:</span>
                            <span class="detail-value">${{network.channel}}</span>
                        </div>
                        <div class="detail-item">
                            <span class="detail-label">Точек доступа:</span>
                            <span class="detail-value">${{network.bssid_count}}</span>
                        </div>
                    </div>
                    
                    <div class="signal-bar">
                        <div class="signal-level" style="width: ${{signalWidth}}%"></div>
                    </div>
                `;
                
                networksGrid.appendChild(card);
            }});
        }}
        
        function selectNetwork(index) {{
            selectedNetwork = index;
            const network = networksData[index];
            
            overallScore.textContent = network.security_score;
            overallScore.className = `score-value ${{getScoreClass(network.security_score)}}`;
            
            networkDetails.innerHTML = `
                <div class="detail-section">
                    <div class="section-title">Основная информация</div>
                    <div class="security-score">
                        <div class="score-value ${{getScoreClass(network.security_score)}}">${{network.security_score}}</div>
                        <div>Общий счет безопасности</div>
                    </div>
                    <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin-top: 20px;">
                        <div style="background: #1a1a1a; padding: 15px; border-radius: 4px; border: 1px solid #333;">
                            <div style="color: #888; font-size: 0.8em; margin-bottom: 5px;">Имя сети</div>
                            <div style="color: #fff; font-weight: 500;">${{network.ssid}}</div>
                        </div>
                        <div style="background: #1a1a1a; padding: 15px; border-radius: 4px; border: 1px solid #333;">
                            <div style="color: #888; font-size: 0.8em; margin-bottom: 5px;">Уровень риска</div>
                            <div><span class="network-risk risk-${{getRiskText(network.risk_level)}}">${{network.risk_level}}</span></div>
                        </div>
                        <div style="background: #1a1a1a; padding: 15px; border-radius: 4px; border: 1px solid #333;">
                            <div style="color: #888; font-size: 0.8em; margin-bottom: 5px;">Сигнал</div>
                            <div style="color: #fff; font-weight: 500;">${{network.signal_strength}}%</div>
                        </div>
                        <div style="background: #1a1a1a; padding: 15px; border-radius: 4px; border: 1px solid #333;">
                            <div style="color: #888; font-size: 0.8em; margin-bottom: 5px;">Точек доступа</div>
                            <div style="color: #fff; font-weight: 500;">${{network.bssid_count}}</div>
                        </div>
                    </div>
                </div>
                
                <div class="detail-section">
                    <div class="section-title">Технические детали</div>
                    <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px;">
                        <div style="background: #1a1a1a; padding: 15px; border-radius: 4px; border: 1px solid #333;">
                            <div style="color: #888; font-size: 0.8em; margin-bottom: 5px;">Аутентификация</div>
                            <div style="color: #fff; font-weight: 500;">${{network.authentication}}</div>
                        </div>
                        <div style="background: #1a1a1a; padding: 15px; border-radius: 4px; border: 1px solid #333;">
                            <div style="color: #888; font-size: 0.8em; margin-bottom: 5px;">Шифрование</div>
                            <div style="color: #fff; font-weight: 500;">${{network.encryption}}</div>
                        </div>
                        <div style="background: #1a1a1a; padding: 15px; border-radius: 4px; border: 1px solid #333;">
                            <div style="color: #888; font-size: 0.8em; margin-bottom: 5px;">Канал</div>
                            <div style="color: #fff; font-weight: 500;">${{network.channel}}</div>
                        </div>
                        <div style="background: #1a1a1a; padding: 15px; border-radius: 4px; border: 1px solid #333;">
                            <div style="color: #888; font-size: 0.8em; margin-bottom: 5px;">Тип радио</div>
                            <div style="color: #fff; font-weight: 500;">${{network.radio_type}}</div>
                        </div>
                        <div style="background: #1a1a1a; padding: 15px; border-radius: 4px; border: 1px solid #333;">
                            <div style="color: #888; font-size: 0.8em; margin-bottom: 5px;">Время сканирования</div>
                            <div style="color: #fff; font-weight: 500;">${{network.scan_time}}</div>
                        </div>
                    </div>
                </div>
                
                <div class="detail-section">
                    <div class="section-title">Информация об эксплуатации</div>
                    <div class="exploitation-info">
                        <div class="info-grid">
                            <div class="info-item">
                                <div class="info-value">${{network.exploitation_info.time}}</div>
                                <div class="info-label">Время взлома</div>
                            </div>
                            <div class="info-item">
                                <div class="info-value">${{network.exploitation_info.success_rate}}</div>
                                <div class="info-label">Успешность</div>
                            </div>
                            <div class="info-item">
                                <div class="info-value">${{network.exploitation_info.complexity}}</div>
                                <div class="info-label">Сложность</div>
                            </div>
                        </div>
                    </div>
                </div>
                
                <div class="detail-section">
                    <div class="section-title">Сценарии атак</div>
                    <div class="attack-scenarios">
                        <ul class="scenario-list">
                            ${{network.attack_scenarios.map(scenario => `<li class="scenario-item">${{scenario}}</li>`).join('')}}
                        </ul>
                    </div>
                </div>
                
                <div class="detail-section">
                    <div class="section-title">Выявленные уязвимости</div>
                    <ul class="vuln-list">
                        ${{network.vulnerabilities.map(vuln => `<li class="vuln-item">${{vuln}}</li>`).join('')}}
                    </ul>
                </div>
                
                <div class="detail-section">
                    <div class="section-title">Инструменты для атак</div>
                    <div class="tools-grid">
                        ${{network.attack_vectors.map(tool => `
                            <div class="tool-card">
                                <div class="tool-name">${{tool.name}}</div>
                                <div class="tool-description">${{tool.description}}</div>
                                <a href="${{tool.url}}" class="tool-link" target="_blank">Скачать/Документация</a>
                            </div>
                        `).join('')}}
                    </div>
                </div>
                
                <div class="detail-section">
                    <div class="section-title">Статьи и материалы</div>
                    <div class="articles-grid">
                        ${{network.articles.map(article => `
                            <div class="article-card">
                                <div class="article-title">${{article.title}}</div>
                                <div class="article-type">${{article.type}}</div>
                                <a href="${{article.url}}" class="article-link" target="_blank">Читать статью</a>
                            </div>
                        `).join('')}}
                    </div>
                </div>
                
                <div class="detail-section">
                    <div class="section-title">Рекомендации по защите</div>
                    <div class="recommendations">
                        ${{network.security_recommendations.map(rec => `<div class="recommendation-item">${{rec}}</div>`).join('')}}
                    </div>
                </div>
            `;
            
            renderNetworksGrid();
        }}
        
        filterButtons.forEach(button => {{
            button.addEventListener('click', () => {{
                filterButtons.forEach(btn => btn.classList.remove('active'));
                button.classList.add('active');
                currentFilter = button.dataset.filter;
                renderNetworksGrid();
            }});
        }});
        
        searchInput.addEventListener('input', (e) => {{
            currentSearch = e.target.value;
            renderNetworksGrid();
        }});
        
        // Инициализация
        renderNetworksGrid();
        
        if (networksData.length > 0) {{
            selectNetwork(0);
        }}
    </script>
</body>
</html>
"""
        
        filename = f"wifi_analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
        filepath = os.path.join(self.reports_dir, filename)
        
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(html_template)
        
        return filepath
    
    def generate_additional_files(self, analysis_results):
        """Генерация дополнительных файлов"""
        self.ensure_reports_dir()
        
        json_data = {
            "scan_info": {
                "timestamp": datetime.now().isoformat(),
                "total_networks": len(analysis_results),
                "scanner_version": "2.0",
                "developer": "yoxiko"
            },
            "networks": analysis_results
        }
        
        json_filename = f"wifi_raw_data_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        json_filepath = os.path.join(self.reports_dir, json_filename)
        
        with open(json_filepath, 'w', encoding='utf-8') as f:
            json.dump(json_data, f, ensure_ascii=False, indent=2)
        
        csv_filename = f"wifi_summary_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        csv_filepath = os.path.join(self.reports_dir, csv_filename)
        
        with open(csv_filepath, 'w', encoding='utf-8') as f:
            f.write("SSID,Authentication,Encryption,Signal,Risk_Level,Security_Score,BSSID_Count,Channel\n")
            for network in analysis_results:
                f.write(f'"{network["ssid"]}","{network["authentication"]}","{network["encryption"]}",{network["signal_strength"]},{network["risk_level"]},{network["security_score"]},{network["bssid_count"]},"{network["channel"]}"\n')
        
        txt_filename = f"wifi_quick_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        txt_filepath = os.path.join(self.reports_dir, txt_filename)
        
        with open(txt_filepath, 'w', encoding='utf-8') as f:
            f.write("=" * 60 + "\n")
            f.write("БЫСТРЫЙ ОТЧЕТ ПО БЕЗОПАСНОСТИ WI-FI СЕТЕЙ\n")
            f.write("=" * 60 + "\n\n")
            f.write(f"Дата сканирования: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Всего сетей: {len(analysis_results)}\n\n")
            
            critical_count = len([r for r in analysis_results if r['risk_level'] == 'КРИТИЧЕСКИЙ'])
            if critical_count > 0:
                f.write(f"  КРИТИЧЕСКИЕ СЕТИ ({critical_count}):\n")
                for network in analysis_results:
                    if network['risk_level'] == 'КРИТИЧЕСКИЙ':
                        f.write(f"   • {network['ssid']} - {network['authentication']} - Сигнал: {network['signal_strength']}%\n")
                f.write("\n")
            
            f.write("ВСЕ СЕТИ:\n")
            for network in analysis_results:
                f.write(f"• {network['ssid']}\n")
                f.write(f"  Тип: {network['authentication']} | Шифрование: {network['encryption']}\n")
                f.write(f"  Сигнал: {network['signal_strength']}% | Риск: {network['risk_level']} | Счет: {network['security_score']}/100\n")
                f.write(f"  Канал: {network['channel']} | Точек доступа: {network['bssid_count']}\n\n")
        
        return {
            "json": json_filepath,
            "csv": csv_filepath,
            "txt": txt_filepath
        }
    
    def main(self):
        print("Запуск анализатора безопасности Wi-Fi сетей")
        print("Разработчик: yoxiko")
        print("=" * 60)
        
        try:
            test_output = self.run_command("netsh wlan show drivers")
            if "Требуется повышение" in test_output or "Access is denied" in test_output:
                print("Требуются права администратора для полного сканирования")
                return
        except:
            pass
        
        print("Выполнение глубокого сканирования...")
        security_report = self.generate_security_report()
        
        if not security_report:
            print("Не удалось обнаружить Wi-Fi сети")
            return
        
        print(f"Обнаружено сетей: {len(security_report)}")
        
        report_file = self.generate_html_report(security_report)
        additional_files = self.generate_additional_files(security_report)
        
        print("=" * 60)
        print("Анализ завершен")
        print(f"HTML отчет: {report_file}")
        print(f"JSON данные: {additional_files['json']}")
        print(f"CSV таблица: {additional_files['csv']}")
        print(f"Текстовый отчет: {additional_files['txt']}")
        
        try:
            if platform.system() == 'Windows':
                os.startfile(report_file)
                print("Отчет открывается в браузере...")
            elif platform.system() == 'Darwin':
                subprocess.run(['open', report_file])
            else:
                subprocess.run(['xdg-open', report_file])
        except Exception as e:
            print(f"Откройте файл вручную: {report_file}")

if __name__ == "__main__":
    try:
        analyzer = WiFiSecurityAnalyzer()
        analyzer.main()
    except KeyboardInterrupt:
        print("\nПрервано пользователем")
    except Exception as e:
        print(f"\nОшибка: {e}")
    finally:
        input("\nНажмите Enter для выхода...")