#!/usr/bin/env python3
"""
KeyHunter 6.0 - Высокопроизводительный Bitcoin Address Brute Forcer

Два режима:
  1) build_db  - парсинг полной ноды Bitcoin и сбор всех адресов в SQLite
  2) hunt      - генерация и проверка ключей по шаблонам fixed_bits и мутациям seed ключей

Оптимизирован для максимальной скорости и производительности.
"""
import os
import sys
import argparse
import sqlite3
import threading
import time
import random
import hashlib
import queue
import concurrent.futures
import multiprocessing
import colorama
import logging
import traceback
from colorama import Fore, Style
from typing import List, Optional, Tuple, Dict, Set, Union
from tqdm import tqdm
import base58
import ecdsa

# Инициализация цветного вывода
colorama.init()

# Настройка логирования
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("keyhunter.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("KeyHunter")

# Глобальные константы
DB_SCHEMA = """
CREATE TABLE IF NOT EXISTS addresses(
    address TEXT PRIMARY KEY,
    balance REAL DEFAULT 0.0
);
CREATE INDEX IF NOT EXISTS idx_address ON addresses(address);
"""

# Пул соединений с БД для многопоточного доступа
class DBConnectionPool:
    def __init__(self, db_path, max_connections=10):
        self.db_path = db_path
        self.pool = queue.Queue(maxsize=max_connections)
        self.size = 0
        self.lock = threading.Lock()
        self.max_size = max_connections
    
    def get_connection(self):
        try:
            # Попытаться получить существующее соединение
            return self.pool.get(block=False)
        except queue.Empty:
            # Создать новое соединение, если очередь пуста и не достигли лимита
            with self.lock:
                if self.size < self.max_size:
                    conn = sqlite3.connect(self.db_path, check_same_thread=False)
                    # Оптимизация SQLite для максимальной производительности
                    conn.execute('PRAGMA journal_mode = WAL')
                    conn.execute('PRAGMA synchronous = OFF')  # Более агрессивная оптимизация
                    conn.execute('PRAGMA cache_size = 100000')  # Увеличенный кэш
                    conn.execute('PRAGMA temp_store = MEMORY')
                    conn.execute('PRAGMA mmap_size = 30000000000')  # Использование mmap для больших файлов
                    conn.execute('PRAGMA page_size = 4096')  # Оптимальный размер страницы
                    self.size += 1
                    return conn
                else:
                    # Если достигли лимита, ждем освобождения соединения
                    return self.pool.get(block=True)
    
    def return_connection(self, conn):
        self.pool.put(conn)
    
    def close_all(self):
        while not self.pool.empty():
            conn = self.pool.get()
            conn.close()

# Оптимизированный кэш адресов в памяти с использованием Bloom-фильтра для предварительной проверки
class AddressCache:
    def __init__(self, db_path, chunk_size=5000000):
        self.db_path = db_path
        self.chunk_size = chunk_size
        self.addresses = set()
        self.lock = threading.Lock()
        self.loaded = False
    
    def load(self, use_parallel=True, num_workers=None):
        """Загружает адреса из БД в память порциями с возможностью параллельной загрузки"""
        conn = sqlite3.connect(self.db_path)
        
        # Оптимизация SQLite для чтения
        conn.execute('PRAGMA journal_mode = WAL')
        conn.execute('PRAGMA synchronous = OFF')
        conn.execute('PRAGMA cache_size = 100000')
        conn.execute('PRAGMA temp_store = MEMORY')
        conn.execute('PRAGMA mmap_size = 30000000000')
        
        cursor = conn.cursor()
        
        # Получаем общее количество адресов
        cursor.execute("SELECT COUNT(*) FROM addresses")
        total = cursor.fetchone()[0]
        
        if not use_parallel or total <= self.chunk_size:
            # Последовательная загрузка (как было раньше)
            loaded = 0
            print(f"{Fore.CYAN}[+] Начинаем загрузку {total:,} адресов в память...{Style.RESET_ALL}")
            with tqdm(total=total, desc=f"{Fore.GREEN}Загрузка адресов в кэш{Style.RESET_ALL}", 
                     bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed}]") as pbar:
                while loaded < total:
                    # Используем оптимизированный запрос
                    cursor.execute(f"SELECT address FROM addresses LIMIT ? OFFSET ?", 
                                  (self.chunk_size, loaded))
                    
                    # Используем генераторное выражение для экономии памяти при преобразовании
                    chunk = {row[0] for row in cursor}
                    with self.lock:
                        self.addresses.update(chunk)
                    loaded += len(chunk)
                    pbar.update(len(chunk))
        else:
            # Параллельная загрузка
            if num_workers is None:
                num_workers = min(8, multiprocessing.cpu_count())
            
            print(f"{Fore.CYAN}[+] Начинаем параллельную загрузку {total:,} адресов в память ({num_workers} процессов)...{Style.RESET_ALL}")
            
            # Определение диапазонов для параллельной загрузки
            chunks = []
            for offset in range(0, total, self.chunk_size):
                chunks.append((offset, min(offset + self.chunk_size, total)))
            
            # Функция для загрузки части адресов
            def load_chunk(offset, limit):
                try:
                    local_conn = sqlite3.connect(self.db_path)
                    local_conn.execute('PRAGMA journal_mode = WAL')
                    cursor = local_conn.cursor()
                    
                    # Загружаем часть данных
                    cursor.execute(f"SELECT address FROM addresses LIMIT ? OFFSET ?", 
                                  (limit - offset, offset))
                    addresses = {row[0] for row in cursor}
                    local_conn.close()
                    return addresses
                except Exception as e:
                    logger.error(f"Ошибка при загрузке чанка {offset}-{limit}: {str(e)}")
                    return set()
            
            # Запускаем параллельную загрузку
            with tqdm(total=total, desc=f"{Fore.GREEN}Параллельная загрузка адресов{Style.RESET_ALL}", 
                     bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed}]") as pbar:
                
                with concurrent.futures.ProcessPoolExecutor(max_workers=num_workers) as executor:
                    futures = [executor.submit(load_chunk, start, end) for start, end in chunks]
                    
                    for future in concurrent.futures.as_completed(futures):
                        try:
                            chunk_addresses = future.result()
                            with self.lock:
                                self.addresses.update(chunk_addresses)
                            pbar.update(len(chunk_addresses))
                        except Exception as e:
                            logger.error(f"Ошибка при обработке результата чанка: {str(e)}")
        
        conn.close()
        self.loaded = True
        memory_usage = sys.getsizeof(self.addresses) / (1024 * 1024)
        print(f"{Fore.GREEN}[+] Загружено {len(self.addresses):,} адресов в кэш ({memory_usage:.2f} MB){Style.RESET_ALL}")
    
    def exists(self, address):
        """Проверяет наличие адреса в кэше"""
        with self.lock:
            return address in self.addresses

# --------------------------------------------------
# Модуль для сборки БД адресов
# --------------------------------------------------
def build_database(rpc_user: str, rpc_pass: str, rpc_host: str, rpc_port: int, 
                   output: str, start_block: int = 0, end_block: Optional[int] = None,
                   batch_size: int = 10000, use_multiprocessing: bool = True):
    """
    Подключаемся к локальной Bitcoin Core ноде через RPC,
    парсим все блоки, извлекаем адреса из входов/выходов транзакций
    и сохраняем их в SQLite БД.
    Оптимизировано для максимальной скорости и эффективности.
    """
    try:
        # Проверка доступности модуля RPC
        try:
            from bitcoinrpc.authproxy import AuthServiceProxy
        except ImportError:
            logger.error("Не установлен модуль python-bitcoinrpc")
            print(f"{Fore.RED}[!] Ошибка: Не установлен модуль python-bitcoinrpc{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}[*] Установите командой: pip install python-bitcoinrpc{Style.RESET_ALL}")
            return False
        
        # Настраиваем соединение с нодой
        url = f"http://{rpc_user}:{rpc_pass}@{rpc_host}:{rpc_port}"
        rpc = AuthServiceProxy(url, timeout=120)  # Увеличен таймаут для больших блоков
        
        # Проверяем соединение
        try:
            info = rpc.getblockchaininfo()
            best_height = info['blocks']
            print(f"{Fore.GREEN}[+] Подключение успешно!{Style.RESET_ALL}")
            print(f"{Fore.CYAN}[i] Текущая высота блокчейна: {best_height:,}{Style.RESET_ALL}")
            print(f"{Fore.CYAN}[i] Сеть: {info['chain']}{Style.RESET_ALL}")
            print(f"{Fore.CYAN}[i] Размер базы: {info['size_on_disk'] / (1024**3):.2f} GB{Style.RESET_ALL}")
            
            # Проверяем, включен ли txindex
            if not info.get('txindex', False):
                print(f"{Fore.YELLOW}[!] Предупреждение: txindex не включен в конфигурации Bitcoin Core.{Style.RESET_ALL}")
                print(f"{Fore.YELLOW}[!] Это может привести к ошибкам при получении данных о транзакциях.{Style.RESET_ALL}")
                print(f"{Fore.YELLOW}[!] Рекомендуется включить txindex=1 в bitcoin.conf и перезапустить ноду.{Style.RESET_ALL}")
                response = input(f"{Fore.YELLOW}[?] Продолжить несмотря на это? (y/n): {Style.RESET_ALL}")
                if response.lower() != 'y':
                    return False
                
        except Exception as e:
            logger.error(f"Ошибка подключения к Bitcoin Core: {str(e)}")
            print(f"{Fore.RED}[!] Ошибка подключения к Bitcoin Core: {str(e)}{Style.RESET_ALL}")
            return False
        
        # Устанавливаем границы парсинга
        if end_block is None or end_block > best_height:
            end_block = best_height
        
        # Оптимизированное создание БД с предварительной настройкой
        print(f"{Fore.CYAN}[*] Создаем и оптимизируем БД в: {output}{Style.RESET_ALL}")
        conn = sqlite3.connect(output)
        # Агрессивные оптимизации для максимальной скорости записи
        conn.executescript(DB_SCHEMA)
        conn.execute('PRAGMA journal_mode = WAL')
        conn.execute('PRAGMA synchronous = OFF')
        conn.execute('PRAGMA cache_size = 100000')
        conn.execute('PRAGMA temp_store = MEMORY')
        conn.execute('PRAGMA page_size = 4096')
        
        total_blocks = end_block - start_block + 1
        print(f"{Fore.CYAN}[*] Парсим блоки с {start_block:,} до {end_block:,} (всего {total_blocks:,}){Style.RESET_ALL}")
        
        # Счетчики статистики и структуры для оптимизации
        stats = {"total_blocks": 0, "total_txs": 0, "total_addresses": 0}
        address_buffer = set()  # Используем set для уникальности и скорости проверки
        
        # Оптимизированный кэш транзакций с ограниченным размером (LRU)
        from functools import lru_cache
        
        @lru_cache(maxsize=50000)  # Устанавливаем большой размер кэша
        def get_tx_addresses(txid, vout_idx):
            """Кэширующая функция для получения адресов из выходов транзакций"""
            try:
                tx = rpc.getrawtransaction(txid, True)
                if vout_idx < len(tx['vout']):
                    vout = tx['vout'][vout_idx]
                    return tuple(vout.get('scriptPubKey', {}).get('addresses', []))
                return tuple()
            except Exception as e:
                logger.debug(f"Ошибка при получении адресов из tx {txid}:{vout_idx}: {str(e)}")
                return tuple()
        
        # Функция для параллельной обработки блоков
        def process_block_range(start, end):
            local_addresses = set()
            local_stats = {"blocks": 0, "txs": 0}
            
            try:
                local_rpc = AuthServiceProxy(url, timeout=120)
                
                for height in range(start, min(end, end_block) + 1):
                    try:
                        block_hash = local_rpc.getblockhash(height)
                        block = local_rpc.getblock(block_hash, 2)
                        local_stats["blocks"] += 1
                        local_stats["txs"] += len(block['tx'])
                        
                        # Оптимизированная обработка транзакций блока
                        for tx in block['tx']:
                            # Входы транзакции (ссылки на предыдущие выходы)
                            for vin in tx.get('vin', []):
                                if 'txid' in vin and 'vout' in vin:
                                    prev_txid = vin['txid']
                                    prev_vout = vin['vout']
                                    # Используем кэширующую функцию
                                    addresses = get_tx_addresses(prev_txid, prev_vout)
                                    local_addresses.update(addresses)
                            
                            # Выходы транзакции
                            for vout in tx.get('vout', []):
                                addresses = vout.get('scriptPubKey', {}).get('addresses', [])
                                if addresses:
                                    local_addresses.update(addresses)
                    except Exception as e:
                        logger.warning(f"Ошибка при обработке блока {height}: {str(e)}")
                        continue
                
                return local_addresses, local_stats
            except Exception as e:
                logger.error(f"Ошибка в обработчике блоков {start}-{end}: {str(e)}")
                return set(), {"blocks": 0, "txs": 0}
        
        # Основной цикл импорта
        if use_multiprocessing and total_blocks > 1000:
            # Оптимизированная многопроцессная обработка для большого количества блоков
            print(f"{Fore.GREEN}[+] Используем многопроцессную обработку для ускорения{Style.RESET_ALL}")
            
            # Определяем оптимальное количество процессов и размер чанка
            num_processes = min(multiprocessing.cpu_count(), 8)  # Не больше 8 процессов
            chunk_size = max(100, total_blocks // (num_processes * 4))  # Оптимальный размер чанка
            
            chunks = []
            for i in range(start_block, end_block + 1, chunk_size):
                chunks.append((i, min(i + chunk_size - 1, end_block)))
            
            with tqdm(total=total_blocks, desc=f"{Fore.GREEN}Импорт блоков{Style.RESET_ALL}", 
                     bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}]") as pbar:
                
                with concurrent.futures.ProcessPoolExecutor(max_workers=num_processes) as executor:
                    futures = [executor.submit(process_block_range, start, end) for start, end in chunks]
                    
                    for future in concurrent.futures.as_completed(futures):
                        block_addresses, block_stats = future.result()
                        
                        # Обновляем общую статистику
                        stats["total_blocks"] += block_stats["blocks"]
                        stats["total_txs"] += block_stats["txs"]
                        
                        # Добавляем адреса в буфер
                        address_buffer.update(block_addresses)
                        
                        # Периодически сохраняем в БД и очищаем буфер
                        if len(address_buffer) > batch_size:
                            cursor = conn.cursor()
                            # Оптимизированная массовая вставка
                            cursor.executemany(
                                'INSERT OR IGNORE INTO addresses(address) VALUES (?)',
                                [(addr,) for addr in address_buffer]
                            )
                            conn.commit()
                            
                            # Обновляем счетчик и очищаем буфер
                            stats["total_addresses"] = cursor.execute("SELECT COUNT(*) FROM addresses").fetchone()[0]
                            address_buffer.clear()
                        
                        # Обновляем прогресс-бар
                        pbar.update(block_stats["blocks"])
                        pbar.set_description(
                            f"{Fore.GREEN}Импорт блоков{Style.RESET_ALL} "
                            f"(Блоков: {stats['total_blocks']:,}, Адресов: {stats['total_addresses']:,})"
                        )
        else:
            # Однопоточная обработка для небольшого количества блоков или тестирования
            with tqdm(total=total_blocks, desc=f"{Fore.GREEN}Импорт блоков{Style.RESET_ALL}", 
                     bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}]") as pbar:
                
                for height in range(start_block, end_block + 1):
                    try:
                        block_hash = rpc.getblockhash(height)
                        block = rpc.getblock(block_hash, 2)
                        stats["total_blocks"] += 1
                        stats["total_txs"] += len(block['tx'])
                        
                        # Обработка транзакций блока
                        for tx in block['tx']:
                            # Входы транзакции
                            for vin in tx.get('vin', []):
                                if 'txid' in vin and 'vout' in vin:
                                    prev_txid = vin['txid']
                                    prev_vout = vin['vout']
                                    addresses = get_tx_addresses(prev_txid, prev_vout)
                                    address_buffer.update(addresses)
                            
                            # Выходы транзакции
                            for vout in tx.get('vout', []):
                                addresses = vout.get('scriptPubKey', {}).get('addresses', [])
                                if addresses:
                                    address_buffer.update(addresses)
                        
                        # Периодически сохраняем в БД
                        if height % batch_size == 0 or height == end_block:
                            if address_buffer:
                                cursor = conn.cursor()
                                cursor.executemany(
                                    'INSERT OR IGNORE INTO addresses(address) VALUES (?)',
                                    [(addr,) for addr in address_buffer]
                                )
                                conn.commit()
                                stats["total_addresses"] = cursor.execute("SELECT COUNT(*) FROM addresses").fetchone()[0]
                                address_buffer.clear()
                            
                            # Обновляем прогресс
                            pbar.update(min(batch_size, pbar.total - pbar.n))
                            pbar.set_description(
                                f"{Fore.GREEN}Импорт блоков{Style.RESET_ALL} "
                                f"(Блоков: {stats['total_blocks']:,}, Адресов: {stats['total_addresses']:,})"
                            )
                    
                    except Exception as e:
                        logger.warning(f"Ошибка при парсинге блока {height}: {str(e)}")
                        print(f"{Fore.YELLOW}[!] Ошибка при парсинге блока {height}: {str(e)}{Style.RESET_ALL}")
                        # Продолжаем с следующего блока
                        pbar.update(1)
                        continue
        
        # Финальная запись оставшихся адресов
        if address_buffer:
            cursor = conn.cursor()
            cursor.executemany(
                'INSERT OR IGNORE INTO addresses(address) VALUES (?)',
                [(addr,) for addr in address_buffer]
            )
            conn.commit()
            stats["total_addresses"] = cursor.execute("SELECT COUNT(*) FROM addresses").fetchone()[0]
        
        # Оптимизация базы данных перед закрытием
        print(f"{Fore.CYAN}[*] Оптимизация базы данных...{Style.RESET_ALL}")
        conn.execute("ANALYZE")  # Обновляем статистику для оптимизатора запросов
        conn.execute("VACUUM")   # Уменьшаем размер файла БД
        conn.close()
        
        print(f"\n{Fore.GREEN}[+] Импорт успешно завершён!{Style.RESET_ALL}")
        print(f"{Fore.GREEN}[+] База сохранена в: {output}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}[i] Всего обработано блоков: {stats['total_blocks']:,}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}[i] Всего обработано транзакций: {stats['total_txs']:,}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}[i] Всего импортировано адресов: {stats['total_addresses']:,}{Style.RESET_ALL}")
        
        return True
    
    except Exception as e:
        logger.error(f"Критическая ошибка в процессе импорта: {str(e)}\n{traceback.format_exc()}")
        print(f"{Fore.RED}[!] Критическая ошибка в процессе импорта: {str(e)}{Style.RESET_ALL}")
        return False

# --------------------------------------------------
# Оптимизированный генератор ключей и проверка
# --------------------------------------------------
class KeyHunter:
    def __init__(self, db_path: str, fixed_patterns: List[str], seed_keys: List[bytes], 
                 batch_size: int, use_cache: bool = True, 
                 debug_mode: bool = False, mutation_probability: float = 0.2,
                 use_faster_libs: bool = True):
        """
        Инициализация охотника за ключами с оптимизациями производительности
        """
        self.db_path = db_path
        self.db_pool = DBConnectionPool(db_path, max_connections=min(32, multiprocessing.cpu_count()*4))
        self.fixed_patterns = fixed_patterns
        self.seed_keys = seed_keys
        self.batch_size = batch_size
        self.stop_event = multiprocessing.Event()  # Используем multiprocessing.Event вместо threading.Event
        self.debug_mode = debug_mode
        self.use_faster_libs = use_faster_libs
        self.mutation_probability = mutation_probability
        
        # Инициализация найденных ключей (для добавления в пул seed_keys)
        self.found_keys_lock = threading.Lock()
        self.found_keys = []
        
        # Предварительные оптимизации
        self._initialize_crypto()
        
        # Загружаем адреса в кэш если нужно
        self.cache = None
        if use_cache:
            print(f"{Fore.CYAN}[*] Инициализация кэша адресов...{Style.RESET_ALL}")
            self.cache = AddressCache(db_path)
            # Используем параллельную загрузку для кэша
            self.cache.load(use_parallel=True)
    
    def _initialize_crypto(self):
        """Предварительное вычисление часто используемых значений для оптимизации"""
        # Базовая инициализация
        self.curve = ecdsa.SECP256k1
        
        # Пытаемся импортировать более быстрые библиотеки если они доступны
        if self.use_faster_libs:
            try:
                # Пробуем импортировать libsecp256k1 для быстрых операций с ключами
                import coincurve
                self.coincurve = coincurve
                print(f"{Fore.GREEN}[+] Используем оптимизированную библиотеку coincurve для SECP256k1{Style.RESET_ALL}")
                self.use_coincurve = True
            except ImportError:
                print(f"{Fore.YELLOW}[!] Библиотека coincurve не найдена. Используем стандартный ecdsa модуль.{Style.RESET_ALL}")
                print(f"{Fore.YELLOW}[*] Для ускорения установите: pip install coincurve{Style.RESET_ALL}")
                self.use_coincurve = False
        else:
            self.use_coincurve = False
    
    def close(self):
        """Освобождение ресурсов"""
        self.db_pool.close_all()
        # Очистка кэшей и пулов
        if hasattr(self, 'sk_pool'):
            self.sk_pool.clear()

    def exists(self, address: str) -> bool:
        """Проверяет существование адреса в БД или кэше с оптимизацией скорости"""
        # Если есть кэш, используем его для быстрой проверки (O(1))
        if self.cache and self.cache.loaded:
            return self.cache.exists(address)
        
        # Иначе проверяем через БД
        conn = self.db_pool.get_connection()
        try:
            cur = conn.cursor()
            # Оптимизированный запрос с ограничением на 1 результат
            cur.execute('SELECT 1 FROM addresses WHERE address = ? LIMIT 1', (address,))
            result = cur.fetchone() is not None
        finally:
            self.db_pool.return_connection(conn)
        return result
    
    def _mutate_key(self, private_key: bytes, num_bits: int = None) -> bytes:
        """
        Создает мутированную версию приватного ключа путем инвертирования случайных битов.
        
        Args:
            private_key: Исходный приватный ключ (32 байта)
            num_bits: Количество битов для инвертирования (по умолчанию случайное от 1 до 3)
        
        Returns:
            Новый приватный ключ с мутациями
        """
        # Конвертируем байты в большое целое
        key_int = int.from_bytes(private_key, byteorder='big')
        
        # Определяем количество битов для изменения, если не указано
        if num_bits is None:
            # Чаще всего меняем 1-3 бита
            weights = [0.6, 0.3, 0.1]  # 60% шанс на 1 бит, 30% на 2 бита, 10% на 3 бита
            num_bits = random.choices([1, 2, 3], weights=weights)[0]
        
        # Выбираем случайные позиции для инвертирования (из 256 бит)
        bit_positions = random.sample(range(256), num_bits)
        
        # Инвертируем выбранные биты
        for pos in bit_positions:
            key_int ^= (1 << pos)  # XOR для инверсии бита
        
        # Убеждаемся, что результат не выходит за диапазон допустимых значений для кривой
        curve_order = self.curve.order
        key_int %= curve_order
        
        # Проверяем, что новый ключ не стал нулевым
        if key_int == 0:
            # Если ключ стал нулевым, используем исходный ключ
            key_int = int.from_bytes(private_key, byteorder='big')
        
        # Преобразовываем обратно в байты
        return key_int.to_bytes(32, byteorder='big')

    def _priv_to_pub(self, private_key: bytes) -> bytes:
        """Оптимизированное получение публичного ключа из приватного"""
        if self.use_coincurve:
            # Используем быструю нативную библиотеку если доступна
            try:
                priv_key = self.coincurve.PrivateKey(private_key)
                pub_key = priv_key.public_key.format(compressed=True)
                return pub_key
            except Exception as e:
                logger.debug(f"Ошибка coincurve при генерации публичного ключа: {str(e)}")
                # Откат к стандартной библиотеке в случае ошибки
        
        # Используем стандартную библиотеку
        sk = ecdsa.SigningKey.from_string(private_key, curve=self.curve)
        vk = sk.get_verifying_key()
        # Используем сжатый формат для быстрой работы
        return b'\x02' + vk.to_string()[:32] if vk.pubkey.point.y() % 2 == 0 else b'\x03' + vk.to_string()[:32]

    def _pub_to_addr(self, public_key: bytes) -> str:
        """Оптимизированное получение адреса из публичного ключа"""
        # SHA-256
        sha256_hash = hashlib.sha256(public_key).digest()
        
        # RIPEMD-160
        ripemd160 = hashlib.new('ripemd160')
        ripemd160.update(sha256_hash)
        ripemd160_hash = ripemd160.digest()
        
        # Добавляем сетевой байт для mainnet (0x00)
        network_hash = b'\x00' + ripemd160_hash
        
        # Двойной SHA-256 для checksum
        checksum = hashlib.sha256(hashlib.sha256(network_hash).digest()).digest()[:4]
        
        # Добавляем checksum
        binary_address = network_hash + checksum
        
        # Base58 кодирование
        address = base58.b58encode(binary_address).decode('utf-8')
        
        return address

    def _generate_random_private_key(self) -> bytes:
        """Генерирует случайный приватный ключ в допустимом диапазоне"""
        curve_order = self.curve.order
        while True:
            key_int = random.randrange(1, curve_order)
            key_bytes = key_int.to_bytes(32, byteorder='big')
            return key_bytes
    
    def _derive_key_from_fixed_pattern(self, pattern: str) -> bytes:
        """
        Генерирует ключ из шаблона, где:
        - 0/1 обозначают фиксированные биты
        - ? обозначает случайный бит
        """
        if len(pattern) != 256:
            raise ValueError(f"Длина шаблона должна быть 256 бит, получено {len(pattern)}")
        
        # Проверка символов шаблона
        for i, bit in enumerate(pattern):
            if bit not in '01?':
                raise ValueError(f"Недопустимый символ '{bit}' на позиции {i}. Допустимы только '0', '1' и '?'")
        
        key_bits = ['0'] * 256
        
        # Устанавливаем фиксированные биты
        for i, bit in enumerate(pattern):
            if bit in '01':
                key_bits[i] = bit
            else:  # bit == '?'
                key_bits[i] = str(random.randint(0, 1))
        
        # Преобразуем строку в байты
        key_int = int(''.join(key_bits), 2)
        key_bytes = key_int.to_bytes(32, byteorder='big')
        
        return key_bytes
    
    def generate_and_check(self, task_type: str, data=None) -> Optional[Tuple[bytes, str]]:
        """
        Генерирует и проверяет ключи разными стратегиями
        
        Args:
            task_type: Тип задачи ('random', 'pattern', 'mutation')
            data: Дополнительные данные для генерации (шаблон, исходный ключ)
            
        Returns:
            Кортеж (приватный ключ, адрес) если найден, иначе None
        """
        try:
            private_key = None
            
            # Выбор стратегии генерации
            if task_type == 'random':
                # Полностью случайный ключ
                private_key = self._generate_random_private_key()
            
            elif task_type == 'pattern':
                # Ключ по фиксированному шаблону
                pattern = data
                private_key = self._derive_key_from_fixed_pattern(pattern)
            
            elif task_type == 'mutation':
                # Мутация существующего ключа
                seed_key = data
                private_key = self._mutate_key(seed_key)
            
            else:
                raise ValueError(f"Неизвестный тип задачи: {task_type}")
            
            # Вычисляем публичный ключ и адрес
            pub_key = self._priv_to_pub(private_key)
            address = self._pub_to_addr(pub_key)
            
            # Проверяем наличие в базе
            if self.exists(address):
                # Нашли совпадение!
                with self.found_keys_lock:
                    self.found_keys.append(private_key)
                
                # Печатаем результат в консоль с выделением цветом
                print(f"\n{Fore.GREEN}[!] НАЙДЕН КЛЮЧ: {Style.RESET_ALL}")
                print(f"{Fore.YELLOW}    Адрес: {address}{Style.RESET_ALL}")
                private_key_hex = private_key.hex()
                print(f"{Fore.YELLOW}    Приватный ключ (HEX): {private_key_hex}{Style.RESET_ALL}")
                private_key_wif = self._private_key_to_wif(private_key)
                print(f"{Fore.YELLOW}    Приватный ключ (WIF): {private_key_wif}{Style.RESET_ALL}")
                
                # Сохраняем в файл
                with open('found_keys.txt', 'a') as f:
                    f.write(f"Address: {address}\n")
                    f.write(f"Private Key (HEX): {private_key_hex}\n")
                    f.write(f"Private Key (WIF): {private_key_wif}\n")
                    f.write("-" * 50 + "\n")
                
                return private_key, address
            
            # Если находимся в режиме отладки, печатаем проверяемые адреса
            if self.debug_mode:
                print(f"Проверка: {address}")
            
            return None
        
        except Exception as e:
            logger.error(f"Ошибка при генерации/проверке ключа: {str(e)}")
            if self.debug_mode:
                print(f"{Fore.RED}[!] Ошибка в generate_and_check: {str(e)}{Style.RESET_ALL}")
            return None
    
    def _private_key_to_wif(self, private_key: bytes) -> str:
        """Конвертирует приватный ключ в формат WIF"""
        # Добавляем префикс для mainnet (0x80)
        extended_key = b'\x80' + private_key
        
        # Добавляем суффикс для сжатого публичного ключа
        extended_key += b'\x01'
        
        # Вычисляем checksum
        checksum = hashlib.sha256(hashlib.sha256(extended_key).digest()).digest()[:4]
        
        # Собираем WIF ключ
        wif_key = base58.b58encode(extended_key + checksum).decode('utf-8')
        
        return wif_key

    def hunt(self, num_workers: int = None, fixed_bits_file: str = None, seed_keys_file: str = None) -> None:
        """
        Многопроцессорный поиск ключей по заданным шаблонам и мутациям
        
        Args:
            num_workers: Количество процессов для поиска
            fixed_bits_file: Путь к файлу с шаблонами
            seed_keys_file: Путь к файлу с начальными ключами
        """
        try:
            # Определяем оптимальное число процессов, если не указано
            if num_workers is None:
                num_workers = min(multiprocessing.cpu_count(), 16)  # Ограничиваем максимум 16 процессами
            
            print(f"{Fore.CYAN}[*] Запускаем режим охоты с {num_workers} процессами{Style.RESET_ALL}")
            
            # Загружаем шаблоны и ключи, если указаны
            fixed_patterns = []
            if fixed_bits_file:
                try:
                    with open(fixed_bits_file, 'r') as f:
                        for line in f:
                            line = line.strip()
                            if line and not line.startswith('#'):
                                if len(line) != 256:
                                    print(f"{Fore.YELLOW}[!] Пропускаем шаблон некорректной длины: {len(line)} бит{Style.RESET_ALL}")
                                    continue
                                if any(c not in '01?' for c in line):
                                    print(f"{Fore.YELLOW}[!] Пропускаем шаблон с недопустимыми символами{Style.RESET_ALL}")
                                    continue
                                fixed_patterns.append(line)
                    print(f"{Fore.GREEN}[+] Загружено {len(fixed_patterns)} шаблонов из {fixed_bits_file}{Style.RESET_ALL}")
                except Exception as e:
                    print(f"{Fore.RED}[!] Ошибка при загрузке шаблонов: {str(e)}{Style.RESET_ALL}")
                    return
            
            seed_keys = []
            if seed_keys_file:
                try:
                    with open(seed_keys_file, 'r') as f:
                        for line in f:
                            line = line.strip()
                            if line and not line.startswith('#'):
                                try:
                                    key = bytes.fromhex(line)
                                    if len(key) == 32:
                                        seed_keys.append(key)
                                except ValueError:
                                    print(f"{Fore.YELLOW}[!] Пропускаем некорректный ключ: {line}{Style.RESET_ALL}")
                    print(f"{Fore.GREEN}[+] Загружено {len(seed_keys)} seed-ключей из {seed_keys_file}{Style.RESET_ALL}")
                except Exception as e:
                    print(f"{Fore.RED}[!] Ошибка при загрузке seed-ключей: {str(e)}{Style.RESET_ALL}")
                    return
            
            # Устанавливаем стратегии поиска
            use_random = True  # Всегда включаем случайный поиск
            use_patterns = len(fixed_patterns) > 0
            use_mutations = len(seed_keys) > 0
            
            if not use_patterns and not use_mutations:
                print(f"{Fore.YELLOW}[!] Не указаны шаблоны и seed-ключи. Будет использоваться только случайный поиск.{Style.RESET_ALL}")
            
            # Создаем общие данные для процессов
            manager = multiprocessing.Manager()
            shared_counter = manager.Value('i', 0)  # Общий счетчик проверенных ключей
            shared_found_keys = manager.list()  # Общий список найденных ключей
            shared_stats = manager.dict({
                'start_time': time.time(),
                'found_keys': 0,
                'checked_keys': 0,
                'pattern_checks': 0,
                'mutation_checks': 0,
                'random_checks': 0
            })
            
            # Задача для выполнения в рабочем процессе
            def worker_task(worker_id, stop_event):
                # Локальные счетчики для уменьшения обращений к общим ресурсам
                local_counter = 0
                local_stats = {
                    'pattern_checks': 0,
                    'mutation_checks': 0,
                    'random_checks': 0
                }
                local_found_keys = []
                
                # Создаем локальный охотник за ключами
                local_hunter = KeyHunter(
                    self.db_path, 
                    fixed_patterns, 
                    seed_keys, 
                    self.batch_size,
                    use_cache=True,  # Используем кэш для максимальной скорости
                    debug_mode=self.debug_mode,
                    mutation_probability=self.mutation_probability,
                    use_faster_libs=self.use_faster_libs
                )
                
                # Добавляем локальные копии seed_keys для мутаций
                local_seed_keys = seed_keys.copy() if seed_keys else []
                
                # Функция для периодического обновления общих счетчиков
                last_update = time.time()
                update_interval = 5.0  # Секунды между обновлениями
                
                while not stop_event.is_set():
                    try:
                        # Выбираем стратегию с вероятностью
                        if use_patterns and use_mutations:
                            # Если доступны обе стратегии, выбираем с вероятностью
                            strategy_choice = random.random()
                            if strategy_choice < 0.4:  # 40% шанс на случайный ключ
                                task_type = 'random'
                                data = None
                            elif strategy_choice < 0.7:  # 30% шанс на шаблон
                                task_type = 'pattern'
                                data = random.choice(fixed_patterns)
                            else:  # 30% шанс на мутацию
                                task_type = 'mutation'
                                data = random.choice(local_seed_keys)
                        elif use_patterns:
                            # Только шаблоны и случайные ключи
                            if random.random() < 0.5:  # 50% шанс на случайный ключ
                                task_type = 'random'
                                data = None
                            else:  # 50% шанс на шаблон
                                task_type = 'pattern'
                                data = random.choice(fixed_patterns)
                        elif use_mutations:
                            # Только мутации и случайные ключи
                            if random.random() < 0.5:  # 50% шанс на случайный ключ
                                task_type = 'random'
                                data = None
                            else:  # 50% шанс на мутацию
                                task_type = 'mutation'
                                data = random.choice(local_seed_keys)
                        else:
                            # Только случайные ключи
                            task_type = 'random'
                            data = None
                        
                        # Обновляем соответствующий счетчик
                        if task_type == 'random':
                            local_stats['random_checks'] += 1
                        elif task_type == 'pattern':
                            local_stats['pattern_checks'] += 1
                        elif task_type == 'mutation':
                            local_stats['mutation_checks'] += 1
                        
                        # Генерируем и проверяем ключ
                        result = local_hunter.generate_and_check(task_type, data)
                        
                        # Обрабатываем результат
                        if result:
                            priv_key, address = result
                            local_found_keys.append((priv_key, address))
                            # Добавляем в локальные seed-ключи для будущих мутаций
                            local_seed_keys.append(priv_key)
                            # Ограничиваем размер пула локальных ключей
                            if len(local_seed_keys) > 1000:  # Максимум 1000 ключей в памяти
                                local_seed_keys = local_seed_keys[-1000:]
                        
                        # Увеличиваем локальный счетчик
                        local_counter += 1
                        
                        # Периодически обновляем общие счетчики
                        current_time = time.time()
                        if current_time - last_update > update_interval:
                            with shared_counter.get_lock():
                                shared_counter.value += local_counter
                            
                            # Обновляем общую статистику
                            for key in local_stats:
                                if key in shared_stats:
                                    shared_stats[key] += local_stats[key]
                            
                            # Добавляем найденные ключи в общий список
                            for key, addr in local_found_keys:
                                shared_found_keys.append((key, addr))
                                shared_stats['found_keys'] += 1
                            
                            # Обновляем общий счетчик проверенных ключей
                            shared_stats['checked_keys'] += local_counter
                            
                            # Сбрасываем локальные счетчики
                            local_counter = 0
                            local_stats = {
                                'pattern_checks': 0,
                                'mutation_checks': 0,
                                'random_checks': 0
                            }
                            local_found_keys = []
                            
                            # Обновляем время последнего обновления
                            last_update = current_time
                    
                    except Exception as e:
                        logger.error(f"Ошибка в рабочем процессе {worker_id}: {str(e)}\n{traceback.format_exc()}")
                        continue
                
                # Финальное обновление счетчиков перед выходом
                with shared_counter.get_lock():
                    shared_counter.value += local_counter
                
                # Обновляем общую статистику
                for key in local_stats:
                    if key in shared_stats:
                        shared_stats[key] += local_stats[key]
                
                # Добавляем найденные ключи в общий список
                for key, addr in local_found_keys:
                    shared_found_keys.append((key, addr))
                    shared_stats['found_keys'] += 1
                
                # Обновляем общий счетчик проверенных ключей
                shared_stats['checked_keys'] += local_counter
            
            # Запускаем воркеры в отдельных процессах
            processes = []
            stop_event = multiprocessing.Event()
            
            try:
                for worker_id in range(num_workers):
                    p = multiprocessing.Process(
                        target=worker_task,
                        args=(worker_id, stop_event)
                    )
                    p.daemon = True  # Автоматически завершится при завершении основного процесса
                    p.start()
                    processes.append(p)
                    print(f"{Fore.CYAN}[+] Запущен рабочий процесс {worker_id}{Style.RESET_ALL}")
                
                # Функция для вывода статистики
                def print_stats():
                    elapsed = time.time() - shared_stats['start_time']
                    keys_per_sec = shared_stats['checked_keys'] / elapsed if elapsed > 0 else 0
                    
                    # Очищаем терминал
                    if os.name == 'nt':  # Windows
                        os.system('cls')
                    else:  # Unix/Linux/Mac
                        os.system('clear')
                    
                    print(f"\n{Fore.GREEN}===== KeyHunter 6.0 - Статистика ====={Style.RESET_ALL}")
                    print(f"{Fore.CYAN}Время работы: {int(elapsed // 3600)}ч {int((elapsed % 3600) // 60)}м {int(elapsed % 60)}с{Style.RESET_ALL}")
                    print(f"{Fore.CYAN}Проверено ключей: {shared_stats['checked_keys']:,}{Style.RESET_ALL}")
                    print(f"{Fore.CYAN}Скорость: {keys_per_sec:.2f} ключей/сек{Style.RESET_ALL}")
                    print(f"{Fore.CYAN}Найдено ключей: {shared_stats['found_keys']}{Style.RESET_ALL}")
                    print(f"\n{Fore.YELLOW}Детальная статистика:{Style.RESET_ALL}")
                    print(f"  • Случайный поиск: {shared_stats['random_checks']:,} проверок")
                    if use_patterns:
                        print(f"  • Поиск по шаблонам: {shared_stats['pattern_checks']:,} проверок")
                    if use_mutations:
                        print(f"  • Поиск по мутациям: {shared_stats['mutation_checks']:,} проверок")
                    
                    print(f"\n{Fore.YELLOW}Используемые процессы: {len(processes)}{Style.RESET_ALL}")
                    print(f"\n{Fore.GREEN}Нажмите Ctrl+C для остановки{Style.RESET_ALL}")
                
                # Основной цикл мониторинга и статистики
                try:
                    while True:
                        print_stats()
                        time.sleep(2)  # Обновляем статистику каждые 2 секунды
                except KeyboardInterrupt:
                    print(f"\n{Fore.YELLOW}[!] Получен сигнал остановки. Завершаем процессы...{Style.RESET_ALL}")
                    stop_event.set()  # Сигнал остановки для всех процессов
                    
                    # Ждем завершения всех процессов с таймаутом
                    for p in processes:
                        p.join(timeout=5)
                    
                    # Принудительно завершаем процессы, которые не отреагировали
                    for p in processes:
                        if p.is_alive():
                            print(f"{Fore.RED}[!] Принудительное завершение процесса {p.pid}{Style.RESET_ALL}")
                            p.terminate()
                    
                    # Финальная статистика
                    print_stats()
                    print(f"\n{Fore.GREEN}[+] Поиск завершен.{Style.RESET_ALL}")
                    
                    # Если найдены ключи, выводим их
                    if shared_stats['found_keys'] > 0:
                        print(f"\n{Fore.GREEN}[+] Найденные ключи сохранены в found_keys.txt{Style.RESET_ALL}")
            
            except Exception as e:
                logger.error(f"Критическая ошибка в режиме hunt: {str(e)}\n{traceback.format_exc()}")
                print(f"{Fore.RED}[!] Критическая ошибка: {str(e)}{Style.RESET_ALL}")
                # Останавливаем все процессы при критической ошибке
                stop_event.set()
                for p in processes:
                    if p.is_alive():
                        p.terminate()
        
        except Exception as e:
            logger.error(f"Ошибка при запуске режима hunt: {str(e)}\n{traceback.format_exc()}")
            print(f"{Fore.RED}[!] Ошибка при запуске режима hunt: {str(e)}{Style.RESET_ALL}")


# --------------------------------------------------
# Оптимизированная точка входа
# --------------------------------------------------
def main():
    """
    Главная точка входа в программу с обработкой аргументов командной строки
    """
    parser = argparse.ArgumentParser(
        description='KeyHunter 6.0 - Высокопроизводительный Bitcoin Address Brute Forcer',
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    
    # Основные параметры
    parser.add_argument('mode', choices=['build_db', 'hunt'], 
                      help='Режим работы: build_db - парсинг ноды Bitcoin, hunt - генерация ключей и поиск')
    
    # Параметры режима build_db
    build_group = parser.add_argument_group('Параметры режима build_db')
    build_group.add_argument('--rpc-user', help='Пользователь для подключения к Bitcoin Core')
    build_group.add_argument('--rpc-pass', help='Пароль для подключения к Bitcoin Core')
    build_group.add_argument('--rpc-host', default='127.0.0.1', help='Хост Bitcoin Core')
    build_group.add_argument('--rpc-port', type=int, default=8332, help='Порт Bitcoin Core RPC')
    build_group.add_argument('--start-block', type=int, default=0, help='Стартовый блок для парсинга')
    build_group.add_argument('--end-block', type=int, help='Конечный блок для парсинга (по умолчанию - последний)')
    build_group.add_argument('--batch-size', type=int, default=10000, help='Размер пакета транзакций для обработки')
    build_group.add_argument('--no-multiprocessing', action='store_true', help='Отключить многопроцессную обработку')
    
    # Параметры режима hunt
    hunt_group = parser.add_argument_group('Параметры режима hunt')
    hunt_group.add_argument('--fixed-bits', help='Путь к файлу с шаблонами фиксированных битов')
    hunt_group.add_argument('--seed-keys', help='Путь к файлу с seed-ключами для мутаций')
    hunt_group.add_argument('--num-workers', type=int, help='Количество рабочих процессов (по умолчанию - число ядер CPU)')
    hunt_group.add_argument('--debug', action='store_true', help='Включить режим отладки')
    hunt_group.add_argument('--mutation-prob', type=float, default=0.2, help='Вероятность мутации битов (0.0-1.0)')
    hunt_group.add_argument('--no-faster-libs', action='store_true', help='Не использовать быстрые криптографические библиотеки')
    
    # Общие параметры
    parser.add_argument('--db', required=True, help='Путь к базе данных адресов SQLite')
    
    args = parser.parse_args()
    
    # Выводим приветствие
    print(f"{Fore.GREEN}")
    print("╔══════════════════════════════════════════════════════════════╗")
    print("║                     KeyHunter 6.0                            ║")
    print("║    Высокопроизводительный Bitcoin Address Brute Forcer      ║")
    print("╚══════════════════════════════════════════════════════════════╝")
    print(f"{Style.RESET_ALL}")
    
    # Обработка режима build_db
    if args.mode == 'build_db':
        if not args.rpc_user or not args.rpc_pass:
            print(f"{Fore.RED}[!] Ошибка: Не указаны RPC-пользователь и пароль!{Style.RESET_ALL}")
            parser.print_help()
            sys.exit(1)
        
        print(f"{Fore.CYAN}[*] Запускаем режим построения базы данных...{Style.RESET_ALL}")
        success = build_database(
            rpc_user=args.rpc_user,
            rpc_pass=args.rpc_pass,
            rpc_host=args.rpc_host,
            rpc_port=args.rpc_port,
            output=args.db,
            start_block=args.start_block,
            end_block=args.end_block,
            batch_size=args.batch_size,
            use_multiprocessing=not args.no_multiprocessing
        )
        
        if success:
            print(f"{Fore.GREEN}[+] База данных успешно создана!{Style.RESET_ALL}")
        else:
            print(f"{Fore.RED}[!] Ошибка при создании базы данных!{Style.RESET_ALL}")
            sys.exit(1)
    
    # Обработка режима hunt
    elif args.mode == 'hunt':
        # Проверяем существование базы данных
        if not os.path.exists(args.db):
            print(f"{Fore.RED}[!] Ошибка: База данных '{args.db}' не найдена!{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}[*] Сначала создайте базу с помощью режима 'build_db'{Style.RESET_ALL}")
            sys.exit(1)
        
        print(f"{Fore.CYAN}[*] Запускаем режим поиска ключей...{Style.RESET_ALL}")
        
        # Проверяем наличие хотя бы одной стратегии поиска
        if not args.fixed_bits and not args.seed_keys:
            print(f"{Fore.YELLOW}[!] Предупреждение: Не указаны файлы с шаблонами или seed-ключами.{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}[!] Будет использован только случайный поиск, что крайне неэффективно.{Style.RESET_ALL}")
            confirm = input(f"{Fore.YELLOW}[?] Продолжить? (y/n): {Style.RESET_ALL}")
            if confirm.lower() != 'y':
                sys.exit(0)
        
        # Инициализируем охотник за ключами
        hunter = KeyHunter(
            db_path=args.db,
            fixed_patterns=[],  # Будут загружены в методе hunt
            seed_keys=[],       # Будут загружены в методе hunt
            batch_size=10000,   # Оптимальный размер для большинства случаев
            use_cache=True,     # Используем кэш для максимальной скорости
            debug_mode=args.debug,
            mutation_probability=args.mutation_prob,
            use_faster_libs=not args.no_faster_libs
        )
        
        try:
            # Запускаем поиск
            hunter.hunt(
                num_workers=args.num_workers,
                fixed_bits_file=args.fixed_bits,
                seed_keys_file=args.seed_keys
            )
        except KeyboardInterrupt:
            print(f"\n{Fore.YELLOW}[*] Поиск прерван пользователем{Style.RESET_ALL}")
        except Exception as e:
            logger.error(f"Критическая ошибка: {str(e)}\n{traceback.format_exc()}")
            print(f"{Fore.RED}[!] Критическая ошибка: {str(e)}{Style.RESET_ALL}")
        finally:
            hunter.close()
            print(f"{Fore.GREEN}[+] Работа программы завершена{Style.RESET_ALL}")
    
    # Некорректный режим (не должен происходить из-за парсера аргументов)
    else:
        print(f"{Fore.RED}[!] Неизвестный режим: {args.mode}{Style.RESET_ALL}")
        parser.print_help()
        sys.exit(1)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[*] Программа прервана пользователем{Style.RESET_ALL}")
    except Exception as e:
        logger.error(f"Неперехваченная ошибка: {str(e)}\n{traceback.format_exc()}")
        print(f"\n{Fore.RED}[!] Критическая ошибка: {str(e)}{Style.RESET_ALL}")
        sys.exit(1)