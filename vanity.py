"""
Генератор красивого адреса Telegram Wallet (контракт WalletTg) + активация.

Схема Telegram Wallet:
  слова 1-12  -> BIP39 seed -> SLIP-10 ed25519 m/44'/607'/0' -> ключ-«якорь» -> адрес
  слова 13-24 -> тот же путь -> рабочий ключ кошелька (ставится через ChangePublicKeyRequestE)

Использование:
  python vanity.py search PEPE    поиск адреса, оканчивающегося на PEPE (регистр точный),
                                  затем активация в том же окне
  python vanity.py activate       активация, если окно поиска закрылось (слова вводятся вручную)
  python vanity.py rotate         сменить слова 13-24 на новые (адрес тот же)
  python vanity.py selftest       проверка криптографии на эталонных векторах

Сид-фраза нигде не сохраняется: она есть только на экране и в памяти программы.
"""

import binascii
import hashlib
import hmac
import json
import multiprocessing as mp
import os
import struct
import sys
import time
import urllib.request
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

HERE = Path(__file__).resolve().parent
WORDLIST_SHA256 = '2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda'

# contracts/WalletTrampoline.boc из ton-blockchain/tg-wallet-contract
TRAMPOLINE_BOC = bytes.fromhex(
    'b5ee9c7241010101001a000030ff00209821d7498308b9f240df8085f833d0ed1e20ed53d969427e39')
TRAMPOLINE_CODE_HASH = bytes.fromhex(
    '9149ae51c1e4689710cebf7830297b16acfbadb363a920a537893e7ffeeca768')
SUBWALLET_ID = 0x7FFF7F11  # mainnet
OP_CHANGE_KEY_E = 0xFBBA99C8
KEY_ROTATION_TAG = 0x4B45595F524F544154494F4E  # "KEY_ROTATION"
TONCENTER = 'https://toncenter.com/api/v2'
B64URL = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_'


def load_wordlist():
    raw = (HERE / 'english.txt').read_bytes()
    if hashlib.sha256(raw).hexdigest() != WORDLIST_SHA256:
        sys.exit('english.txt повреждён: хеш не совпадает с официальным списком BIP39')
    words = raw.decode().split()
    assert len(words) == 2048
    return words


WORDS = load_wordlist()
WORD_INDEX = {w: i for i, w in enumerate(WORDS)}


# ---------- BIP39 / SLIP-10 / ed25519 ----------

def entropy_to_words(entropy):
    """16 байт энтропии -> 12 слов BIP39 (4 бита чек-суммы)."""
    cs = hashlib.sha256(entropy).digest()[0] >> 4
    n = (int.from_bytes(entropy, 'big') << 4) | cs
    return [WORDS[(n >> (11 * (11 - i))) & 0x7FF] for i in range(12)]


def validate_words(words):
    if len(words) != 12 or any(w not in WORD_INDEX for w in words):
        return False
    n = 0
    for w in words:
        n = (n << 11) | WORD_INDEX[w]
    entropy = (n >> 4).to_bytes(16, 'big')
    return entropy_to_words(entropy) == words


def words_to_seed(words, passphrase=''):
    return hashlib.pbkdf2_hmac('sha512', ' '.join(words).encode(),
                               ('mnemonic' + passphrase).encode(), 2048)


def slip10_ed25519(seed, path=(44, 607, 0)):
    I = hmac.digest(b'ed25519 seed', seed, 'sha512')
    key, chain = I[:32], I[32:]
    for index in path:
        I = hmac.digest(chain, b'\x00' + key + struct.pack('>I', index | 0x80000000), 'sha512')
        key, chain = I[:32], I[32:]
    return key


def public_key(priv):
    return Ed25519PrivateKey.from_private_bytes(priv).public_key().public_bytes_raw()


def sign(priv, data):
    return Ed25519PrivateKey.from_private_bytes(priv).sign(data)


def words_to_keys(words):
    priv = slip10_ed25519(words_to_seed(words))
    return priv, public_key(priv)


# ---------- Ячейки и BOC (минимум, нужный для одного сообщения) ----------

class Cell:
    def __init__(self, bits='', refs=()):
        assert len(bits) <= 1023 and len(refs) <= 4
        self.bits = bits  # строка из '0'/'1'
        self.refs = list(refs)

    def data_bytes(self):
        b = self.bits
        if len(b) % 8:
            b += '1' + '0' * (7 - len(b) % 8)  # тег завершения
        return int(b, 2).to_bytes(len(b) // 8, 'big') if b else b''

    def descriptors(self):
        n = len(self.bits)
        return bytes([len(self.refs), n // 8 + (n + 7) // 8])

    def depth(self):
        return 0 if not self.refs else 1 + max(r.depth() for r in self.refs)

    def hash(self):
        repr_ = self.descriptors() + self.data_bytes()
        repr_ += b''.join(r.depth().to_bytes(2, 'big') for r in self.refs)
        repr_ += b''.join(r.hash() for r in self.refs)
        return hashlib.sha256(repr_).digest()


def uint(value, n):
    return format(value, f'0{n}b') if n else ''


def raw_bits(data):
    return ''.join(format(b, '08b') for b in data)


def crc32c(data):
    crc = 0xFFFFFFFF
    for b in data:
        crc ^= b
        for _ in range(8):
            crc = (crc >> 1) ^ (0x82F63B78 if crc & 1 else 0)
    return crc ^ 0xFFFFFFFF


def to_boc(root):
    order, index = [], {}

    def visit(c):
        h = c.hash()
        if h in index:
            return
        index[h] = len(order)
        order.append(c)
        for r in c.refs:
            visit(r)

    visit(root)
    # родитель всегда раньше потомков (обход в глубину с корня), индексы ссылок > индекса родителя
    size = 1
    serialized = []
    for c in order:
        s = c.descriptors() + c.data_bytes() + b''.join(
            index[r.hash()].to_bytes(size, 'big') for r in c.refs)
        serialized.append(s)
    for c in order:
        for r in c.refs:
            assert index[r.hash()] > index[c.hash()]
    body = b''.join(serialized)
    off = max(1, (len(body).bit_length() + 7) // 8)
    out = bytes.fromhex('b5ee9c72') + bytes([0x40 | size, off])
    out += len(order).to_bytes(size, 'big') + (1).to_bytes(size, 'big') + (0).to_bytes(size, 'big')
    out += len(body).to_bytes(off, 'big') + (0).to_bytes(size, 'big') + body
    return out + crc32c(out).to_bytes(4, 'little')


def trampoline_code():
    # BOC из одной ячейки: заголовок 11 байт, затем d1 d2 и данные
    d1, d2 = TRAMPOLINE_BOC[11], TRAMPOLINE_BOC[12]
    assert d1 == 0
    data = TRAMPOLINE_BOC[13:13 + (d2 + 1) // 2]
    bits = raw_bits(data)
    if d2 % 2:  # неполный байт: срезаем тег завершения
        bits = bits.rstrip('0')[:-1]
    return Cell(bits)


# ---------- Адрес ----------

def state_init(pubkey):
    data = Cell(uint(0, 8) + uint(0, 32) + uint(SUBWALLET_ID, 32) + raw_bits(pubkey))
    return Cell('00110', [trampoline_code(), data])


# Быстрый путь для перебора: те же байты representation, что у Cell.hash()
_DATA_PREFIX = bytes([0, 82]) + b'\x00' * 5 + SUBWALLET_ID.to_bytes(4, 'big')
_INIT_PREFIX = bytes([2, 1, 0x34]) + b'\x00' * 4 + TRAMPOLINE_CODE_HASH


def address_hash_fast(pubkey):
    data_hash = hashlib.sha256(_DATA_PREFIX + pubkey).digest()
    return hashlib.sha256(_INIT_PREFIX + data_hash).digest()


def friendly(addr_hash, bounceable=False):
    raw = bytes([0x11 if bounceable else 0x51, 0]) + addr_hash
    raw += binascii.crc_hqx(raw, 0).to_bytes(2, 'big')
    n = int.from_bytes(raw, 'big')
    return ''.join(B64URL[(n >> (6 * (47 - i))) & 63] for i in range(48))


# ---------- Поиск ----------

def suffix_target(suffix):
    """Окончание из 4 символов -> 3 байта: последний байт хеша + crc16."""
    if len(suffix) != 4 or any(ch not in B64URL for ch in suffix):
        sys.exit('Нужно ровно 4 символа из A-Z a-z 0-9 - _')
    n = 0
    for ch in suffix:
        n = (n << 6) | B64URL.index(ch)
    return n.to_bytes(3, 'big')


def worker(target, counter, found, stop):
    last_byte, crc_target = target[0], int.from_bytes(target[1:], 'big')
    prefix = bytes([0x51, 0])
    local = 0
    while not stop.is_set():
        entropy = os.urandom(16)
        words = entropy_to_words(entropy)
        priv = slip10_ed25519(words_to_seed(words))
        h = address_hash_fast(public_key(priv))
        local += 1
        if local == 200:
            with counter.get_lock():
                counter.value += local
            local = 0
        if h[31] != last_byte:
            continue
        if binascii.crc_hqx(prefix + h, 0) == crc_target:
            found.put(words)
            return


def cmd_search(suffix):
    target = suffix_target(suffix)
    procs_n = os.cpu_count() or 4
    counter = mp.Value('q', 0)
    found = mp.Queue()
    stop = mp.Event()
    procs = [mp.Process(target=worker, args=(target, counter, found, stop), daemon=True)
             for _ in range(procs_n)]
    for p in procs:
        p.start()
    expected = 64 ** len(suffix)
    print(f'Ищу UQ...{suffix} на {procs_n} процессах, в среднем нужно ~{expected:,} попыток')
    t0 = time.time()
    try:
        while True:
            try:
                anchor = found.get(timeout=5)
                break
            except Exception:
                n, dt = counter.value, time.time() - t0
                rate = n / dt if dt else 0
                print(f'\r  {n:,} попыток, {rate:,.0f}/с, прошло {dt / 60:.1f} мин   ',
                      end='', flush=True)
    finally:
        stop.set()
        for p in procs:
            p.join(timeout=10)
            if p.is_alive():
                p.terminate()
    print()

    # перепроверка находки полным (медленным) путём через ячейки
    _, anchor_pub = words_to_keys(anchor)
    address = friendly(state_init(anchor_pub).hash())
    assert address.endswith(suffix), address

    signing = entropy_to_words(os.urandom(16))
    all24 = anchor + signing
    print(f'\nНАЙДЕН: {address}')
    print('\n'.join(f'{i + 1:2}. {w}' for i, w in enumerate(all24)))
    print(f'\nСлова: {" ".join(all24)}')
    print('\nСид-фраза НИГДЕ не сохранена. Перепишите 24 слова на бумагу прямо сейчас:\n'
          'после закрытия окна их не восстановить.')
    print(f'\nОтправьте 0.1 GRAM на {address}')
    while True:
        ans = input('Когда отправите, нажмите Enter (q - выйти без активации): ').strip().lower()
        if ans == 'q':
            print('Активацию можно сделать позже: python vanity.py activate')
            return
        if activate(all24):
            return


# ---------- Активация ----------

def toncenter(path, body=None):
    req = urllib.request.Request(
        TONCENTER + path,
        data=json.dumps(body).encode() if body is not None else None,
        headers={'Content-Type': 'application/json'})
    for attempt in range(6):
        try:
            with urllib.request.urlopen(req, timeout=30) as r:
                res = json.load(r)
            break
        except urllib.error.HTTPError as e:
            if e.code == 429 and attempt < 5:
                time.sleep(1.5 * (attempt + 1))
                continue
            res = json.load(e)
            break
    if not res.get('ok'):
        raise RuntimeError(f'toncenter: {res.get("error")}')
    return res['result']


def get_method_int(address, method):
    r = toncenter('/runGetMethod', {'address': address, 'method': method, 'stack': []})
    if r['exit_code'] != 0:
        raise RuntimeError(f'{method}: exit code {r["exit_code"]}')
    return int(r['stack'][0][1], 16)


def build_change_key(anchor_pub, signer_priv, new_priv, new_pub, seqno, deploy, valid_until):
    """anchor_pub задаёт адрес (слова 1-12), signer_priv — текущий ключ кошелька."""
    init = state_init(anchor_pub)
    addr_hash = init.hash()

    proof = Cell(uint(KEY_ROTATION_TAG, 96) + uint(0, 8) + raw_bits(addr_hash))
    rotation_sig = sign(new_priv, proof.hash())

    request = Cell(
        uint(OP_CHANGE_KEY_E, 32) + uint(SUBWALLET_ID, 32) + uint(valid_until, 32)
        + uint(seqno, 32) + raw_bits(new_pub),
        [Cell(raw_bits(rotation_sig)),
         Cell(raw_bits(bytes(32)))])  # encryptedOldPrivateKey: контракт лишь логирует его
    signature = sign(signer_priv, request.hash())
    body = Cell(raw_bits(signature) + request.bits, request.refs)

    # ext_in_msg_info$10 src:addr_none dest:addr_std import_fee:0
    bits = '10' + '00' + '100' + uint(0, 8) + raw_bits(addr_hash) + '0000'
    refs = []
    if deploy:
        bits += '11'  # Maybe(Either StateInit ^StateInit): есть, ссылкой
        refs.append(init)
    else:
        bits += '0'
    bits += '1'  # body ссылкой
    refs.append(body)
    return to_boc(Cell(bits, refs)), addr_hash


def input_words():
    """Ввод 24 слов вручную: на диск ничего не пишется."""
    while True:
        words = input('Вставьте 24 слова через пробел: ').lower().split()
        if len(words) != 24:
            print(f'Нужно 24 слова, а введено {len(words)}.')
        elif not (validate_words(words[:12]) and validate_words(words[12:])):
            print('Слова введены с ошибкой (неверная чек-сумма BIP39). Проверьте и повторите.')
        else:
            return words


def activate(words):
    """Деплой + смена ключа на слова 13-24. True, если кошелёк готов к импорту."""
    anchor_priv, anchor_pub = words_to_keys(words[:12])
    new_priv, new_pub = words_to_keys(words[12:])
    address = friendly(state_init(anchor_pub).hash())
    print(f'Адрес: {address}')

    info = toncenter(f'/getAddressInformation?address={address}')
    balance, state = int(info['balance']), info['state']
    print(f'Состояние: {state}, баланс: {balance / 1e9} GRAM')

    if state == 'active':
        current = get_method_int(address, 'get_public_key').to_bytes(32, 'big')
        if current == new_pub:
            print('Ключ уже сменён на слова 13-24. Можно импортировать 24 слова в Wallet.')
            return True
        if current != anchor_pub:
            print('На кошельке стоит другой ключ (возможно, вы уже сменили фразу в Wallet).')
            return True
        seqno, deploy = get_method_int(address, 'seqno'), False
    else:
        if balance < 20_000_000:
            print('Баланс меньше 0.02 GRAM: перевод ещё не дошёл. Подождите минуту.')
            return False
        seqno, deploy = 0, True

    boc, _ = build_change_key(anchor_pub, anchor_priv, new_priv, new_pub, seqno, deploy,
                              int(time.time()) + 180)
    if send_and_wait(address, boc, new_pub):
        print('Готово: ключ кошелька = слова 13-24.')
        print('Импортируйте все 24 слова в Gram Wallet.')
        return True
    print('Подтверждения пока нет. Проверьте адрес в эксплорере и повторите.')
    return False


def cmd_activate():
    words = input_words()
    while not activate(words):
        if input('Enter - повторить, q - выйти: ').strip().lower() == 'q':
            return


def send_and_wait(address, boc, new_pub):
    import base64
    toncenter('/sendBoc', {'boc': base64.b64encode(boc).decode()})
    print('Транзакция отправлена, жду подтверждения...')
    for _ in range(30):
        time.sleep(5)
        try:
            if get_method_int(address, 'get_public_key').to_bytes(32, 'big') == new_pub:
                return True
        except RuntimeError:
            pass
    return False


def cmd_rotate():
    """Смена рабочего ключа (слова 13-24) на новые 12 слов. Адрес не меняется."""
    words = input_words()
    _, anchor_pub = words_to_keys(words[:12])
    cur_priv, cur_pub = words_to_keys(words[12:])
    address = friendly(state_init(anchor_pub).hash())
    print(f'Адрес: {address}')

    info = toncenter(f'/getAddressInformation?address={address}')
    if info['state'] != 'active':
        sys.exit('Кошелёк не активирован. Сначала выполните activate.')
    if int(info['balance']) < 5_000_000:
        sys.exit('Баланс меньше 0.005 GRAM: не хватит на комиссию.')
    if get_method_int(address, 'get_public_key').to_bytes(32, 'big') != cur_pub:
        sys.exit('Слова 13-24 в файле не совпадают с текущим ключом кошелька.')
    seqno = get_method_int(address, 'seqno')

    new_words = entropy_to_words(os.urandom(16))
    new_priv, new_pub = words_to_keys(new_words)
    all24 = words[:12] + new_words
    # новая фраза показывается ДО отправки: после смены ключа старая перестанет работать
    print('\nНОВАЯ фраза (на диск не сохраняется):')
    print('\n'.join(f'{i + 1:2}. {w}' for i, w in enumerate(all24)))
    if input('\nПереписали новые 24 слова на бумагу? Введите "да": ').strip().lower() != 'да':
        print('Отменено, ключ не менялся. Старая фраза работает.')
        return

    boc, _ = build_change_key(anchor_pub, cur_priv, new_priv, new_pub, seqno, False,
                              int(time.time()) + 180)
    if send_and_wait(address, boc, new_pub):
        print('\nГотово: ключ сменён, старая фраза больше не работает.')
        print('Выйдите из кошелька в Gram Wallet и импортируйте его заново по новой фразе.')
    else:
        print('Подтверждения пока нет. Сохраните ОБЕ фразы, пока не проверите адрес\n'
              'в эксплорере: одна из них точно рабочая.')


# ---------- Самопроверка ----------

def cmd_selftest():
    # BIP39 (официальный вектор, пароль TREZOR)
    w = entropy_to_words(bytes(16))
    assert ' '.join(w) == 'abandon ' * 11 + 'about'
    assert words_to_seed(w, 'TREZOR').hex() == (
        'c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d182'
        '64c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04')
    w = entropy_to_words(bytes.fromhex('7f' * 16))
    assert ' '.join(w) == 'legal winner thank year wave sausage worth useful legal winner thank yellow'
    # SLIP-10 ed25519, test vector 1, m/0'
    assert slip10_ed25519(bytes.fromhex('000102030405060708090a0b0c0d0e0f'), (0,)).hex() == \
        '68e0fe46dfb67e368c75379acec591dad19df3cde26e63b93a8e704f1dade7a3'
    # Хеш кода трамплина
    assert trampoline_code().hash() == TRAMPOLINE_CODE_HASH
    # Быстрый путь адреса == полный путь через ячейки
    for _ in range(20):
        pub = public_key(os.urandom(32))
        assert address_hash_fast(pub) == state_init(pub).hash()
    print('selftest OK')


if __name__ == '__main__':
    if len(sys.argv) >= 2 and sys.argv[1] == 'selftest':
        cmd_selftest()
    elif len(sys.argv) == 3 and sys.argv[1] == 'search':
        cmd_search(sys.argv[2])
    elif len(sys.argv) == 2 and sys.argv[1] == 'activate':
        cmd_activate()
    elif len(sys.argv) == 2 and sys.argv[1] == 'rotate':
        cmd_rotate()
    else:
        print(__doc__)
