import ctypes


def secure_wipe_bytearray(data: bytearray) -> None:
    """Обнуляет буфер bytearray на месте (через реальный адрес буфера, а не id()+смещение).

    Ограничения: затирается только этот буфер. Копии (str/bytes, кэши аллокатора, swap)
    из чистого Python не достать - для настоящих гарантий нужны libsodium (sodium_memzero)
    или защита уровня TEE/гипервизора.
    """
    if not isinstance(data, bytearray):
        raise TypeError("Только bytearray может быть безопасно затерт")
    if not data:
        return
    buf = (ctypes.c_char * len(data)).from_buffer(data)
    try:
        ctypes.memset(buf, 0, len(data))
    finally:
        del buf  # освободить экспорт буфера
