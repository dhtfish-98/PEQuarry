"""Finite local input and explicit output operations for static PE review.

These operations never execute the input. Limits bound bytes, not elapsed time.
The final path component must be a regular file and cannot be a symbolic link.
"""
import os as quarry_os
import stat as quarry_stat

quarry_INPUT_LIMIT = 256 * 1024 * 1024
quarry_MAPPED_LIMIT = 256 * 1024 * 1024
quarry_SIGNATURE_LIMIT = 8 * 1024 * 1024


class quarry_LimitError(ValueError):
    """The requested operation cannot be completed within its declared limit."""


def quarry_positive_limit(quarry_value, quarry_name):
    if type(quarry_value) is not int or quarry_value <= 0:
        raise ValueError(quarry_name + ' must be a positive integer')
    return quarry_value


def quarry_read_regular(quarry_filename, quarry_limit, *, quarry_allow_empty=False):
    quarry_positive_limit(quarry_limit, 'input limit')
    quarry_flags = quarry_os.O_RDONLY | getattr(quarry_os, 'O_NONBLOCK', 0)
    quarry_flags |= getattr(quarry_os, 'O_NOFOLLOW', 0) | getattr(quarry_os, 'O_CLOEXEC', 0)
    # lstat is also required on platforms that do not provide O_NOFOLLOW.
    quarry_before_path = quarry_os.lstat(quarry_filename)
    if not quarry_stat.S_ISREG(quarry_before_path.st_mode):
        raise ValueError('input must be a regular file, not a link or device')
    quarry_fd = quarry_os.open(quarry_filename, quarry_flags)
    try:
        quarry_before = quarry_os.fstat(quarry_fd)
        if not quarry_stat.S_ISREG(quarry_before.st_mode):
            raise ValueError('input must be a regular file')
        if (quarry_before.st_dev, quarry_before.st_ino) != (quarry_before_path.st_dev, quarry_before_path.st_ino):
            raise ValueError('input identity changed while opening')
        if quarry_before.st_size > quarry_limit:
            raise quarry_LimitError('input exceeds byte limit')
        if not quarry_allow_empty and quarry_before.st_size == 0:
            return b''
        quarry_parts = []
        quarry_count = 0
        while True:
            quarry_part = quarry_os.read(quarry_fd, min(1024 * 1024, quarry_limit - quarry_count + 1))
            if not quarry_part:
                break
            quarry_count += len(quarry_part)
            if quarry_count > quarry_limit:
                raise quarry_LimitError('input exceeds byte limit')
            quarry_parts.append(quarry_part)
        quarry_after = quarry_os.fstat(quarry_fd)
        quarry_identity = lambda quarry_record: (
            quarry_record.st_dev, quarry_record.st_ino, quarry_record.st_size,
            quarry_record.st_mtime_ns, quarry_record.st_ctime_ns,
        )
        if quarry_count != quarry_before.st_size or quarry_identity(quarry_before) != quarry_identity(quarry_after):
            raise ValueError('input changed while reading')
        return b''.join(quarry_parts)
    finally:
        quarry_os.close(quarry_fd)


def quarry_in_memory_bytes(quarry_data, quarry_limit):
    if not isinstance(quarry_data, (bytes, bytearray, memoryview)):
        raise TypeError('data must be bytes, bytearray or memoryview')
    quarry_size = quarry_data.nbytes if isinstance(quarry_data, memoryview) else len(quarry_data)
    if quarry_size > quarry_limit:
        raise quarry_LimitError('input exceeds byte limit')
    # Own a stable snapshot; caller mutations no longer change parsed input.
    return bytes(quarry_data)


def quarry_write_regular(quarry_filename, quarry_data):
    quarry_flags = quarry_os.O_WRONLY | getattr(quarry_os, 'O_NONBLOCK', 0)
    quarry_flags |= getattr(quarry_os, 'O_NOFOLLOW', 0) | getattr(quarry_os, 'O_CLOEXEC', 0)
    try:
        quarry_existing = quarry_os.lstat(quarry_filename)
    except FileNotFoundError:
        quarry_existing = None
    if quarry_existing is not None and not quarry_stat.S_ISREG(quarry_existing.st_mode):
        raise ValueError('output must be a regular file, not a link or device')
    if quarry_existing is None:
        quarry_flags |= quarry_os.O_CREAT | quarry_os.O_EXCL
    quarry_fd = quarry_os.open(quarry_filename, quarry_flags, 0o600)
    try:
        quarry_record = quarry_os.fstat(quarry_fd)
        if not quarry_stat.S_ISREG(quarry_record.st_mode):
            raise ValueError('output must be a regular file')
        if quarry_existing is not None and (quarry_record.st_dev, quarry_record.st_ino) != (quarry_existing.st_dev, quarry_existing.st_ino):
            raise ValueError('output identity changed while opening')
        quarry_os.ftruncate(quarry_fd, 0)
        quarry_position = 0
        quarry_view = memoryview(quarry_data)
        while quarry_position < len(quarry_view):
            quarry_written = quarry_os.write(quarry_fd, quarry_view[quarry_position:quarry_position + 1024 * 1024])
            if quarry_written <= 0:
                raise OSError('output write did not make progress')
            quarry_position += quarry_written
    finally:
        quarry_os.close(quarry_fd)
