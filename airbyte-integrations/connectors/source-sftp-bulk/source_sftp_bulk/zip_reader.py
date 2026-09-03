import struct
import zipfile
from typing import List, Optional, Tuple

from airbyte_cdk.sources.file_based.remote_file import RemoteFile

class SFTPRemoteFileInsideArchive(RemoteFile):
    """A file inside a zip archive on an SFTP server."""

    start_offset: int
    compressed_size: int
    uncompressed_size: int
    compression_method: int
    flag_bits: int = 0
    crc: int = 0
    extra: bytes = b""

    @property
    def is_encrypted(self) -> bool:
        return bool(self.flag_bits & 0x1)


class SFTPZipFileHandler:
    """
    Reads a zip archive's central directory over an already-open SFTP file
    handle, using direct seeks rather than S3-style HTTP range requests -
    paramiko's SFTPFile supports arbitrary seek()/read() on the open
    connection, so no chunked signature-scanning is needed the way S3's
    ZipFileHandler does it.
    """

    EOCD_SIGNATURE = b"\x50\x4b\x05\x06"
    ZIP64_LOCATOR_SIGNATURE = b"\x50\x4b\x06\x07"
    EOCD_CENTRAL_DIR_START_OFFSET = 16
    ZIP64_EOCD_OFFSET = 8
    ZIP64_CENTRAL_DIR_START_OFFSET = 48
    EOCD_SEARCH_WINDOW = 64 * 1024  # zip comment is capped at 65535 bytes

    def __init__(self, sftp_file):
        self._file = sftp_file  # an open paramiko SFTPFile

    def _file_size(self) -> int:
        return self._file.stat().st_size

    def _find_eocd(self) -> bytes:
        size = self._file_size()
        window = min(self.EOCD_SEARCH_WINDOW, size)
        self._file.seek(size - window)
        tail = self._file.read(window)
        index = tail.rfind(self.EOCD_SIGNATURE)
        if index == -1:
            raise ValueError("Could not locate end-of-central-directory record in zip file.")
        return tail[index:]

    def _get_central_directory_start(self) -> int:
        eocd_data = self._find_eocd()
        central_dir_start = struct.unpack_from("<L", eocd_data, self.EOCD_CENTRAL_DIR_START_OFFSET)[0]
        if central_dir_start == 0xFFFFFFFF:
            # ZIP64: locate the zip64 EOCD locator immediately preceding the standard EOCD.
            self._file.seek(0)
            # Simplify by scanning the same tail window for the zip64 locator signature.
            size = self._file_size()
            window = min(self.EOCD_SEARCH_WINDOW, size)
            self._file.seek(size - window)
            tail = self._file.read(window)
            idx = tail.rfind(self.ZIP64_LOCATOR_SIGNATURE)
            if idx == -1:
                raise ValueError("zip64 marker found but locator record could not be located.")
            zip64_eocd_offset = struct.unpack_from("<Q", tail, idx + self.ZIP64_EOCD_OFFSET)[0]
            self._file.seek(zip64_eocd_offset)
            zip64_data = self._file.read(56)
            central_dir_start = struct.unpack_from("<Q", zip64_data, self.ZIP64_CENTRAL_DIR_START_OFFSET)[0]
        return central_dir_start

    def get_zip_files(self) -> Tuple[List[zipfile.ZipInfo], int]:
        central_dir_start = self._get_central_directory_start()
        self._file.seek(central_dir_start)
        central_dir_data = self._file.read(self._file_size() - central_dir_start)

        import io
        with io.BytesIO(central_dir_data) as bytes_io:
            with zipfile.ZipFile(bytes_io, "r") as zf:
                return zf.infolist(), central_dir_start


class DecompressedStream(io.IOBase):
    """
    A custom stream class that handles decompression of data from a given file object.
    This class supports seeking, reading, and other basic file operations on compressed data.
    """

    LOCAL_FILE_HEADER_SIZE: int = 30
    NAME_LENGTH_OFFSET: int = 26
    ZIP_CRYPTO_HEADER_SIZE: int = 12

    def __init__(
        self,
        file_obj: IO[bytes],
        file_info: RemoteFileInsideArchive,
        password: Optional[str] = None,
        buffer_size: int = BUFFER_SIZE_DEFAULT,
    ):
        """
        Initialize a DecompressedStream.

        :param file_obj: Underlying file-like object.
        :param file_info: Meta information about the file inside the archive.
        :param password: Password to decrypt `file_info`, if it is password-protected.
        :param buffer_size: Size of the buffer for reading data.
        """
        self._file = file_obj
        self.uncompressed_size = file_info.uncompressed_size
        self.compression_method = file_info.compression_method
        self._buffer = bytearray()
        self.buffer_size = buffer_size

        content_start = self._calculate_actual_start(file_info.start_offset)
        # Set by _init_*_decryption below: a zero-arg factory producing a fresh, correctly-primed
        # decrypter (None for unencrypted entries). Called once here and again on every seek(),
        # since a fresh decrypter is needed whenever the stream restarts from `self.file_start`.
        self._make_decrypter: Optional[Callable[[], Callable[[bytes], bytes]]] = None
        self.file_start, self.compressed_size = self._init_decryption(file_info, password, content_start)

        self._reset_decompressor()
        self.position = 0  # Current position in uncompressed stream
        self._file.seek(self.file_start)
        # Mapping between uncompressed and compressed offsets for quick seeking
        self.offset_map = {0: self.file_start, self.uncompressed_size: self.file_start + self.compressed_size}

    def _init_decryption(self, file_info: RemoteFileInsideArchive, password: Optional[str], content_start: int) -> Tuple[int, int]:
        """
        For password-protected entries, validate the password and set up `self._make_decrypter`.

        :return: The (file_start, compressed_size) of the actual compressed payload, i.e. `content_start`
                 and `file_info.compressed_size` shifted past whatever encryption overhead (header,
                 salt, etc.) precedes the real compressed data.
        """
        if not file_info.is_encrypted:
            return content_start, file_info.compressed_size

        if file_info.compression_method == WINZIP_AES_COMPRESSION_TYPE:
            return self._init_aes_decryption(file_info, password, content_start)
        return self._init_zip_crypto_decryption(file_info, password, content_start)

    def _init_zip_crypto_decryption(
        self, file_info: RemoteFileInsideArchive, password: Optional[str], content_start: int
    ) -> Tuple[int, int]:
        """Validate a traditional ZipCrypto password against its 12-byte encryption header."""
        if not password:
            raise ValueError(f"'{file_info.uri}' is password-protected, but no zip password was configured for this source.")

        password_bytes = password.encode("utf-8")
        self._file.seek(content_start)
        header = self._file.read(self.ZIP_CRYPTO_HEADER_SIZE)

        decrypted_header = zipfile._ZipDecrypter(password_bytes)(header)
        expected_check_byte = (file_info.crc >> 24) & 0xFF
        if decrypted_header[-1] != expected_check_byte:
            raise ValueError(f"Incorrect zip password for '{file_info.uri}'.")

        def make_decrypter():
            decrypter = zipfile._ZipDecrypter(password_bytes)
            # Advance its key state past the header, exactly as it did just above, even though we
            # don't need that (already-validated) decrypted output again here.
            decrypter(header)
            return decrypter

        self._make_decrypter = make_decrypter
        return content_start + self.ZIP_CRYPTO_HEADER_SIZE, file_info.compressed_size - self.ZIP_CRYPTO_HEADER_SIZE

    def _init_aes_decryption(self, file_info: RemoteFileInsideArchive, password: Optional[str], content_start: int) -> Tuple[int, int]:
        """Validate a WinZip AES password against its 2-byte password-verification value."""
        if not password:
            raise ValueError(f"'{file_info.uri}' is password-protected, but no zip password was configured for this source.")

        parsed_extra = _parse_winzip_aes_extra_field(file_info.extra)
        if parsed_extra is None:
            raise ValueError(f"'{file_info.uri}' is AES-encrypted, but its WinZip AES extra field could not be parsed.")
        strength, real_compression_method = parsed_extra
        if strength not in WINZIP_AES_STRENGTH_TO_SALT_AND_KEY_SIZE:
            raise ValueError(f"'{file_info.uri}' uses an unrecognized AES strength ({strength}).")
        salt_size, key_size = WINZIP_AES_STRENGTH_TO_SALT_AND_KEY_SIZE[strength]

        self._file.seek(content_start)
        salt = self._file.read(salt_size)
        password_verification = self._file.read(WINZIP_AES_PASSWORD_VERIFICATION_SIZE)

        derived = hashlib.pbkdf2_hmac(
            "sha1",
            password.encode("utf-8"),
            salt,
            WINZIP_AES_PBKDF2_ITERATIONS,
            dklen=2 * key_size + WINZIP_AES_PASSWORD_VERIFICATION_SIZE,
        )
        encryption_key, expected_verification = derived[:key_size], derived[2 * key_size :]
        if password_verification != expected_verification:
            raise ValueError(f"Incorrect zip password for '{file_info.uri}'.")

        # The central directory's compress_type is the WINZIP_AES_COMPRESSION_TYPE sentinel; swap
        # in the real one (parsed from the extra field above) so decompression works correctly.
        self.compression_method = real_compression_method
        self._make_decrypter = lambda: _AesCtrCipher(encryption_key)

        overhead = salt_size + WINZIP_AES_PASSWORD_VERIFICATION_SIZE + WINZIP_AES_AUTHENTICATION_CODE_SIZE
        payload_start = content_start + salt_size + WINZIP_AES_PASSWORD_VERIFICATION_SIZE
        return payload_start, file_info.compressed_size - overhead

    def _calculate_actual_start(self, file_start: int) -> int:
        """
        Determine the actual start position of the file content within the ZIP archive.

        In a ZIP archive, each file entry is preceded by a local file header. This header contains
        metadata about the file, including the lengths of the file's name and any extra data.
        To accurately locate the start of the actual file content, we need to skip over this header.

        This method calculates the start position by taking into account the length of the file name
        and any extra data present in the local file header.

        :param file_start: The starting position of the file entry (including its local file header)
                           inside the ZIP archive.
        :return: The actual starting position of the file content, after skipping the local file header.
        """
        self._file.seek(file_start + self.NAME_LENGTH_OFFSET)  # Navigate to the position where lengths of name and extra data are stored
        name_len, extra_len = struct.unpack("<HH", self._file.read(4))  # Extract the lengths
        return file_start + self.LOCAL_FILE_HEADER_SIZE + name_len + extra_len  # Calculate the actual start by skipping the header

    def _reset_decompressor(self):
        """
        Reset the decompressor and, for password-protected entries, the decrypter. Both are stateful
        and must restart from scratch whenever the stream restarts reading from `self.file_start`.
        """
        self.decompressor = zipfile._get_decompressor(self.compression_method)
        self._decrypter = self._make_decrypter() if self._make_decrypter else None

    def _decompress_chunk(self, chunk: bytes) -> bytes:
        """
        Decrypt (if applicable) and decompress a chunk of data based on the compression method.
        """
        if self._decrypter is not None:
            chunk = self._decrypter(chunk)
        if self.compression_method == zipfile.ZIP_STORED:
            return chunk
        return self.decompressor.decompress(chunk)

    def read(self, size: int = -1) -> bytes:
        """
        Read a specified number of bytes from the stream.
        """
        # Size not specified, read till end
        if size == -1:
            size = self.uncompressed_size - self.position

        # If buffer already has enough data, return it directly
        if size <= len(self._buffer):
            data = self._buffer[:size]
            self._buffer = self._buffer[size:]
            self.position += len(data)
            return data

        data = self._buffer
        self._buffer = bytearray()
        while len(data) < size and self._file.tell() - self.file_start < self.compressed_size:
            max_read_size = min(self.buffer_size, self.compressed_size + self.file_start - self._file.tell())
            chunk = self._file.read(max_read_size)

            if not chunk:
                break

            decompressed_data = self._decompress_chunk(chunk)

            # Buffer excessive data for future reads
            if len(data) + len(decompressed_data) > size:
                desired_length = size - len(data)
                data += decompressed_data[:desired_length]
                self._buffer = decompressed_data[desired_length:]
            else:
                data += decompressed_data

        self.position += len(data)
        return data

    def seek(self, offset: int, whence: int = io.SEEK_SET) -> int:
        """
        Seek to a specific position in the uncompressed stream.
        """
        if whence == io.SEEK_SET:
            self._buffer = bytearray()
        elif whence == io.SEEK_CUR:
            offset = self.position + offset
        elif whence == io.SEEK_END:
            offset = self.uncompressed_size + offset

        # Ensure the offset is within the file's boundaries
        offset = max(0, min(offset, self.uncompressed_size))

        closest_offset = max(k for k in self.offset_map if k <= offset)
        closest_position = self.offset_map[closest_offset]

        self._file.seek(closest_position)
        self._reset_decompressor()
        self.position = closest_offset

        # Read till desired offset
        while self.position < offset:
            read_size = min(self.buffer_size, offset - self.position)
            self.read(read_size)

        return self.position

    def tell(self) -> int:
        """
        Return the current position in the uncompressed stream.
        """
        return self.position

    def readable(self) -> bool:
        """
        Return if the stream is readable.
        """
        return True

    def seekable(self) -> bool:
        """
        Return if the stream is seekable.
        """
        return True

    def close(self):
        """
        Close the stream and underlying file object.
        """
        self._file.close()


class ZipContentReader:
    """
    A custom reader class that provides buffered reading capabilities on a decompressed stream.
    Supports reading lines, reading chunks, and iterating over the content.
    """

    def __init__(self, decompressed_stream: DecompressedStream, encoding: Optional[str] = None, buffer_size: int = BUFFER_SIZE_DEFAULT):
        """
        Initialize a ZipContentReader.

        :param decompressed_stream: A DecompressedStream object.
        :param encoding: Encoding to decode the bytes. If None, bytes are returned.
        :param buffer_size: Size of the buffer for reading data.
        """
        self.raw = decompressed_stream
        self.encoding = encoding
        self.buffer_size = buffer_size
        self.buffer = bytearray()
        self._closed = False

    def __iter__(self):
        """
        Make the class iterable.
        """
        return self

    def __next__(self) -> Union[str, bytes]:
        """
        Iterate over the lines in the reader.
        """
        line = self.readline()
        if not line:
            raise StopIteration
        return line

    def readline(self, limit: int = -1) -> Union[str, bytes]:
        """
        Read a single line (terminated by "\\n", "\\r\\n", or a lone "\\r") from the stream.

        Scans the raw buffer in bulk with `bytes.find()` rather than pulling and decoding one byte
        at a time - the previous approach cost a Python-level method call per byte of the entire
        decompressed file, which dominates runtime on multi-GB CSVs (this is what made zipped
        streams an order of magnitude slower than reading the same CSV unzipped).
        """
        if limit != -1:
            raise NotImplementedError("Limits other than -1 not implemented yet")

        while True:
            line_end = self._find_line_end()
            if line_end is not None:
                raw_line, self.buffer = bytes(self.buffer[:line_end]), self.buffer[line_end:]
                return raw_line.decode(self.encoding) if self.encoding else raw_line
            if not self._pull_more_into_buffer():
                raw_line, self.buffer = bytes(self.buffer), bytearray()
                return raw_line.decode(self.encoding) if self.encoding else raw_line

    def _find_line_end(self) -> Optional[int]:
        """
        Return the index just past the first complete line terminator in `self.buffer`, or None if
        no full terminator is present yet.

        A "\\r" sitting at the very end of the buffer is ambiguous - it might be a lone line ending,
        or the first half of a "\\r\\n" that was simply split across two underlying reads - so it's
        treated as "not found yet" until either more data arrives to disambiguate it or the stream
        reaches EOF (at which point `readline` finalizes on whatever's left, per the loop above).
        """
        newline_pos = self.buffer.find(b"\n")
        cr_pos = self.buffer.find(b"\r")
        if cr_pos != -1 and (newline_pos == -1 or cr_pos < newline_pos):
            if cr_pos + 1 == len(self.buffer):
                return None
            return cr_pos + 2 if self.buffer[cr_pos + 1] == 0x0A else cr_pos + 1
        return newline_pos + 1 if newline_pos != -1 else None

    def _pull_more_into_buffer(self) -> bool:
        """Read another chunk from the underlying stream into `self.buffer`. Returns False at EOF."""
        chunk = self.raw.read(self.buffer_size)
        if not chunk:
            return False
        self.buffer += chunk
        return True

    def read(self, size: int = -1) -> Union[str, bytes]:
        """
        Read a specified number of bytes/characters from the reader.
        """
        while len(self.buffer) < size:
            chunk = self.raw.read(self.buffer_size)
            if not chunk:
                break
            self.buffer += chunk

        data = self.buffer[:size]
        self.buffer = self.buffer[size:]

        try:
            return data.decode(self.encoding) if self.encoding else bytes(data)
        except UnicodeDecodeError:
            if self.encoding == "utf_8_sig":
                # utf_8_sig considers `\xef\xbb\xbf` as a single character and therefore calling `bytearray(b'\xef').decode("utf_8_sig") will
                # cause an exception to be raised.
                number_of_bytes_to_add = size - 1
                if data.endswith(bytearray(b"\xef")):
                    number_of_bytes_to_add += 2
                elif data.endswith(bytearray(b"\xbb")):
                    number_of_bytes_to_add += 1
                data = data + self.buffer[:number_of_bytes_to_add]
                self.buffer = self.buffer[number_of_bytes_to_add:]
                return data.decode(self.encoding) if self.encoding else bytes(data)
            raise

    def seek(self, offset: int, whence: int = io.SEEK_SET) -> int:
        """
        Seek to a specific position in the decompressed stream.
        """
        self.buffer = bytearray()
        return self.raw.seek(offset, whence)

    def close(self):
        """
        Close the reader and underlying decompressed stream.
        """
        self._closed = True
        self.raw.close()

    def tell(self) -> int:
        """
        Return the current position in the decompressed stream.
        """
        return self.raw.tell()

    @property
    def closed(self) -> bool:
        """
        Check if the reader is closed.
        """
        return self._closed

    def __enter__(self) -> "ZipContentReader":
        """Enter the runtime context for the reader."""
        return self

    def __exit__(self, exc_type, exc_value, traceback) -> None:
        """Exit the runtime context for the reader and ensure resources are closed."""
        self.close()
