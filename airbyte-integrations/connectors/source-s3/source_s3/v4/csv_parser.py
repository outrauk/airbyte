#
# Copyright (c) 2023 Airbyte, Inc., all rights reserved.
#
"""
Extends the CDK's stdlib-backed CSV parser to support `S3CsvFormat.pad_missing_columns`.

`airbyte-cdk` is not vendored in this repo (external pip dependency, pinned to an exact version in
pyproject.toml precisely because of this file — see the comment there). `_CsvReader.read_data` has
no seam to override just one branch of its mismatch-handling logic, so `S3CsvReader.read_data`
below is a copy of the upstream method (airbyte_cdk.sources.file_based.file_types.csv_parser),
modified ONLY in the "row has fewer fields than the header" branch: when
`S3CsvFormat.pad_missing_columns` is enabled, that branch is bypassed entirely instead of being
subject to `ignore_errors_on_fields_mismatch` — the row is emitted with the None-padding
`_row_to_dict` (inherited, unmodified) already produces for the missing trailing fields, rather
than being dropped/failed.

The "row has MORE fields than the header" branch (`None in row`, i.e.
`row[None] = values[len(headers):]`) is untouched and continues to be governed solely by
`ignore_errors_on_fields_mismatch`, exactly as upstream, in both directions.

If a future `airbyte-cdk` bump changes `_CsvReader.read_data`'s shape, this override needs to be
resynced by hand; `unit_tests/v4/test_csv_parser.py`'s anti-drift test guards against silent
drift for the `pad_missing_columns=False` path by diffing against the real, installed `_CsvReader`.
"""

import csv
import logging
from typing import Any, Dict, Generator
from uuid import uuid4

from airbyte_cdk.sources.file_based.config.file_based_stream_config import FileBasedStreamConfig
from airbyte_cdk.sources.file_based.exceptions import FileBasedSourceError, RecordParseError
from airbyte_cdk.sources.file_based.file_based_stream_reader import (
    AbstractFileBasedStreamReader,
    FileReadMode,
)
from airbyte_cdk.sources.file_based.file_types.csv_parser import (
    DIALECT_NAME,
    CsvParser,
    _CsvReader,
    _extract_format,
)
from airbyte_cdk.sources.file_based.remote_file import RemoteFile
from airbyte_cdk.utils.traced_exception import AirbyteTracedException


class S3CsvReader(_CsvReader):
    def read_data(
        self,
        config: FileBasedStreamConfig,
        file: RemoteFile,
        stream_reader: AbstractFileBasedStreamReader,
        logger: logging.Logger,
        file_read_mode: FileReadMode,
    ) -> Generator[Dict[str, Any], None, None]:
        config_format = _extract_format(config)
        pad_missing_columns = getattr(config_format, "pad_missing_columns", False)
        lineno = 0

        # Formats are configured individually per-stream so a unique dialect should be registered for each stream.
        # We don't unregister the dialect because we are lazily parsing each csv file to generate records
        # Give each stream's dialect a unique name; otherwise, when we are doing a concurrent sync we can end up
        # with a race condition where a thread attempts to use a dialect before a separate thread has finished
        # registering it.
        dialect_name = f"{config.name}_{str(uuid4())}_{DIALECT_NAME}"
        csv.register_dialect(
            dialect_name,
            delimiter=config_format.delimiter,
            quotechar=config_format.quote_char,
            escapechar=config_format.escape_char,
            doublequote=config_format.double_quote,
            quoting=csv.QUOTE_MINIMAL,
        )
        try:
            with stream_reader.open_file(file, file_read_mode, config_format.encoding, logger) as fp:
                try:
                    headers, raw_headers = self._read_and_validate_headers(fp, config_format, dialect_name)
                except UnicodeError:
                    raise AirbyteTracedException(
                        message=f"{FileBasedSourceError.ENCODING_ERROR.value} Expected encoding: {config_format.encoding}",
                    )

                rows_to_skip = (
                    config_format.skip_rows_before_header
                    + (1 if config_format.header_definition.has_header_row() else 0)
                    + config_format.skip_rows_after_header
                )
                self._skip_rows(fp, rows_to_skip)
                lineno += rows_to_skip

                reader = csv.reader(fp, dialect=dialect_name)  # type: ignore
                trailing_empty_header_count = self._get_trailing_empty_header_count(raw_headers)
                for values in reader:
                    lineno += 1
                    if not values:
                        continue

                    values = self._strip_trailing_empty_header_values(
                        values,
                        headers,
                        trailing_empty_header_count,
                        file.uri,
                        lineno,
                    )
                    row = self._row_to_dict(headers, values)

                    # More fields than headers: unaffected by pad_missing_columns, unchanged from upstream.
                    if None in row:
                        if config_format.ignore_errors_on_fields_mismatch:
                            logger.error(
                                f"Skipping record in line {lineno} of file {file.uri}; invalid CSV row with missing column."
                            )
                        else:
                            raise RecordParseError(
                                FileBasedSourceError.ERROR_PARSING_RECORD_MISMATCHED_COLUMNS,
                                filename=file.uri,
                                lineno=lineno,
                            )

                    # Fewer fields than headers: pad_missing_columns bypasses this check entirely and
                    # emits the row with the None-padding _row_to_dict already computed, regardless of
                    # ignore_errors_on_fields_mismatch.
                    if None in row.values() and not pad_missing_columns:
                        if config_format.ignore_errors_on_fields_mismatch:
                            logger.error(
                                f"Skipping record in line {lineno} of file {file.uri}; invalid CSV row with extra column."
                            )
                        else:
                            raise RecordParseError(
                                FileBasedSourceError.ERROR_PARSING_RECORD_MISMATCHED_ROWS,
                                filename=file.uri,
                                lineno=lineno,
                            )
                    yield row
        finally:
            csv.unregister_dialect(dialect_name)


class S3CsvParser(CsvParser):
    """CsvParser wired to use S3CsvReader instead of the CDK's stdlib `_CsvReader`, so that
    `S3CsvFormat.pad_missing_columns` is honored."""

    def __init__(self, csv_field_max_bytes: int = 2**31) -> None:
        super().__init__(csv_reader=S3CsvReader(), csv_field_max_bytes=csv_field_max_bytes)
