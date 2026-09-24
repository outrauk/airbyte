#
# Copyright (c) 2023 Airbyte, Inc., all rights reserved.
#
"""
Extends the CDK's stdlib-backed CSV parser to support `S3CsvFormat.pad_missing_columns`.

`airbyte-cdk` is not vendored in this repo (external pip dependency, pinned to an exact version in
pyproject.toml precisely because of this file — see the comment there). Two of `_CsvReader`'s /
`CsvParser`'s methods have no seam to override just the bit we need, so `S3CsvReader.read_data` and
`S3CsvParser._cast_types` (+ their respective call chains) below are copies of the upstream methods
(airbyte_cdk.sources.file_based.file_types.csv_parser), each modified in exactly one place:

1. `S3CsvReader.read_data`: in the "row has fewer fields than the header" branch, when
   `S3CsvFormat.pad_missing_columns` is enabled, that branch is bypassed entirely instead of being
   subject to `ignore_errors_on_fields_mismatch` — the row is emitted with the None-padding
   `_row_to_dict` (inherited, unmodified) already produces for the missing trailing fields, rather
   than being dropped/failed. The "row has MORE fields than the header" branch (`None in row`, i.e.
   `row[None] = values[len(headers):]`) is untouched and continues to be governed solely by
   `ignore_errors_on_fields_mismatch`, exactly as upstream, in both directions.

2. `S3CsvParser._cast_types` (reached via `parse_records` -> `_get_cast_function`, both of which
   hardcode a `CsvParser.<method>` reference rather than going through `self`/`type(self)`, so they
   must be overridden too purely to route to our `_cast_types`): a `None` value -- which can now
   reach this method only via pad_missing_columns, since a real CSV cell is always at least an empty
   string "" -- is passed through as `None` immediately, instead of falling into e.g.
   `int(None)`/`float(None)` for a non-string schema column, which raise an uncaught `TypeError`
   (the surrounding try/except only catches `ValueError`). This crash was hit in production against
   the real "Barbour ABI Planning" feed: nearly every row pads at least one `integer`-typed
   `Role_id_N`/`Cyno_N` field, so every row crashed the read before any record was emitted.

If a future `airbyte-cdk` bump changes either upstream method's shape, these overrides need to be
resynced by hand; `unit_tests/v4/test_csv_parser.py`'s anti-drift tests guard against silent drift
on the `pad_missing_columns=False` / non-`None` paths by diffing against the real, installed
`_CsvReader`/`CsvParser`.
"""

import csv
import json
import logging
from functools import partial
from typing import Any, Callable, Dict, Generator, Iterable, Mapping, Optional
from uuid import uuid4

import orjson

from airbyte_cdk.sources.file_based.config.csv_format import CsvFormat
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
    _format_warning,
    _no_cast,
    _value_to_bool,
    _value_to_list,
    _value_to_python_type,
)
from airbyte_cdk.sources.file_based.remote_file import RemoteFile
from airbyte_cdk.sources.file_based.schema_helpers import TYPE_PYTHON_MAPPING, SchemaType
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
    `S3CsvFormat.pad_missing_columns` is honored, and with a None-safe `_cast_types` so padded
    `None` values don't crash on non-string schema columns. See module docstring for details."""

    def __init__(self, csv_field_max_bytes: int = 2**31) -> None:
        super().__init__(csv_reader=S3CsvReader(), csv_field_max_bytes=csv_field_max_bytes)

    def parse_records(
        self,
        config: FileBasedStreamConfig,
        file: RemoteFile,
        stream_reader: AbstractFileBasedStreamReader,
        logger: logging.Logger,
        discovered_schema: Optional[Mapping[str, SchemaType]],
    ) -> Iterable[Dict[str, Any]]:
        # Copy of CsvParser.parse_records, changed only to route through S3CsvParser._get_cast_function
        # instead of the hardcoded CsvParser._get_cast_function.
        data_generator = None
        try:
            config_format = _extract_format(config)
            if discovered_schema:
                property_types = {col: prop["type"] for col, prop in discovered_schema["properties"].items()}
                deduped_property_types = CsvParser._pre_propcess_property_types(property_types)
            else:
                deduped_property_types = {}
            cast_fn = S3CsvParser._get_cast_function(deduped_property_types, config_format, logger, config.schemaless)
            data_generator = self._csv_reader.read_data(config, file, stream_reader, logger, self.file_read_mode)
            for row in data_generator:
                yield CsvParser._to_nullable(
                    cast_fn(row),
                    deduped_property_types,
                    config_format.null_values,
                    config_format.strings_can_be_null,
                )
        finally:
            if data_generator is not None:
                data_generator.close()

    @staticmethod
    def _get_cast_function(
        deduped_property_types: Mapping[str, str],
        config_format: CsvFormat,
        logger: logging.Logger,
        schemaless: bool,
    ) -> Callable[[Mapping[str, str]], Mapping[str, str]]:
        # Copy of CsvParser._get_cast_function, changed only to bind S3CsvParser._cast_types instead
        # of the hardcoded CsvParser._cast_types.
        if deduped_property_types and not schemaless:
            return partial(
                S3CsvParser._cast_types,
                deduped_property_types=deduped_property_types,
                config_format=config_format,
                logger=logger,
            )
        else:
            # If no schema is provided, yield the rows as they are
            return _no_cast

    @staticmethod
    def _cast_types(
        row: Dict[str, Any],
        deduped_property_types: Mapping[str, str],
        config_format: CsvFormat,
        logger: logging.Logger,
    ) -> Dict[str, Any]:
        """
        Copy of CsvParser._cast_types, changed only to short-circuit on `value is None` before any
        type-specific casting is attempted. `None` can only appear here via pad_missing_columns
        (real CSV cells are always at least an empty string ""), and upstream has no handling for it:
        `int(None)`/`float(None)` raise an uncaught `TypeError` for any non-string schema column
        (the surrounding try/except only catches `ValueError`), and `str(None)` silently produces the
        3-character string "None" instead of a null. Treating `None` as already-cast avoids both.
        """
        warnings = []
        result = {}

        for key, value in row.items():
            if value is None:
                result[key] = None
                continue

            prop_type = deduped_property_types.get(key)
            cast_value: Any = value

            if prop_type in TYPE_PYTHON_MAPPING and prop_type is not None:
                _, python_type = TYPE_PYTHON_MAPPING[prop_type]

                if python_type is None:
                    if value == "":
                        cast_value = None
                    else:
                        warnings.append(_format_warning(key, value, prop_type))

                elif python_type is bool:
                    try:
                        cast_value = _value_to_bool(value, config_format.true_values, config_format.false_values)
                    except ValueError:
                        warnings.append(_format_warning(key, value, prop_type))

                elif python_type is dict:
                    try:
                        # we don't re-use _value_to_object here because we type the column as object as long as there is only one object
                        cast_value = orjson.loads(value)
                    except orjson.JSONDecodeError:
                        warnings.append(_format_warning(key, value, prop_type))

                elif python_type is list:
                    try:
                        cast_value = _value_to_list(value)
                    except (ValueError, json.JSONDecodeError):
                        warnings.append(_format_warning(key, value, prop_type))

                elif python_type:
                    try:
                        cast_value = _value_to_python_type(value, python_type)
                    except ValueError:
                        warnings.append(_format_warning(key, value, prop_type))

                result[key] = cast_value

        if warnings:
            logger.warning(
                f"{FileBasedSourceError.ERROR_CASTING_VALUE.value}: {','.join([w for w in warnings])}",
            )
        return result
