#
# Copyright (c) 2023 Airbyte, Inc., all rights reserved.
#

from pydantic.v1 import Field

from airbyte_cdk.sources.file_based.config.csv_format import CsvFormat


class S3CsvFormat(CsvFormat):
    """
    S3-specific CSV format that adds `pad_missing_columns`, alongside the CDK's existing
    `ignore_errors_on_fields_mismatch`.

    See `source_s3/v4/csv_parser.py` for the reader that honors this flag.
    """

    pad_missing_columns: bool = Field(
        title="Pad Missing Columns",
        description=(
            "When enabled, a data row with fewer fields than the header is emitted with `null` in "
            "the missing trailing fields instead of being dropped (when `ignore_errors_on_fields_"
            "mismatch` is enabled) or failing the sync (when it isn't). Use this for CSVs where "
            "trailing columns are legitimately optional and rows may omit trailing commas instead of "
            "padding them. Rows with MORE fields than the header are unaffected and remain governed "
            "solely by `ignore_errors_on_fields_mismatch`. Requires an explicit schema to be "
            "configured for the stream, since automatic schema inference cannot safely handle "
            "padded null values."
        ),
        default=False,
    )
