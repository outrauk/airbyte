#
# Copyright (c) 2023 Airbyte, Inc., all rights reserved.
#

from typing import Any, Dict, List, Optional, Union

import dpath.util
from pydantic.v1 import AnyUrl, Field, root_validator
from pydantic.v1.error_wrappers import ValidationError

from airbyte_cdk import is_cloud_environment
from airbyte_cdk.sources.file_based.config.abstract_file_based_spec import AbstractFileBasedSpec, DeliverRawFiles, DeliverRecords
from airbyte_cdk.sources.file_based.config.avro_format import AvroFormat
from airbyte_cdk.sources.file_based.config.excel_format import ExcelFormat
from airbyte_cdk.sources.file_based.config.file_based_stream_config import FileBasedStreamConfig
from airbyte_cdk.sources.file_based.config.jsonl_format import JsonlFormat
from airbyte_cdk.sources.file_based.config.parquet_format import ParquetFormat
from airbyte_cdk.sources.file_based.config.unstructured_format import UnstructuredFormat

from source_s3.v4.csv_format import S3CsvFormat


class S3FileBasedStreamConfig(FileBasedStreamConfig):
    """S3-specific stream config that adds a flag to skip the full parse check for Parquet files."""
    password: Optional[str] = Field(
        title="Zip Password",
        description=(
            "Password to decrypt password-protected ZIP archives matched by this stream's globs. "
            "Overrides the source-level Zip Password for this stream only. Leave blank to fall back "
            "to the source-level password, or if this stream's files aren't encrypted."
        ),
        default=None,
        airbyte_secret=True,
    )
    skip_full_check_for_parquet: bool = Field(
        title="Skip Full Check for Parquet",
        description=(
            "When enabled, the CHECK operation for Parquet streams will verify file accessibility "
            "but skip the full record-parse step. This avoids out-of-memory errors on large Parquet files."
        ),
        default=False,
    )
    # Overrides the parent's `format` field only to swap CsvFormat for S3CsvFormat (adds
    # `pad_missing_columns`); title/description/order are unchanged from FileBasedStreamConfig.
    format: Union[AvroFormat, S3CsvFormat, JsonlFormat, ParquetFormat, UnstructuredFormat, ExcelFormat] = Field(
        title="Format",
        description="The configuration options that are used to alter how to read incoming files that deviate from the standard formatting.",
    )

    @root_validator
    def validate_pad_missing_columns_requires_schema(cls, values: Dict[str, Any]) -> Dict[str, Any]:
        """
        `pad_missing_columns` makes short rows the common case for a stream, which can otherwise
        crash automatic schema inference on the resulting padded `null` values (see
        plan-pad-missing-columns.md). Require an explicit schema up front instead, at config-parse
        time -- enforced for CHECK, DISCOVER, and READ alike, since all three parse the config
        through `Config(**config)` before doing anything else.
        """
        fmt = values.get("format")
        if isinstance(fmt, S3CsvFormat) and fmt.pad_missing_columns and not values.get("input_schema"):
            raise ValidationError(
                "`pad_missing_columns` requires an explicit `input_schema` to be configured for this "
                "stream, since automatic schema inference cannot safely handle padded null values.",
                model=S3FileBasedStreamConfig,
            )
        return values


class Config(AbstractFileBasedSpec):
    """
    NOTE: When this Spec is changed, legacy_config_transformer.py must also be modified to uptake the changes
    because it is responsible for converting legacy S3 v3 configs into v4 configs using the File-Based CDK.
    """

    @classmethod
    def documentation_url(cls) -> AnyUrl:
        return AnyUrl("https://docs.airbyte.com/integrations/sources/s3", scheme="https")

    bucket: str = Field(title="Bucket", description="Name of the S3 bucket where the file(s) exist.", order=0)

    # Use the extended stream config type but keep parent field metadata via schema patching.
    streams: List[S3FileBasedStreamConfig]

    aws_access_key_id: Optional[str] = Field(
        title="AWS Access Key ID",
        default=None,
        description="In order to access private Buckets stored on AWS S3, this connector requires credentials with the proper "
        "permissions. If accessing publicly available data, this field is not necessary.",
        airbyte_secret=True,
        order=2,
    )

    role_arn: Optional[str] = Field(
        title=f"AWS Role ARN",
        default=None,
        description="Specifies the Amazon Resource Name (ARN) of an IAM role that you want to use to perform operations "
        f"requested using this profile. Set the External ID to the Airbyte workspace ID, which can be found in the URL of this page.",
        order=6,
    )

    aws_secret_access_key: Optional[str] = Field(
        title="AWS Secret Access Key",
        default=None,
        description="In order to access private Buckets stored on AWS S3, this connector requires credentials with the proper "
        "permissions. If accessing publicly available data, this field is not necessary.",
        airbyte_secret=True,
        order=3,
    )

    endpoint: Optional[str] = Field(
        default="",
        title="Endpoint",
        description="Endpoint to an S3 compatible service. Leave empty to use AWS.",
        examples=["my-s3-endpoint.com", "https://my-s3-endpoint.com"],
        order=4,
    )

    region_name: Optional[str] = Field(
        title="AWS Region",
        default=None,
        description="AWS region where the S3 bucket is located. If not provided, the region will be determined automatically.",
        order=5,
    )

    password: Optional[str] = Field(
        title="Zip Password",
        default=None,
        description="Password to decrypt password-protected ZIP archives encountered during the sync. Only traditional "
        "'ZipCrypto' passwords are currently supported; AES-encrypted zip files are not yet supported.",
        airbyte_secret=True,
        order=7,
    )

    requester_pays: bool = Field(
        title="Requester Pays",
        default=False,
        description=(
            "Whether the S3 bucket has Requester Pays enabled. If true, all list and read "
            "requests will include the AWS Requester Pays flag, and your AWS account will be "
            "billed for the associated request and data transfer costs."
        ),
        order=8,
    )

    delivery_method: DeliverRecords | DeliverRawFiles = Field(
        title="Delivery Method",
        discriminator="delivery_type",
        type="object",
        order=6,
        display_type="radio",
        group="advanced",
        default="use_records_transfer",
    )

    @root_validator
    def validate_optional_args(cls, values):
        aws_access_key_id = values.get("aws_access_key_id")
        aws_secret_access_key = values.get("aws_secret_access_key")
        if (aws_access_key_id or aws_secret_access_key) and not (aws_access_key_id and aws_secret_access_key):
            raise ValidationError(
                "`aws_access_key_id` and `aws_secret_access_key` are both required to authenticate with AWS.", model=Config
            )

        if is_cloud_environment():
            endpoint = values.get("endpoint")
            if endpoint:
                if endpoint.startswith("http://"):  # ignore-https-check
                    raise ValidationError("The endpoint must be a secure HTTPS endpoint.", model=Config)

        return values

    @classmethod
    def schema(cls, *args: Any, **kwargs: Any) -> Dict[str, Any]:
        """
        Generates the mapping comprised of the config fields
        """
        schema = super().schema(*args, **kwargs)

        # Keep parent streams metadata to avoid drift, then inject the S3-specific flag.
        parent_schema = AbstractFileBasedSpec.schema()
        schema["properties"]["streams"] = parent_schema["properties"]["streams"]

        s3_stream_schema = S3FileBasedStreamConfig.schema(*args, **kwargs)
        skip_prop = s3_stream_schema["properties"]["skip_full_check_for_parquet"]
        stream_item_props = schema["properties"]["streams"]["items"]["properties"]
        stream_item_props["skip_full_check_for_parquet"] = skip_prop
        stream_item_props["password"] = s3_stream_schema["properties"]["password"]

        # The plain CsvFormat used to build `parent_schema` above doesn't know about
        # `pad_missing_columns` (an S3-specific extension of CsvFormat, see csv_format.py), so
        # inject its schema into the CSV format's oneOf entry, alongside `ignore_errors_on_fields_mismatch`.
        csv_format_schema = next(
            fmt for fmt in stream_item_props["format"]["oneOf"] if fmt["properties"]["filetype"]["default"] == "csv"
        )
        csv_format_schema["properties"]["pad_missing_columns"] = S3CsvFormat.schema(*args, **kwargs)["properties"]["pad_missing_columns"]

        # Hide API processing option until https://github.com/airbytehq/airbyte-platform-internal/issues/10354 is fixed
        processing_options = dpath.util.get(schema, "properties/streams/items/properties/format/oneOf/4/properties/processing/oneOf")
        dpath.util.set(schema, "properties/streams/items/properties/format/oneOf/4/properties/processing/oneOf", processing_options[:1])

        return schema
