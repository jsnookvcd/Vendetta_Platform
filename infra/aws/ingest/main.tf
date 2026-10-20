# Event pipeline: everything lands on one Kinesis stream; Firehose copies the
# stream to the raw archive (lake account) partitioned by tenant and source;
# ingest-stream reads the same stream for streaming Sigma detection; ingest-worker
# writes normalized OCSF into Security Lake through the custom source roles.

resource "aws_kms_key" "ingest" {
  description             = "vcd-soc ingest stream, queues and logs"
  enable_key_rotation     = true
  deletion_window_in_days = 30
}

resource "aws_kms_alias" "ingest" {
  name          = "alias/vcd-soc-ingest"
  target_key_id = aws_kms_key.ingest.key_id
}

resource "aws_kinesis_stream" "events" {
  name             = "vcd-soc-events"
  retention_period = var.kinesis_retention_hours
  encryption_type  = "KMS"
  kms_key_id       = aws_kms_key.ingest.arn

  stream_mode_details {
    stream_mode = "ON_DEMAND"
  }
}

# ------------------------------------------------------------------ Firehose
data "aws_iam_policy_document" "firehose_trust" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["firehose.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [data.aws_caller_identity.current.account_id]
    }
  }
}

# Name is fixed: the lake stack's raw bucket and key policies allow it by ARN.
resource "aws_iam_role" "firehose" {
  name               = "vcd-soc-ingest-firehose"
  assume_role_policy = data.aws_iam_policy_document.firehose_trust.json
}

resource "aws_cloudwatch_log_group" "firehose" {
  name              = "/vcd-soc/firehose/raw-archive"
  retention_in_days = var.log_retention_days
}

data "aws_iam_policy_document" "firehose" {
  statement {
    sid = "ReadStream"
    actions = [
      "kinesis:DescribeStream", "kinesis:DescribeStreamSummary", "kinesis:GetRecords",
      "kinesis:GetShardIterator", "kinesis:ListShards",
    ]
    resources = [aws_kinesis_stream.events.arn]
  }
  statement {
    sid       = "StreamKey"
    actions   = ["kms:Decrypt"]
    resources = [aws_kms_key.ingest.arn]
  }
  statement {
    sid       = "WriteRawArchive"
    actions   = ["s3:AbortMultipartUpload", "s3:PutObject"]
    resources = ["${var.raw_bucket_arn}/*"]
  }
  statement {
    sid       = "RawArchiveBucket"
    actions   = ["s3:GetBucketLocation", "s3:ListBucket", "s3:ListBucketMultipartUploads"]
    resources = [var.raw_bucket_arn]
  }
  statement {
    sid       = "RawArchiveKey"
    actions   = ["kms:GenerateDataKey", "kms:Encrypt", "kms:Decrypt"]
    resources = [var.raw_kms_key_arn]
  }
  statement {
    sid       = "Logs"
    actions   = ["logs:PutLogEvents", "logs:CreateLogStream"]
    resources = ["${aws_cloudwatch_log_group.firehose.arn}:*"]
  }
}

resource "aws_iam_role_policy" "firehose" {
  name   = "raw-archive"
  role   = aws_iam_role.firehose.id
  policy = data.aws_iam_policy_document.firehose.json
}

resource "aws_kinesis_firehose_delivery_stream" "raw" {
  name        = "vcd-soc-raw-archive"
  destination = "extended_s3"

  kinesis_source_configuration {
    kinesis_stream_arn = aws_kinesis_stream.events.arn
    role_arn           = aws_iam_role.firehose.arn
  }

  extended_s3_configuration {
    role_arn            = aws_iam_role.firehose.arn
    bucket_arn          = var.raw_bucket_arn
    kms_key_arn         = var.raw_kms_key_arn
    buffering_size      = var.firehose_buffer_mb
    buffering_interval  = var.firehose_buffer_seconds
    compression_format  = "GZIP"
    prefix              = "tenant=!{partitionKeyFromQuery:tenant}/source=!{partitionKeyFromQuery:source}/!{timestamp:yyyy/MM/dd}/"
    error_output_prefix = "errors/!{firehose:error-output-type}/!{timestamp:yyyy/MM/dd}/"

    dynamic_partitioning_configuration {
      enabled        = true
      retry_duration = 300
    }

    processing_configuration {
      enabled = true

      processors {
        type = "MetadataExtraction"
        parameters {
          parameter_name  = "MetadataExtractionQuery"
          parameter_value = "{tenant:.tenant_id,source:.source}"
        }
        parameters {
          parameter_name  = "JsonParsingEngine"
          parameter_value = "JQ-1.6"
        }
      }

      processors {
        type = "AppendDelimiterToRecord"
        parameters {
          parameter_name  = "Delimiter"
          parameter_value = "\\n"
        }
      }
    }

    cloudwatch_logging_options {
      enabled         = true
      log_group_name  = aws_cloudwatch_log_group.firehose.name
      log_stream_name = "delivery"
    }
  }

  depends_on = [aws_iam_role_policy.firehose]
}

# ------------------------------------------------------------------ bucket feeds
# S3 object notifications from vendor or client buckets (CloudTrail exports,
# FDR-style feeds) queue here; ingest-worker reads the queue and fetches the
# object with the tenant's cross-account role. SQS-managed SSE keeps S3 and SNS
# able to deliver without a KMS key grant.
resource "aws_sqs_queue" "bucket_feed_dlq" {
  name                      = "vcd-soc-ingest-bucket-feed-dlq"
  message_retention_seconds = 1209600
  sqs_managed_sse_enabled   = true
}

resource "aws_sqs_queue" "bucket_feed" {
  name                       = "vcd-soc-ingest-bucket-feed"
  visibility_timeout_seconds = 900
  message_retention_seconds  = 345600
  sqs_managed_sse_enabled    = true

  redrive_policy = jsonencode({
    deadLetterTargetArn = aws_sqs_queue.bucket_feed_dlq.arn
    maxReceiveCount     = 5
  })
}

resource "aws_sqs_queue_redrive_allow_policy" "bucket_feed_dlq" {
  queue_url = aws_sqs_queue.bucket_feed_dlq.id
  redrive_allow_policy = jsonencode({
    redrivePermission = "byQueue"
    sourceQueueArns   = [aws_sqs_queue.bucket_feed.arn]
  })
}

data "aws_iam_policy_document" "bucket_feed" {
  statement {
    sid       = "DenyInsecureTransport"
    effect    = "Deny"
    actions   = ["sqs:*"]
    resources = [aws_sqs_queue.bucket_feed.arn]
    principals {
      type        = "*"
      identifiers = ["*"]
    }
    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }

  dynamic "statement" {
    for_each = length(var.bucket_feed_source_arns) > 0 ? [1] : []
    content {
      sid       = "FeedNotifications"
      actions   = ["sqs:SendMessage"]
      resources = [aws_sqs_queue.bucket_feed.arn]
      principals {
        type        = "Service"
        identifiers = ["s3.amazonaws.com", "sns.amazonaws.com"]
      }
      condition {
        test     = "ArnLike"
        variable = "aws:SourceArn"
        values   = var.bucket_feed_source_arns
      }
    }
  }
}

resource "aws_sqs_queue_policy" "bucket_feed" {
  queue_url = aws_sqs_queue.bucket_feed.id
  policy    = data.aws_iam_policy_document.bucket_feed.json
}

# ------------------------------------------------------------------ stream checkpoints
resource "aws_dynamodb_table" "stream_checkpoints" {
  name         = "vcd-soc-ingest-stream-checkpoints"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "leaseKey"

  attribute {
    name = "leaseKey"
    type = "S"
  }

  point_in_time_recovery {
    enabled = true
  }

  server_side_encryption {
    enabled     = true
    kms_key_arn = aws_kms_key.ingest.arn
  }

  deletion_protection_enabled = true
}
