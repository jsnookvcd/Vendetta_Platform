output "vpc_attachment_id" {
  description = "Add to the network stack spoke_attachments as segment = spoke."
  value       = module.vpc.transit_gateway_attachment_id
}

output "events_stream_arn" {
  value = aws_kinesis_stream.events.arn
}

output "firehose_arn" {
  value = aws_kinesis_firehose_delivery_stream.raw.arn
}

output "bucket_feed_queue_arn" {
  description = "Give to vendors and clients as the S3 notification target."
  value       = aws_sqs_queue.bucket_feed.arn
}

output "webhook_endpoint" {
  description = "Webhook base URL; vendors post to <endpoint>/api/ingest/<connector>/<tenant>."
  value       = aws_apigatewayv2_api.webhook.api_endpoint
}

output "syslog_nlb_dns_name" {
  description = "CNAME syslog.<base_domain> to this."
  value       = aws_lb.syslog.dns_name
}

output "worker_task_role_arn" {
  description = "Client VendettaSOCReader roles trust this ARN, with sts:ExternalId set to the tenant id."
  value       = module.ingest_worker.task_role_arn
}

output "pipeline_role_arns" {
  value = {
    firehose = aws_iam_role.firehose.arn
    worker   = module.ingest_worker.task_role_arn
    stream   = module.ingest_stream.task_role_arn
    web      = module.ingest_web.task_role_arn
    vector   = module.vector.task_role_arn
  }
}
