package uk.gov.nationalarchives.notifications

import com.github.tomakehurst.wiremock.client.WireMock._
import io.circe.generic.auto._
import io.circe.parser
import org.scalatest.prop.{TableDrivenPropertyChecks, TableFor8}
import software.amazon.awssdk.services.sqs.model.Message
import uk.gov.nationalarchives.notifications.decoders.ExportStatusDecoder.ExportSuccessDetails
import uk.gov.nationalarchives.notifications.messages.EventMessages.SqsExportMessageBody

trait LambdaIntegrationSpec extends LambdaSpecUtils with TableDrivenPropertyChecks {
  def events: TableFor8[String, String, Option[String], Option[String], Option[SqsExpectedMessageDetails], Option[SnsExpectedMessageDetails], () => Unit, String]

  forAll(events) {
    (description, input, emailBody, slackBody, sqsMessage, snsMessage, stubContext, slackUrl) => {
      emailBody match {
        case Some(body) =>
          "the process method" should s"send an email message for $description" in {
            stubContext()
            val stream = new java.io.ByteArrayInputStream(input.getBytes(java.nio.charset.StandardCharsets.UTF_8.name))
            new Lambda().process(stream, null)
            wiremockSesEndpoint.verify(1,
              postRequestedFor(urlEqualTo("/"))
                .withRequestBody(equalTo(body))
            )
          }
        case None =>
          "the process method" should s"not send an email message for $description" in {
            stubContext()
            val stream = new java.io.ByteArrayInputStream(input.getBytes(java.nio.charset.StandardCharsets.UTF_8.name))
            new Lambda().process(stream, null)
            wiremockSesEndpoint.verify(0, postRequestedFor(urlEqualTo("/")))
          }
      }

      slackBody match {
        case Some(body) =>
          "the process method" should s"send a slack message for $description" in {
            stubContext()
            val stream = new java.io.ByteArrayInputStream(input.getBytes(java.nio.charset.StandardCharsets.UTF_8.name))
            new Lambda().process(stream, null)
            wiremockSlackServer.verify(slackBody.size,
              postRequestedFor(urlEqualTo(slackUrl))
                .withRequestBody(equalToJson(body))
            )
          }
        case None =>
          "the process method" should s"not send a slack message for $description" in {
            stubContext()
            val stream = new java.io.ByteArrayInputStream(input.getBytes(java.nio.charset.StandardCharsets.UTF_8.name))
            new Lambda().process(stream, null)
            wiremockSlackServer.verify(0,
              postRequestedFor(urlEqualTo(slackUrl))
            )
          }
      }

      sqsMessage match {
        case Some(expectedMessageDetails) =>
          "the process method" should s"send a sqs message for $description" in {
            stubContext()
            val stream = new java.io.ByteArrayInputStream(input.getBytes(java.nio.charset.StandardCharsets.UTF_8.name))
            new Lambda().process(stream, null)
            val messages: List[Message] = transformEngineQueueHelper.receive

            messages.size shouldBe 1
            val messageBody = messages.head.body()
            val message = parser.decode[SqsExportMessageBody](messageBody) match {
              case Right(value) => value
            }

            val expectedSuccessDetails = expectedMessageDetails.successDetails
            val expectedConsignmentRef = expectedSuccessDetails.consignmentReference
            val expectedBucket = expectedSuccessDetails.exportBucket
            val expectedSignedUrl = s"https://$expectedBucket.s3.eu-west-2.amazonaws.com/$expectedConsignmentRef.tar.gz?X-Amz-Security-Token"
            val expectedShaSignedUrl = s"https://$expectedBucket.s3.eu-west-2.amazonaws.com/$expectedConsignmentRef.tar.gz.sha256?X-Amz-Security-Token"

            message.`consignment-reference` shouldEqual expectedConsignmentRef
            message.`number-of-retries` shouldBe expectedMessageDetails.retryCount
            message.`s3-bagit-url`.startsWith(expectedSignedUrl) shouldBe true
            message.`s3-sha-url`.startsWith(expectedShaSignedUrl) shouldBe true
          }
        case None =>
          "the process method" should s"not send a sqs message for $description" in {
            stubContext()
            val stream = new java.io.ByteArrayInputStream(input.getBytes(java.nio.charset.StandardCharsets.UTF_8.name))
            new Lambda().process(stream, null)
            val messages: List[Message] = transformEngineQueueHelper.receive

            messages.size shouldBe 0
          }
      }

      snsMessage match {
        case Some(expectedDetails) =>
          "the process method" should s"send an sns message for $description" in {
            stubContext()
            val fieldValueSeparator: String = "%22%3A%22"
            val stream = new java.io.ByteArrayInputStream(input.getBytes(java.nio.charset.StandardCharsets.UTF_8.name))
            new Lambda().process(stream, null)
            wiremockSnsEndpoint.verify(1,
              postRequestedFor(urlEqualTo("/"))
                .withRequestBody(containing("properties"))
                .withRequestBody(containing(s"messageType${fieldValueSeparator}uk.gov.nationalarchives.da.messages.bag.available.BagAvailable"))
                .withRequestBody(containing("timestamp"))
                .withRequestBody(containing("function" + fieldValueSeparator + "tdr-export-process"))
                .withRequestBody(containing(s"producer${fieldValueSeparator}TDR"))
                .withRequestBody(containing("executionId"))
                .withRequestBody(containing("parentExecutionId"))
                .withRequestBody(containing("parameters"))
                .withRequestBody(containing(s"reference${fieldValueSeparator}${expectedDetails.consignmentReference}"))
                .withRequestBody(containing(s"originator${fieldValueSeparator}TDR"))
                .withRequestBody(containing(s"consignmentType"))
                .withRequestBody(containing(s"Bucket${fieldValueSeparator}${expectedDetails.bucketName}"))
                .withRequestBody(containing(s"s3BagKey${fieldValueSeparator}${expectedDetails.consignmentReference}.tar.gz"))
                .withRequestBody(containing(s"s3BagSha256Key${fieldValueSeparator}${expectedDetails.consignmentReference}.tar.gz.sha256"))
            )
          }
        case None =>
          "the process method" should s"not send a sns message for $description" in {
            stubContext()
            val stream = new java.io.ByteArrayInputStream(input.getBytes(java.nio.charset.StandardCharsets.UTF_8.name))
            new Lambda().process(stream, null)
            wiremockSnsEndpoint.verify(0, postRequestedFor(urlEqualTo("/")))
          }
      }
    }
  }
}

case class SqsExpectedMessageDetails(successDetails: ExportSuccessDetails, retryCount: Int)

case class SnsExpectedMessageDetails(consignmentReference: String,
                                     consignmentType: String,
                                     bucketName: String,
                                     environment: String)
