package uk.gov.nationalarchives.notifications

import org.scalatest.prop.TableFor8
import uk.gov.nationalarchives.notifications.decoders.ExportStatusDecoder.{ExportStatusEvent, ExportSuccessDetails}

import java.util.UUID

class ExportIntegrationSpec extends LambdaIntegrationSpec {

  override lazy val events: TableFor8[String, String, Option[String], Option[String], Option[SqsExpectedMessageDetails], Option[SnsExpectedMessageDetails], () => Unit, String] = Table(
    ("description", "input", "emailBody", "slackBody", "sqsMessage", "snsMessage", "stubContext", "slackUrl"),
    ("a successful standard export event on intg",
      exportStatusEventInputText(exportStatus1), None, None, None, expectedSnsMessage(exportStatus1), () => (), "/webhook-export"),
    ("a successful standard export event using a mock transferring body on intg",
      exportStatusEventInputText(exportStatus2), None, None, None, None, () => (), "/webhook-export"),
    ("a successful judgment export event on intg",
      exportStatusEventInputText(exportStatus3), None, None, None, expectedSnsMessage(exportStatus3), () => (), "/webhook-export"),
    ("a successful judgment export event using a mock transferring body on intg",
      exportStatusEventInputText(exportStatus4), None, None, None, None, () => (), "/webhook-export"),
    ("a failed export event on intg",
      exportStatusEventInputText(exportStatus5), None, Some(expectedSlackMessage(exportStatus5)), None, None, () => (), "/webhook-export"),
    ("a successful standard export event on staging",
      exportStatusEventInputText(exportStatus6), None, Some(expectedSlackMessage(exportStatus6)), None, expectedSnsMessage(exportStatus6), () => (), "/webhook-export"),
    ("a successful standard export event using a mock transferring body on staging",
      exportStatusEventInputText(exportStatus8), None, Some(expectedSlackMessage(exportStatus8)), None, None, () => (), "/webhook-export"),
    ("a successful judgment export event on staging",
      exportStatusEventInputText(exportStatus7), None, Some(expectedSlackMessage(exportStatus7)), None, expectedSnsMessage(exportStatus6), () => (), "/webhook-export"),
    ("a successful judgment export event using a mock transferring body on staging",
      exportStatusEventInputText(exportStatus8), None, Some(expectedSlackMessage(exportStatus8)), None, None, () => (), "/webhook-export"),
    ("a failed export event on staging",
      exportStatusEventInputText(exportStatus9), None, Some(expectedSlackMessage(exportStatus9)), None, None, () => (), "/webhook-export"),
    ("a failed export on intg with no error details",
      exportStatusEventInputText(exportStatus10), None, Some(expectedSlackMessage(exportStatus10)), None, None, () => (), "/webhook-export"),
    ("a failed export on staging with no error details",
      exportStatusEventInputText(exportStatus11), None, Some(expectedSlackMessage(exportStatus11)), None, None, () => (), "/webhook-export"),
    ("a successful standard export event on prod",
      exportStatusEventInputText(exportStatus12), None, Some(expectedSlackMessage(exportStatus12)), None, expectedSnsMessage(exportStatus12), () => (), "/webhook-export"),
    ("a failed standard export event on prod",
      exportStatusEventInputText(exportStatus13), None, Some(expectedSlackMessage(exportStatus13)), None, None, () => (), "/webhook-export"),
    ("a successful standard export event using a mock transferring body on prod",
      exportStatusEventInputText(exportStatus8), None, Some(expectedSlackMessage(exportStatus8)), None, None, () => (), "/webhook-export"),
    ("a successful judgment export on prod",
    exportStatusEventInputText(exportStatus14), None, Some(expectedSlackMessage(exportStatus14)), None, expectedSnsMessage(exportStatus14), () => (), "/webhook-judgment")
  )

  private lazy val successDetailsStandard = ExportSuccessDetails(UUID.randomUUID(), "consignmentRef1", "tb-body1", "standard", "export-bucket")
  private lazy val successDetailsStandardMockBody = ExportSuccessDetails(UUID.randomUUID(), "consignmentRef1", "Mock 1 Department", "standard", "export-bucket")
  private lazy val successDetailsJudgment = ExportSuccessDetails(UUID.randomUUID(), "consignmentRef1", "tb-body1", "judgment", "export-bucket")
  private lazy val successDetailsJudgmentMockBody = ExportSuccessDetails(UUID.randomUUID(), "consignmentRef1", "Mock 1 Department", "judgment", "export-bucket")
  private lazy val causeOfFailure = "Cause of failure"
  private lazy val exportStatus1 = ExportStatusEvent(UUID.randomUUID(), success = true, environment = "intg", successDetails = Some(successDetailsStandard), failureCause = None)
  private lazy val exportStatus2 = ExportStatusEvent(UUID.randomUUID(), success = true, environment = "intg", successDetails = Some(successDetailsStandardMockBody), failureCause = None)
  private lazy val exportStatus3 = ExportStatusEvent(UUID.randomUUID(), success = true, "intg", Some(successDetailsJudgment), None)
  private lazy val exportStatus4 = ExportStatusEvent(UUID.randomUUID(), success = true, "intg", Some(successDetailsJudgmentMockBody), None)
  private lazy val exportStatus5 = ExportStatusEvent(UUID.randomUUID(), success = false, "intg", None, Some(causeOfFailure))
  private lazy val exportStatus6 = ExportStatusEvent(UUID.randomUUID(), success = true, "staging", Some(successDetailsStandard), None)
  private lazy val exportStatus7 = ExportStatusEvent(UUID.randomUUID(), success = true, "staging", Some(successDetailsJudgment), None)
  private lazy val exportStatus8 = ExportStatusEvent(UUID.randomUUID(), success = true, "staging", Some(successDetailsStandardMockBody), None)
  private lazy val exportStatus9 = ExportStatusEvent(UUID.randomUUID(), success = false, "staging", None, Some(causeOfFailure))
  private lazy val exportStatus10 = ExportStatusEvent(UUID.randomUUID(), success = false, "intg", None, None)
  private lazy val exportStatus11 = ExportStatusEvent(UUID.randomUUID(), success = false, "staging", None, None)
  private lazy val exportStatus12 = ExportStatusEvent(UUID.randomUUID(), success = true, "prod", Some(successDetailsStandard), None)
  private lazy val exportStatus13 = ExportStatusEvent(UUID.randomUUID(), success = false, "prod", None, Some(causeOfFailure))
  private lazy val exportStatus14 = ExportStatusEvent(UUID.randomUUID(), success = true, "prod", Some(successDetailsJudgment), None)

  private def exportStatusEventInputText(exportStatusEvent: ExportStatusEvent): String = {
    val successDetails = exportStatusEvent.successDetails
    val failureCause = exportStatusEvent.failureCause
    val exportOutputJson = if(successDetails.isDefined) {
      val sd = successDetails.get
      s""", \\"successDetails\\":{\\"userId\\": \\"${sd.userId}\\",\\"consignmentReference\\": \\"${sd.consignmentReference}\\",\\"transferringBodyName\\": \\"${sd.transferringBodyName}\\", \\"consignmentType\\": \\"${sd.consignmentType}\\", \\"exportBucket\\": \\"${sd.exportBucket}\\"}"""
    } else if(failureCause.isDefined) s""", \\"failureCause\\":\\"${failureCause.get}\\" """ else """"""

    s"""
       |{
       |    "Records": [
       |        {
       |            "Sns": {
       |                "Message": "{\\"success\\":${exportStatusEvent.success},\\"consignmentId\\":\\"${exportStatusEvent.consignmentId}\\", \\"environment\\": \\"${exportStatusEvent.environment}\\"$exportOutputJson}"
       |            }
       |        }
       |    ]
       |}
       |
       |""".stripMargin
  }

  private def expectedSlackMessage(exportStatusEvent: ExportStatusEvent): String = {
    val successDetails = exportStatusEvent.successDetails
    val failureCause = exportStatusEvent.failureCause
    val exportOutputMessage = if(successDetails.isDefined) {
      s"""\\n*User ID:* ${successDetails.get.userId}\\n*Consignment Reference:* ${successDetails.get.consignmentReference}\\n*Transferring Body Name:* ${successDetails.get.transferringBodyName}"""
    } else if(failureCause.isDefined) s"""\\n*Cause:* ${failureCause.get}""" else """"""

    if (exportStatusEvent.success) {
      s"""{
         |  "blocks" : [ {
         |    "type" : "section",
         |    "text" : {
         |      "type" : "mrkdwn",
         |      "text" : ":white_check_mark: Export *success* on *${exportStatusEvent.environment}!* \\n*Consignment ID:* ${exportStatusEvent.consignmentId}$exportOutputMessage"
         |    }
         |  } ]
         |}""".stripMargin
    } else {
      s"""{
         |  "blocks" : [ {
         |    "type" : "section",
         |    "text" : {
         |      "type" : "mrkdwn",
         |      "text" : ":x: Export *failure* on *${exportStatusEvent.environment}!* \\n*Consignment ID:* ${exportStatusEvent.consignmentId}$exportOutputMessage"
         |    }
         |  } ]
         |}""".stripMargin
    }
  }

  private def expectedSnsMessage(exportStatusEvent: ExportStatusEvent): Option[SnsExpectedMessageDetails] = {
    if (exportStatusEvent.success && exportStatusEvent.successDetails.isDefined) {
      val successDetails = exportStatusEvent.successDetails.get
      val consignmentRef: String = successDetails.consignmentReference
      val consignmentType: String = successDetails.consignmentType
      val bucket: String = successDetails.exportBucket
      val environment: String = exportStatusEvent.environment

      Some(SnsExpectedMessageDetails(consignmentRef, consignmentType, bucket, environment))

    } else None
  }
}
