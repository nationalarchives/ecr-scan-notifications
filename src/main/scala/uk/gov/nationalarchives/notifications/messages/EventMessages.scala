package uk.gov.nationalarchives.notifications.messages

import cats.effect.IO
import cats.syntax.all._
import com.typesafe.config.{Config, ConfigFactory}
import com.typesafe.scalalogging.Logger
import io.circe.Printer
import io.circe.generic.auto._
import io.circe.syntax.EncoderOps
import scalatags.Text.all._
import software.amazon.awssdk.services.ecr.model.FindingSeverity
import uk.gov.nationalarchives.aws.utils.ecr.ECRClients.ecr
import uk.gov.nationalarchives.aws.utils.ecr.ECRUtils
import uk.gov.nationalarchives.aws.utils.ses.SESUtils
import uk.gov.nationalarchives.aws.utils.ses.SESUtils.Email
import uk.gov.nationalarchives.common.messages.Producer.TDR
import uk.gov.nationalarchives.common.messages.Properties
import uk.gov.nationalarchives.da.messages.bag.available
import uk.gov.nationalarchives.da.messages.bag.available.{BagAvailable, ConsignmentType}
import uk.gov.nationalarchives.notifications.decoders.CloudwatchAlarmDecoder.CloudwatchAlarmEvent
import uk.gov.nationalarchives.notifications.decoders.DraftMetadataStepFunctionErrorDecoder.DraftMetadataStepFunctionError
import uk.gov.nationalarchives.notifications.decoders.ExportNotificationDecoder._
import uk.gov.nationalarchives.notifications.decoders.ExportStatusDecoder.ExportStatusEvent
import uk.gov.nationalarchives.notifications.decoders.GenericMessageDecoder.GenericMessagesEvent
import uk.gov.nationalarchives.notifications.decoders.KeycloakEventDecoder.KeycloakEvent
import uk.gov.nationalarchives.notifications.decoders.MalwareScanThreatFoundEventDecoder.MalwareScanThreatFoundEvent
import uk.gov.nationalarchives.notifications.decoders.MetadataReviewRequestDecoder.MetadataReviewRequestEvent
import uk.gov.nationalarchives.notifications.decoders.MetadataReviewSubmittedDecoder.MetadataReviewSubmittedEvent
import uk.gov.nationalarchives.notifications.decoders.ParameterStoreExpiryEventDecoder.ParameterStoreExpiryEvent
import uk.gov.nationalarchives.notifications.decoders.ScanDecoder.{ScanDetail, ScanEvent}
import uk.gov.nationalarchives.notifications.decoders.StepFunctionErrorDecoder.StepFunctionError
import uk.gov.nationalarchives.notifications.decoders.TransferCompleteEventDecoder.TransferCompleteEvent
import uk.gov.nationalarchives.notifications.messages.Messages.eventConfig

import java.net.URI
import java.sql.Timestamp
import java.time.Instant.now
import java.util.UUID
import scala.jdk.CollectionConverters.CollectionHasAsScala

object EventMessages {
  private val tarExtension: String = ".tar.gz"
  private val sh256256Extension: String = ".tar.gz.sha256"
  private val logger: Logger = Logger(this.getClass)
  val config: Config = ConfigFactory.load

  trait ExportMessage {
    val consignmentReference: String
    val consignmentType: String
  }

  case class SlackText(`type`: String, text: String)

  case class SlackBlock(`type`: String, text: SlackText)

  case class SlackMessage(blocks: List[SlackBlock])

  case class SnsMessageDetails(snsTopic: String, messageBody: String)

  case class GovUKEmailDetails(templateId: String, userEmail: String, personalisation: Map[String, String], reference: String)

  implicit val scanEventMessages: Messages[ScanEvent, ImageScanReport] = new Messages[ScanEvent, ImageScanReport] {

    // Tags that we are interested in because they are set on deployed images. We can ignore other tags (e.g. version
    // tags) because they represent old images or ones which have not been deployed yet.
    private val releaseTags = Set("latest", "intg", "staging", "prod", "mgmt")

    // Findings which should be included in slack alerts
    private val allFindingLevels = Set(
      FindingSeverity.CRITICAL,
      FindingSeverity.HIGH,
      FindingSeverity.MEDIUM,
      FindingSeverity.LOW,
      FindingSeverity.UNDEFINED
    )

    // Findings which should be included in email alerts
    private val highAndCriticalFindingLevels = Set(
      FindingSeverity.CRITICAL,
      FindingSeverity.HIGH
    )

    private val mutedVulnerabilities: Set[String] = eventConfig("alerts.ecr-scan.mute")
      .split(",")
      .toSet

    private val ecrScanDocumentationMessage: String = "See the TDR developer manual for guidance on fixing these vulnerabilities: " +
      "https://github.com/nationalarchives/tdr-dev-documentation/blob/master/manual/alerts/ecr-scans.md"

    private def slackBlock(text: String) = SlackBlock("section", SlackText("mrkdwn", text))

    private def includesReleaseTags(imageTags: List[String]): Boolean =
      imageTags.toSet.intersect(releaseTags).nonEmpty

    private def includesRelevantFindings(findings: Seq[Finding], findingLevels: Set[FindingSeverity]): Boolean = {
      findings.map(_.severity).toSet.intersect(findingLevels).nonEmpty
    }

    private def shouldSendSlackNotification(detail: ScanDetail, findings: Seq[Finding]): Boolean =
      includesReleaseTags(detail.tags) && includesRelevantFindings(findings, allFindingLevels)

    private def shouldSendEmailNotification(detail: ScanDetail, findings: Seq[Finding]): Boolean =
      includesReleaseTags(detail.tags) && includesRelevantFindings(findings, highAndCriticalFindingLevels)

    private def filterReport(report: ImageScanReport): ImageScanReport = {
      val filteredFindings = report.findings.filterNot(finding => mutedVulnerabilities.contains(finding.name))
      report.copy(findings = filteredFindings)
    }

    override def context(event: ScanEvent): IO[ImageScanReport] = {
      val repoName = event.detail.repositoryName
      val ecrClient = ecr(URI.create(ConfigFactory.load.getString("ecr.endpoint")))
      val ecrUtils: ECRUtils = ECRUtils(ecrClient)
      val findingsResponse = ecrUtils.imageScanFindings(repoName, event.detail.imageDigest)

      findingsResponse.map(response => {
        val findings = response.imageScanFindings.findings.asScala.map(finding => {
          Finding(finding.name, finding.severity)
        }).toSeq
        ImageScanReport(findings)
      })
    }

    override def slack(event: ScanEvent, report: ImageScanReport): Option[SlackMessage] = {
      val detail = event.detail
      val filteredReport = filterReport(report)
      if (shouldSendSlackNotification(detail, filteredReport.findings)) {
        val headerBlock = slackBlock(s"*ECR image scan complete on image ${detail.repositoryName} ${detail.tags.mkString(",")}*")

        val criticalBlock = slackBlock(s"${filteredReport.criticalCount} critical severity vulnerabilities")
        val highBlock = slackBlock(s"${filteredReport.highCount} high severity vulnerabilities")
        val mediumBlock = slackBlock(s"${filteredReport.mediumCount} medium severity vulnerabilities")
        val lowBlock = slackBlock(s"${filteredReport.lowCount} low severity vulnerabilities")
        val undefinedBlock = slackBlock(s"${filteredReport.undefinedCount} undefined severity vulnerabilities")
        val documentationBlock = slackBlock(ecrScanDocumentationMessage)
        SlackMessage(List(headerBlock, criticalBlock, highBlock, mediumBlock, lowBlock, undefinedBlock, documentationBlock)).some
      } else {
        Option.empty
      }
    }

    override def email(event: ScanEvent, report: ImageScanReport): Option[SESUtils.Email] = {
      val detail = event.detail
      val filteredReport = filterReport(report)
      if (shouldSendEmailNotification(detail, filteredReport.findings)) {
        val message = html(
          body(
            h1(s"Image scan results for ${detail.repositoryName}"),
            div(
              p(s"${filteredReport.criticalCount} critical vulnerabilities"),
              p(s"${filteredReport.highCount} high vulnerabilities"),
              p(s"${filteredReport.mediumCount} medium vulnerabilities"),
              p(s"${filteredReport.lowCount} low vulnerabilities"),
              p(s"${filteredReport.undefinedCount} undefined vulnerabilities")
            ),
            div(
              p(ecrScanDocumentationMessage)
            )
          )
        ).toString()
        Email("scanresults@tdr-management.nationalarchives.gov.uk", eventConfig("ses.email.to"), s"ECR scan results for ${detail.repositoryName}", message).some
      } else {
        Option.empty
      }
    }
  }

  implicit val exportStatusEventMessages: Messages[ExportStatusEvent, Unit] = new Messages[ExportStatusEvent, Unit] {
    //Exclude transfers from any 'Mock' body on Staging / Prod
    private def sendToDaEventBus(ev: ExportStatusEvent): Boolean = {
      if (ev.environment == "intg") {
        ev.success
      } else {
        ev.success && !ev.mockEvent
      }
    }

    override def context(event: ExportStatusEvent): IO[Unit] = IO.unit

    override def email(incomingEvent: ExportStatusEvent, context: Unit): Option[Email] = {
      logger.info(s"Skipping email for export complete message for consignment ${incomingEvent.consignmentId}")
      Option.empty
    }

    override def slack(incomingEvent: ExportStatusEvent, context: Unit): Option[SlackMessage] = {
      if (incomingEvent.environment != "intg" || !incomingEvent.success) {

        val exportInfoMessage = constructExportInfoMessage(incomingEvent)

        val message: String = if (incomingEvent.success) {
          s":white_check_mark: Export *success* on *${incomingEvent.environment}!* \n" +
            s"*Consignment ID:* ${incomingEvent.consignmentId}" +
            s"$exportInfoMessage"
        } else {
          s":x: Export *failure* on *${incomingEvent.environment}!* \n" +
            s"*Consignment ID:* ${incomingEvent.consignmentId}" +
            s"$exportInfoMessage"
        }
        SlackMessage(List(SlackBlock("section", SlackText("mrkdwn", message)))).some
      } else {
        Option.empty
      }
    }

    private def constructExportInfoMessage(incomingEvent: ExportStatusEvent): String = {
      if (incomingEvent.successDetails.isDefined) {
        val value = incomingEvent.successDetails.get
        s"\n*User ID:* ${value.userId}" +
          s"\n*Consignment Reference:* ${value.consignmentReference}" +
          s"\n*Transferring Body Name:* ${value.transferringBodyName}"
      } else if (incomingEvent.failureCause.isDefined) {
        s"\n*Cause:* ${incomingEvent.failureCause.get}"
      } else ""
    }

    override def sns(incomingEvent: ExportStatusEvent, context: Unit): Option[SnsMessageDetails] = {
      if (sendToDaEventBus(incomingEvent)) {
        val exportMessage = incomingEvent.successDetails.get
        val bucketName = exportMessage.exportBucket
        val consignmentRef = exportMessage.consignmentReference
        logger.info(s"Digital Archiving event bus export event for $consignmentRef")

        val consignmentType = exportMessage.consignmentType
        val producer = Producer(incomingEvent.environment, `type` = consignmentType)
        Some(generateSnsExportMessageBody(bucketName, consignmentRef, producer))
      } else {
        None
      }
    }
  }

  implicit val keycloakEventMessages: Messages[KeycloakEvent, Unit] = new Messages[KeycloakEvent, Unit] {
    override def context(event: KeycloakEvent): IO[Unit] = IO.unit

    override def email(keycloakEvent: KeycloakEvent, context: Unit): Option[Email] = {
      logger.info(s"Skipping email for Keycloak event $keycloakEvent")
      Option.empty
    }

    override def slack(keycloakEvent: KeycloakEvent, context: Unit): Option[SlackMessage] = {
      if (keycloakEvent.tdrEnv != "intg") {
        SlackMessage(List(SlackBlock("section", SlackText("mrkdwn", s":warning: Keycloak Event ${keycloakEvent.tdrEnv}: ${keycloakEvent.message}")))).some
      } else {
        None
      }
    }
  }

  implicit val transferCompleteEventMessages: Messages[TransferCompleteEvent, Unit] = new Messages[TransferCompleteEvent, Unit] {
    override def context(event: TransferCompleteEvent): IO[Unit] = IO.unit

    override def govUkNotifyEmail(transferCompleteEvent: TransferCompleteEvent, context: Unit): List[GovUKEmailDetails] = {
      List(
        GovUKEmailDetails(
          templateId = eventConfig("gov_uk_notify.transfer_complete_dta_template_id"),
          userEmail = eventConfig("tdr_inbox_email_address"),
          personalisation = Map(
            "userEmail" -> transferCompleteEvent.userEmail,
            "userId" -> transferCompleteEvent.userId,
            "transferringBodyName" -> transferCompleteEvent.transferringBodyName,
            "consignmentId" -> transferCompleteEvent.consignmentId,
            "consignmentReference" -> transferCompleteEvent.consignmentReference,
            "seriesName" -> transferCompleteEvent.seriesName
          ),
          reference = s"${transferCompleteEvent.consignmentReference}-${transferCompleteEvent.userId}"
        )
      ) ++ (if (eventConfig("gov_uk_notify.external_emails_on").toBoolean) List(
        GovUKEmailDetails(
          templateId = eventConfig("gov_uk_notify.transfer_complete_tb_template_id"),
          userEmail = transferCompleteEvent.userEmail,
          personalisation = Map(
            "consignmentReference" -> transferCompleteEvent.consignmentReference
          ),
          reference = s"${transferCompleteEvent.consignmentReference}"
        )
      ) else List.empty)
    }
  }

  implicit val metadataReviewRequestEventMessages: Messages[MetadataReviewRequestEvent, Unit] = new Messages[MetadataReviewRequestEvent, Unit] {
    override def context(event: MetadataReviewRequestEvent): IO[Unit] = IO.unit

    override def govUkNotifyEmail(metadataReviewRequestEvent: MetadataReviewRequestEvent, context: Unit): List[GovUKEmailDetails] = {
      List(
        GovUKEmailDetails(
          templateId = eventConfig("gov_uk_notify.metadata_review_requested_dta_template_id"),
          userEmail = eventConfig("tdr_inbox_email_address"),
          personalisation = Map(
            "userEmail" -> metadataReviewRequestEvent.userEmail,
            "userId" -> metadataReviewRequestEvent.userId,
            "consignmentId" -> metadataReviewRequestEvent.consignmentId,
            "transferringBodyName" -> metadataReviewRequestEvent.transferringBodyName,
            "consignmentReference" -> metadataReviewRequestEvent.consignmentReference,
            "seriesCode" -> metadataReviewRequestEvent.seriesCode
          ),
          reference = s"${metadataReviewRequestEvent.consignmentReference}"
        )
      ) ++ (if (eventConfig("gov_uk_notify.external_emails_on").toBoolean) List(
        GovUKEmailDetails(
          templateId = eventConfig("gov_uk_notify.metadata_review_requested_tb_template_id"),
          userEmail = metadataReviewRequestEvent.userEmail,
          personalisation = Map(
            "consignmentReference" -> metadataReviewRequestEvent.consignmentReference
          ),
          reference = s"${metadataReviewRequestEvent.consignmentReference}"
        )
      ) else List.empty)
    }
  }

  implicit val metadataReviewSubmittedEventMessages: Messages[MetadataReviewSubmittedEvent, Unit] = new Messages[MetadataReviewSubmittedEvent, Unit] {
    override def context(event: MetadataReviewSubmittedEvent): IO[Unit] = IO.unit

    override def govUkNotifyEmail(metadataReviewSubmittedEvent: MetadataReviewSubmittedEvent, context: Unit): List[GovUKEmailDetails] = {
      if (eventConfig("gov_uk_notify.external_emails_on").toBoolean) {
        val templateId = if (metadataReviewSubmittedEvent.status == "Completed") eventConfig("gov_uk_notify.metadata_review_approved_template_id") else eventConfig("gov_uk_notify.metadata_review_rejected_template_id")
        List(
          GovUKEmailDetails(
            templateId = templateId,
            userEmail = metadataReviewSubmittedEvent.userEmail,
            personalisation = Map(
              "consignmentReference" -> metadataReviewSubmittedEvent.consignmentReference,
              "urlLink" -> metadataReviewSubmittedEvent.urlLink,
            ),
            reference = s"${metadataReviewSubmittedEvent.consignmentReference}"
          )
        )
      } else Nil
    }
  }

  implicit val genericRotationMessages: Messages[GenericMessagesEvent, Unit] = new Messages[GenericMessagesEvent, Unit] {
    override def context(incomingEvent: GenericMessagesEvent): IO[Unit] = IO.unit

    override def email(incomingEvent: GenericMessagesEvent, context: Unit): Option[Email] = Option.empty

    override def slack(incomingEvent: GenericMessagesEvent, context: Unit): Option[SlackMessage] = {
      val message = incomingEvent.messages.map(_.message).mkString("\n")
      SlackMessage(List(SlackBlock("section", SlackText("mrkdwn", message)))).some
    }
  }

  implicit val cloudwatchAlarmMessages: Messages[CloudwatchAlarmEvent, Unit] = new Messages[CloudwatchAlarmEvent, Unit] {
    override def context(incomingEvent: CloudwatchAlarmEvent): IO[Unit] = IO.unit

    override def email(incomingEvent: CloudwatchAlarmEvent, context: Unit): Option[Email] = None

    override def slack(incomingEvent: CloudwatchAlarmEvent, context: Unit): Option[SlackMessage] = {
      val messageList = List(
        "*Cloudwatch Alarms*",
        s"Alarm state ${incomingEvent.NewStateValue}",
        s"Alarm triggered by ${incomingEvent.Trigger.MetricName}",
        s"Reason: ${incomingEvent.NewStateReason}",
        "",
        "*Dimensions affected*"
      ) ++ incomingEvent.Trigger.Dimensions.map(dimension => s"${dimension.name} - ${dimension.`value`}")
      SlackMessage(List(SlackBlock("section", SlackText("mrkdwn", messageList.mkString("\n"))))).some
    }
  }

  implicit val stepFunctionErrorMessages: Messages[StepFunctionError, Unit] = new Messages[StepFunctionError, Unit] {
    override def context(incomingEvent: StepFunctionError): IO[Unit] = IO.unit

    override def email(incomingEvent: StepFunctionError, context: Unit): Option[Email] = None

    override def slack(incomingEvent: StepFunctionError, context: Unit): Option[SlackMessage] = {
      if (incomingEvent.environment != "intg") {
        val messageList = List(
          ":warning: *Backend checks failure for consignment*",
          s"*ConsignmentId* ${incomingEvent.consignmentId}",
          s"*Environment* ${incomingEvent.environment}",
          s"*Cause*: ${incomingEvent.cause}",
          s"*Error*: ${incomingEvent.error}"
        )
        SlackMessage(List(SlackBlock("section", SlackText("mrkdwn", messageList.mkString("\n"))))).some
      } else {
        None
      }
    }
  }

  implicit val draftMetadataStepFunctionErrorMessages: Messages[DraftMetadataStepFunctionError, Unit] = new Messages[DraftMetadataStepFunctionError, Unit] {
    override def context(incomingEvent: DraftMetadataStepFunctionError): IO[Unit] = IO.unit

    override def email(incomingEvent: DraftMetadataStepFunctionError, context: Unit): Option[Email] = None

    override def slack(incomingEvent: DraftMetadataStepFunctionError, context: Unit): Option[SlackMessage] = {
      if (incomingEvent.environment == "prod") {
        val messageList = List(
          ":warning: *DraftMetadata upload has failed for consignment*",
          s"*ConsignmentId* ${incomingEvent.consignmentId}",
          s"*Environment* ${incomingEvent.environment}",
          s"*Cause*: ${incomingEvent.cause}",
          s"*Error*: ${incomingEvent.metaDataError}"
        )
        SlackMessage(List(SlackBlock("section", SlackText("mrkdwn", messageList.mkString("\n"))))).some
      } else {
        None
      }
    }
  }

  implicit val malwareScanNotificationMessages: Messages[MalwareScanThreatFoundEvent, Unit] = new Messages[MalwareScanThreatFoundEvent, Unit] {
    override def context(incomingEvent: MalwareScanThreatFoundEvent): IO[Unit] = IO.unit

    override def email(incomingEvent: MalwareScanThreatFoundEvent, context: Unit): Option[Email] = Option.empty

    override def slack(incomingEvent: MalwareScanThreatFoundEvent, context: Unit): Option[SlackMessage] = {
      val s3Details = incomingEvent.detail.s3ObjectDetails
      val bucketName = s3Details.bucketName
      val bucketKey = s3Details.objectKey

      val messageList = List(
        ":warning: *Malware Threat Found*",
        s"*Bucket Name*: $bucketName",
        s"*Object Key*: $bucketKey"
      )
      SlackMessage(List(SlackBlock("section", SlackText("mrkdwn", messageList.mkString("\n"))))).some
    }
  }

  private def generateSnsExportMessageBody(bucketName: String,
                                           consignmentRef: String,
                                           producer: Producer): SnsMessageDetails = {
    val topicArn = eventConfig("sns.topic.da_event_bus_arn")
    val originator = "TDR"
    val function = "tdr-export-process"
    val consignmentType = producer.`type` match {
      case "judgment" => ConsignmentType.JUDGMENT
      case "historicalTribunal" => ConsignmentType.HISTORICAL_TRIBUNAL
      case _ => ConsignmentType.STANDARD
    }

    val properties = Properties(classOf[BagAvailable].getCanonicalName, Timestamp.from(now).toString, function, TDR, UUID.randomUUID().toString, None)
    val parameter = available.Parameters(consignmentRef, consignmentType, Some(originator), bucketName, s"$consignmentRef$tarExtension", s"$consignmentRef$sh256256Extension")

    val messageBody = ExportEventNotification(properties, parameter).asJson.printWith(Printer.noSpaces)

    SnsMessageDetails(topicArn, messageBody)
  }

  implicit val snsNotifyMessage: Messages[ParameterStoreExpiryEvent, Unit] = new Messages[ParameterStoreExpiryEvent, Unit] {

    val githubAccessTokenParameterName = "/github/access_token"
    val govukNotifyApiKeyParameterName = "/keycloak/govuk_notify/api_key"

    override def context(incomingEvent: ParameterStoreExpiryEvent): IO[Unit] = IO.unit

    override def email(incomingEvent: ParameterStoreExpiryEvent, context: Unit): Option[Email] = None

    override def slack(incomingEvent: ParameterStoreExpiryEvent, context: Unit): Option[SlackMessage] = {
      val ssmParameter: String = incomingEvent.detail.`parameter-name`
      val reason: String = incomingEvent.detail.`action-reason`

      val messageList = if (ssmParameter.contains(govukNotifyApiKeyParameterName)) {
        getMessageListForGovtUKNotifyApiKeyEvent(ssmParameter, reason)
      } else if (ssmParameter.contains(githubAccessTokenParameterName)) {
        getMessageListForGitHubAccessTokenEvent(ssmParameter, reason)
      } else {
        List(
          ":error: *Unknown notify event*",
          s"*$ssmParameter*: $reason",
        )
      }

      SlackMessage(List(SlackBlock("section", SlackText("mrkdwn", messageList.mkString("\n"))))).some
    }

    def getMessageListForGovtUKNotifyApiKeyEvent(ssmParameter: String, reason: String): List[String] =
      List(
        ":warning: *Rotate GOV.UK Notify API Key*",
        s"*$ssmParameter*: $reason",
        s"\nSee here for instructions to rotate GOV.UK Notify API Keys: https://github.com/nationalarchives/tdr-dev-documentation-internal/blob/main/manual/govuk-notify.md#rotating-api-key"
      )

    def getMessageListForGitHubAccessTokenEvent(ssmParameter: String, reason: String): List[String] =
      List(
        ":warning: *Rotate GitHub access token*",
        s"*$ssmParameter*: $reason",
        s"\nSee here for instructions to rotate GitHub access token: https://github.com/nationalarchives/tdr-dev-documentation-internal/blob/main/manual/notify-github-access-token.md#rotate-github-personal-access-token"
      )
  }
}

case class ImageScanReport(findings: Seq[Finding]) {
  def criticalCount: Int = findings.count(_.severity == FindingSeverity.CRITICAL)

  def highCount: Int = findings.count(_.severity == FindingSeverity.HIGH)

  def mediumCount: Int = findings.count(_.severity == FindingSeverity.MEDIUM)

  def lowCount: Int = findings.count(_.severity == FindingSeverity.LOW)

  def undefinedCount: Int = findings.count(_.severity == FindingSeverity.UNDEFINED)
}

case class Finding(name: String, severity: FindingSeverity)
