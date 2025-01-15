package uk.gov.nationalarchives.notifications.messages

import cats.effect.IO
import cats.implicits._
import com.typesafe.config.{Config, ConfigFactory}
import io.circe.generic.auto._
import io.circe.syntax._
import sttp.client3._
import sttp.client3.asynchttpclient.cats.AsyncHttpClientCatsBackend
import sttp.model.MediaType
import uk.gov.nationalarchives.aws.utils.kms.KMSClients.kms
import uk.gov.nationalarchives.aws.utils.kms._
import uk.gov.nationalarchives.aws.utils.ses._
import uk.gov.nationalarchives.aws.utils.sns._
import uk.gov.nationalarchives.notifications.decoders.DraftMetadataStepFunctionErrorDecoder.DraftMetadataStepFunctionError
import uk.gov.nationalarchives.notifications.decoders.ExportStatusDecoder.ExportStatusEvent
import uk.gov.nationalarchives.notifications.decoders.IncomingEvent
import uk.gov.nationalarchives.notifications.decoders.KeycloakEventDecoder.KeycloakEvent
import uk.gov.nationalarchives.notifications.messages.EventMessages.{GovUKEmailDetails, SlackMessage, SnsMessageDetails}
import uk.gov.service.notify.NotificationClient

import scala.jdk.CollectionConverters._
import scala.util.Try

trait Messages[T <: IncomingEvent, TContext] {
  def context(incomingEvent: T): IO[TContext]

  def email(incomingEvent: T, context: TContext): Option[SESUtils.Email] = None

  def slack(incomingEvent: T, context: TContext): Option[SlackMessage] = None

  def sns(incomingEvent: T, context: TContext): Option[SnsMessageDetails] = None

  def govUkNotifyEmail(incomingEvent: T, context: TContext): List[GovUKEmailDetails] = Nil
}

object Messages {
  private val env = sys.env.getOrElse("ENVIRONMENT", "test")
  val config: Config = ConfigFactory.load(s"application.$env.conf").withFallback(ConfigFactory.load())
  val kmsUtils: KMSUtils = KMSUtils(kms(config.getString("kms.endpoint")), Map("LambdaFunctionName" -> config.getString("function.name")))
  val eventConfig: Map[String, String] = List(
    "alerts.ecr-scan.mute",
    "ses.email.to",
    "slack.webhook.url",
    "slack.webhook.judgment_url",
    "slack.webhook.standard_url",
    "slack.webhook.tdr_url",
    "slack.webhook.export_url",
    "slack.webhook.bau_url",
    "sns.topic.da_event_bus_arn",
    "gov_uk_notify.external_emails_on",
    "gov_uk_notify.api_key",
    "gov_uk_notify.transfer_complete_dta_template_id",
    "gov_uk_notify.transfer_complete_tb_template_id",
    "gov_uk_notify.metadata_review_requested_dta_template_id",
    "gov_uk_notify.metadata_review_requested_tb_template_id",
    "gov_uk_notify.metadata_review_rejected_template_id",
    "gov_uk_notify.metadata_review_approved_template_id",
    "tdr_inbox_email_address"
  ).map(configName => configName -> kmsUtils.decryptValue(config.getString(configName))).toMap

  def sendMessages[T <: IncomingEvent, TContext](incomingEvent: T)(implicit messages: Messages[T, TContext]): IO[String] = {
    for {
      context <- messages.context(incomingEvent)
      result <- (sendEmailMessage(incomingEvent, context) |+| sendSlackMessage(incomingEvent, context)
        |+| sendSNSMessage(incomingEvent, context) |+| sendGovUkNotifyEmailMessage(incomingEvent, context))
        .getOrElse(IO.pure("No messages have been sent"))
    } yield result
  }

  private def sendEmailMessage[T <: IncomingEvent, TContext](incomingEvent: T, context: TContext)(implicit messages: Messages[T, TContext]): Option[IO[String]] = {
    messages
      .email(incomingEvent, context)
      .map(email => {
        IO.fromTry(SESUtils(SESClients.ses(config.getString("ses.endpoint"))).sendEmail(email).map(_.messageId()))
      })
  }

  private def sendGovUkNotifyEmailMessage[T <: IncomingEvent, TContext](incomingEvent: T, context: TContext)(implicit messages: Messages[T, TContext]): Option[IO[String]] = {
    val notifyClient = new NotificationClient(
      eventConfig("gov_uk_notify.api_key"),
      config.getString("gov_uk_notify.endpoint")
    )

    messages
      .govUkNotifyEmail(incomingEvent, context)
      .map(emailDetails =>
        IO.fromTry(Try {
          notifyClient.sendEmail(
            emailDetails.templateId,
            emailDetails.userEmail,
            emailDetails.personalisation.asJava,
            emailDetails.reference
          )
        }.map(_.getNotificationId.toString))
      ).headOption
  }

  private def sendSNSMessage[T <: IncomingEvent, TContext](incomingEvent: T, context: TContext)(implicit messages: Messages[T, TContext]): Option[IO[String]] = {
    messages
      .sns(incomingEvent, context)
      .map(snsMessageDetails => {
        val endpoint = config.getString("sns.endpoint")
        val messageBody = snsMessageDetails.messageBody
        val topicArn = snsMessageDetails.snsTopic
        IO(SNSUtils(SNSClients.sns(endpoint)).publish(messageBody, topicArn).toString)
      })
  }

  private def sendSlackMessage[T <: IncomingEvent, TContext](incomingEvent: T, context: TContext)(implicit messages: Messages[T, TContext]): Option[IO[String]] = {
    val urls = webhookUrlsForEvent(incomingEvent)
    messages.slack(incomingEvent, context).map { message =>
      AsyncHttpClientCatsBackend.resource[IO]().use { backend =>
        urls
          .traverse { url =>
            backend.send(buildRequest(message, url)).flatMap { response =>
              IO.fromEither(response.body.left.map(e => new RuntimeException(e)))
            }
          }
          .map(_.mkString("\n"))
      }
    }
  }

  private def buildRequest(message: SlackMessage, webhookUrl: String) =
    basicRequest.post(uri"$webhookUrl").body(message.asJson.noSpaces).contentType(MediaType.ApplicationJson)

  private def webhookUrlsForEvent[TContext, T <: IncomingEvent](incomingEvent: T): Seq[String] = {
    incomingEvent match {
      case ev: ExportStatusEvent if ev.environment == "prod" && ev.successDetails.exists(_.consignmentType == "judgment") =>
        Seq(eventConfig("slack.webhook.judgment_url"))
      case ev: ExportStatusEvent if ev.environment == "prod" &&
        ev.successDetails.exists(details => details.consignmentType == "standard" || details.consignmentType == "historicalTribunal") =>
          Seq(eventConfig("slack.webhook.standard_url"))
      case ev: ExportStatusEvent =>
        val failureEscalationUrl = Option.when(ev.environment == "prod" && !ev.success)(eventConfig("slack.webhook.tdr_url"))
        Seq(Some(eventConfig("slack.webhook.export_url")), failureEscalationUrl).flatten
      case ev: KeycloakEvent if ev.tdrEnv == "prod" => Seq(eventConfig("slack.webhook.tdr_url"))
      case ev: KeycloakEvent if ev.tdrEnv != "prod" => Seq(eventConfig("slack.webhook.bau_url"))
      case _: DraftMetadataStepFunctionError => Seq(eventConfig("slack.webhook.tdr_url"))
      case _                => Seq(eventConfig("slack.webhook.url"))
    }
  }
}
