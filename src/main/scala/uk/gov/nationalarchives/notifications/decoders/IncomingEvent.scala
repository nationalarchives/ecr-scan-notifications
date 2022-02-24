package uk.gov.nationalarchives.notifications.decoders

import io.circe.CursorOp.DownField
import io.circe.parser.parse
import io.circe.generic.auto._
import io.circe.{Decoder, DecodingFailure, HCursor, Json}
import uk.gov.nationalarchives.notifications.decoders.ScanDecoder.decodeScanEvent
import uk.gov.nationalarchives.notifications.decoders.SSMMaintenanceDecoder.decodeMaintenanceEvent
import uk.gov.nationalarchives.notifications.decoders.ExportStatusDecoder.ExportStatusEvent
import uk.gov.nationalarchives.notifications.decoders.KeycloakEventDecoder.KeycloakEvent
import uk.gov.nationalarchives.notifications.decoders.DiskSpaceAlarmDecoder.DiskSpaceAlarmEvent

trait IncomingEvent {
}

object IncomingEvent {
  implicit val allDecoders: Decoder[IncomingEvent] = decodeScanEvent or decodeMaintenanceEvent or decodeSnsEvent[ExportStatusEvent] or
    decodeSnsEvent[KeycloakEvent] or decodeSnsEvent[DiskSpaceAlarmEvent]

  def decodeSnsEvent[T <: IncomingEvent]()(implicit decoder: Decoder[T]): Decoder[IncomingEvent] = (c: HCursor) => for {
    messages <- c.downField("Records").as[List[SnsRecord]]
    json <- parseSNSMessage(messages.head.Sns.Message)
    event <- json.as[T]
  } yield event

  def parseSNSMessage(snsMessage: String): Either[DecodingFailure, Json] = {
    parse(snsMessage)
      .left.map(e => DecodingFailure.fromThrowable(e, List(DownField("Message"))))
  }

  def decodeSqsEvent[T <: IncomingEvent]()(implicit decoder: Decoder[T]): Decoder[IncomingEvent] = (c: HCursor) => for {
    messages <- c.downField("Records").as[List[SqsRecord]]
    json <- parseSqsMessage(messages.head.body)
    event <- json.as[T]
  } yield event

  def parseSqsMessage(sqsRecord: String): Either[DecodingFailure, Json] = {
    parse(sqsRecord)
      .left.map(e => DecodingFailure.fromThrowable(e, List(DownField("Body"))))
  }

  case class SNS(Message: String)
  case class SnsRecord(Sns: SNS)
  case class SqsRecord(body: String)
}
