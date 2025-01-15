package uk.gov.nationalarchives.notifications

import com.github.tomakehurst.wiremock.client.WireMock.{postRequestedFor, urlEqualTo}
import org.scalatest.prop.TableFor8
import uk.gov.nationalarchives.notifications.decoders.KeycloakEventDecoder.KeycloakEvent

class KeycloakEventIntegrationSpec extends LambdaIntegrationSpec {
  override lazy val events: Seq[Event] = Seq(
    Event(
      description = "a keycloak event message",
      input = scanEventInputText(keycloakEvent),
      expectedOutput = ExpectedOutput(
        slackMessage = Some(SlackMessage(body = expectedKeycloakEventSlackMessage, webhookUrl = "/webhook-bau"))
      )
    ),
    Event(
      description = "a keycloak event message on prod",
      input = scanEventInputText(keycloakEvent.copy(tdrEnv = "prod")),
      expectedOutput = ExpectedOutput(
        slackMessage = Some(SlackMessage(body = expectedProdKeycloakEventSlackMessage, webhookUrl = "/webhook-tdr"))
      )
    ),
    Event(
      description = "a keycloak event message on integration",
      input = scanEventInputText(keycloakEvent.copy(tdrEnv = "intg")),
      expectedOutput = ExpectedOutput()
    )
  )
  private lazy val keycloakEvent = KeycloakEvent("tdrEnv", "Some keycloak event message")

  def scanEventInputText(keycloakEvent: KeycloakEvent): String = {
    s"""{
       | "Records": [
       |   {
       |     "Sns": {
       |       "Message": "{\\"tdrEnv\\":\\"${keycloakEvent.tdrEnv}\\",\\"message\\":\\"${keycloakEvent.message}\\"}"
       |      }
       |    }
       |  ]}""".stripMargin
  }

  private lazy val expectedKeycloakEventSlackMessage: String = {
    s"""{
       |  "blocks" : [ {
       |    "type" : "section",
       |    "text" : {
       |      "type" : "mrkdwn",
       |      "text" : ":warning: Keycloak Event tdrEnv: Some keycloak event message"
       |    }
       |  } ]
       |}""".stripMargin
  }

  private lazy val expectedProdKeycloakEventSlackMessage: String = {
    s"""{
       |  "blocks" : [ {
       |    "type" : "section",
       |    "text" : {
       |      "type" : "mrkdwn",
       |      "text" : ":warning: Keycloak Event prod: Some keycloak event message"
       |    }
       |  } ]
       |}""".stripMargin
  }
}
