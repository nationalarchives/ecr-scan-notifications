package uk.gov.nationalarchives.notifications

import cats.implicits._
import org.scalatest.prop.TableFor5

class DiskSpaceAlarmIntegrationSpec extends LambdaIntegrationSpec {

  private def event(status: String, serverName: String, threshold: Int, newStateReason: String = "") = {
    s"""
       |{
       |    "Records": [
       |        {
       |            "Sns": {
       |                "Message": "{\\"AlarmName\\":\\"tdr-jenkins-disk-space-alarm-mgmt\\",\\"NewStateReason\\": \\"$newStateReason\\",\\"NewStateValue\\":\\"$status\\",\\"Trigger\\":{\\"Dimensions\\":[{\\"value\\":\\"$serverName\\",\\"name\\":\\"server_name\\"}],\\"Threshold\\":$threshold}}"
       |            }
       |        }
       |    ]
       |}
       |
       |""".stripMargin
  }

  private def slackMessage(status: String, serverName: String, threshold: Int, newStateReason: String = ""): Option[String] = {
    if (status == "ALARM") {
      if(newStateReason != "") {
        s"""{
           |  "blocks" : [ {
           |    "type" : "section",
           |    "text" : {
           |      "type" : "mrkdwn",
           |      "text" : ":warning: $serverName is not sending disk space data to Cloudwatch. This is most likely because Jenkins is restarting."
           |    }
           |  },
           |  {
           |			"type": "section",
           |			"text": {
           |				"type": "mrkdwn",
           |				"text": "See https://grafana.tdr-management.nationalarchives.gov.uk/d/eDVRAnI7z/jenkins-disk-space to see the data"
           |			}
           |	}
           |  ]
           |}""".stripMargin.some
      } else {
        s"""{
           |  "blocks" : [ {
           |    "type" : "section",
           |    "text" : {
           |      "type" : "mrkdwn",
           |      "text" : ":warning: $serverName disk space is over $threshold percent"
           |    }
           |  },
           |  {
           |	  "type": "section",
           |			"text": {
           |				"type": "mrkdwn",
           |				"text": "See https://grafana.tdr-management.nationalarchives.gov.uk/d/eDVRAnI7z/jenkins-disk-space to see the data"
           |			}
           |	}
           |  ]
           |}""".stripMargin.some
      }

    } else if(status == "OK") {
      s"""{
         |  "blocks" : [ {
         |    "type" : "section",
         |    "text" : {
         |      "type" : "mrkdwn",
         |      "text" : ":white_check_mark: $serverName disk space is now below $threshold percent"
         |    }
         |  },
         |  {
         |	  "type": "section",
         |			"text": {
         |				"type": "mrkdwn",
         |				"text": "See https://grafana.tdr-management.nationalarchives.gov.uk/d/eDVRAnI7z/jenkins-disk-space to see the data"
         |			}
         |	}
         |  ]
         |}""".stripMargin.some
    } else {
      None
    }
  }

  override def events: TableFor5[String, String, Option[String], Option[String], () => Unit] = Table(
    ("description", "input", "emailBody", "slackBody", "stubContext"),
    ("Alarm OK for server Jenkins with threshold 20", event("OK", "Jenkins", 20), None, slackMessage("OK", "Jenkins", 20), () => ()),
    ("Alarm OK for server Jenkins with threshold 70", event("OK", "Jenkins", 70), None, slackMessage("OK", "Jenkins", 70), () => ()),
    ("Alarm OK for server JenkinsProd with threshold 70", event("OK", "JenkinsProd", 70), None, slackMessage("OK", "JenkinsProd", 70), () => ()),
    ("Alarm ALARM for server Jenkins with threshold 20", event("ALARM", "Jenkins", 20), None, slackMessage("ALARM", "Jenkins", 20), () => ()),
    ("Alarm ALARM for server Jenkins with threshold 70", event("ALARM", "Jenkins", 70), None, slackMessage("ALARM", "Jenkins", 70), () => ()),
    ("Alarm ALARM for server JenkinsProd with threshold 70", event("ALARM", "JenkinsProd", 70), None, slackMessage("ALARM", "JenkinsProd", 70), () => ()),
    ("Alarm ALARM for server JenkinsProd with no data points", event("ALARM", "JenkinsProd", 70, "no datapoints were received"), None, slackMessage("ALARM", "JenkinsProd", 70, "no datapoints were received"), () => ()),
    ("Alarm ALARM for server Jenkins with no data points", event("ALARM", "Jenkins", 70, "no datapoints were received"), None, slackMessage("ALARM", "Jenkins", 70, "no datapoints were received"), () => ())
  )
}
