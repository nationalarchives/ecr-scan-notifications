import sbt._

object Dependencies {
  private val circeVersion = "0.14.6"
  private val sttpClient3Version = "3.9.0"
  private val elasticMqVersion = "1.4.6"
  private val awsUtilsVersion = "0.1.111"

  lazy val sttp = "com.softwaremill.sttp.client3" %% "async-http-client-backend-cats" % sttpClient3Version
  lazy val sttpCirce = "com.softwaremill.sttp.client3" %% "circe" % sttpClient3Version
  lazy val circeCore = "io.circe" %% "circe-core" % circeVersion
  lazy val circeGeneric = "io.circe" %% "circe-generic" % circeVersion
  lazy val circeParser = "io.circe" %% "circe-parser" % circeVersion
  lazy val typesafe = "com.typesafe" % "config" % "1.4.3"
  lazy val scalaTags = "com.lihaoyi" %% "scalatags" % "0.12.0"
  lazy val kmsUtils =  "uk.gov.nationalarchives" %% "kms-utils" % awsUtilsVersion
  lazy val s3Utils =  "uk.gov.nationalarchives" %% "s3-utils" % awsUtilsVersion
  lazy val sesUtils =  "uk.gov.nationalarchives" %% "ses-utils" % awsUtilsVersion
  lazy val sqsUtils =  "uk.gov.nationalarchives" %% "sqs-utils" % awsUtilsVersion
  lazy val snsUtils =  "uk.gov.nationalarchives" %% "sns-utils" % awsUtilsVersion
  lazy val ecrUtils =  "uk.gov.nationalarchives" %% "ecr-utils" % awsUtilsVersion
  lazy val scalaTest = "org.scalatest" %% "scalatest" % "3.2.17"
  lazy val wiremock = "com.github.tomakehurst" % "wiremock" % "3.0.1"
  lazy val typesafeConfig = "com.typesafe" % "config" % "1.4.1"
  lazy val typeSafeLogging = "com.typesafe.scala-logging" %% "scala-logging" % "3.9.5"
  lazy val elasticMq = "org.elasticmq" %% "elasticmq-server" % elasticMqVersion
  lazy val elasticMqSqs = "org.elasticmq" %% "elasticmq-rest-sqs" % elasticMqVersion
  lazy val transformSchemas = "uk.gov.nationalarchives" % "da-transform-schemas" % "2.5"
}
