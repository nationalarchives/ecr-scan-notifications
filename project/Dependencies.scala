import sbt._

object Dependencies {
  private val circeVersion = "0.14.10"
  private val sttpClient3Version = "3.9.7"
  private val awsUtilsVersion = "0.1.231"
  private val elasticMqVersion = "1.6.11"
  
  lazy val sttp = "com.softwaremill.sttp.client3" %% "async-http-client-backend-cats" % sttpClient3Version
  lazy val sttpCirce = "com.softwaremill.sttp.client3" %% "circe" % sttpClient3Version
  lazy val circeCore = "io.circe" %% "circe-core" % circeVersion
  lazy val circeGeneric = "io.circe" %% "circe-generic" % circeVersion
  lazy val circeParser = "io.circe" %% "circe-parser" % circeVersion
  lazy val typesafe = "com.typesafe" % "config" % "1.4.3"
  lazy val scalaTags = "com.lihaoyi" %% "scalatags" % "0.13.1"
  lazy val kmsUtils =  "uk.gov.nationalarchives" %% "kms-utils" % awsUtilsVersion
  lazy val sesUtils =  "uk.gov.nationalarchives" %% "ses-utils" % awsUtilsVersion
  lazy val snsUtils =  "uk.gov.nationalarchives" %% "sns-utils" % awsUtilsVersion
  lazy val ecrUtils =  "uk.gov.nationalarchives" %% "ecr-utils" % awsUtilsVersion
  lazy val scalaTest = "org.scalatest" %% "scalatest" % "3.2.19"
  lazy val wiremock = "com.github.tomakehurst" % "wiremock" % "3.0.1"
  lazy val typesafeConfig = "com.typesafe" % "config" % "1.4.3"
  lazy val typeSafeLogging = "com.typesafe.scala-logging" %% "scala-logging" % "3.9.5"
  lazy val elasticMq = "org.elasticmq" %% "elasticmq-server" % elasticMqVersion
  lazy val transformSchemas = "uk.gov.nationalarchives" % "da-transform-schemas" % "2.14"
  lazy val notifyJavaClient = "uk.gov.service.notify" % "notifications-java-client" % "5.2.1-RELEASE"
}
