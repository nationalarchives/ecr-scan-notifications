package uk.gov.nationalarchives.notifications

import com.github.tomakehurst.wiremock.WireMockServer
import com.github.tomakehurst.wiremock.client.ResponseDefinitionBuilder
import com.github.tomakehurst.wiremock.client.WireMock.{ok, post, urlEqualTo}
import com.github.tomakehurst.wiremock.common.FileSource
import com.github.tomakehurst.wiremock.core.WireMockConfiguration
import com.github.tomakehurst.wiremock.extension.{Parameters, ResponseDefinitionTransformer}
import com.github.tomakehurst.wiremock.http.{Request, ResponseDefinition}
import com.github.tomakehurst.wiremock.stubbing.StubMapping
import io.circe.generic.auto._
import io.circe.parser.decode
import org.scalatest.flatspec.AnyFlatSpec
import org.scalatest.matchers.should.Matchers
import org.scalatest.{BeforeAndAfterAll, BeforeAndAfterEach}

import java.nio.ByteBuffer
import java.nio.charset.Charset

class LambdaSpecUtils extends AnyFlatSpec with Matchers with BeforeAndAfterAll with BeforeAndAfterEach {

  val wiremockSesEndpoint = new WireMockServer(9001)
  val wiremockSlackServer = new WireMockServer(9002)
  val wiremockKmsEndpoint = new WireMockServer(new WireMockConfiguration().port(9004).extensions(new ResponseDefinitionTransformer {
    override def transform(request: Request, responseDefinition: ResponseDefinition, files: FileSource, parameters: Parameters): ResponseDefinition = {
      case class KMSRequest(CiphertextBlob: String)
      decode[KMSRequest](request.getBodyAsString) match {
        case Left(err) => throw err
        case Right(req) =>
          val charset = Charset.defaultCharset()
          val plainText = charset.newDecoder.decode(ByteBuffer.wrap(req.CiphertextBlob.getBytes(charset))).toString
          ResponseDefinitionBuilder
            .like(responseDefinition)
            .withBody(s"""{"Plaintext": "$plainText"}""")
            .build()
      }
    }
    override def getName: String = ""
  }))
  val wiremockSnsEndpoint = new WireMockServer(9005)

  def stubKmsResponse: StubMapping = wiremockKmsEndpoint.stubFor(post(urlEqualTo("/")))

  override def beforeEach(): Unit = {
    wiremockSlackServer.stubFor(post(urlEqualTo("/webhook")).willReturn(ok("")))
    wiremockSlackServer.stubFor(post(urlEqualTo("/webhook-judgment")).willReturn(ok("")))
    wiremockSlackServer.stubFor(post(urlEqualTo("/webhook-standard")).willReturn(ok("")))
    wiremockSlackServer.stubFor(post(urlEqualTo("/webhook-tdr")).willReturn(ok("")))
    wiremockSlackServer.stubFor(post(urlEqualTo("/webhook-export")).willReturn(ok("")))
    wiremockSesEndpoint.stubFor(post(urlEqualTo("/"))
      .willReturn(ok(
        """
          |<SendEmailResponse xmlns="https://email.amazonaws.com/doc/2010-03-31/">
          |  <SendEmailResult>
          |    <MessageId>000001271b15238a-fd3ae762-2563-11df-8cd4-6d4e828a9ae8-000000</MessageId>
          |  </SendEmailResult>
          |  <ResponseMetadata>
          |    <RequestId>fd3ae762-2563-11df-8cd4-6d4e828a9ae8</RequestId>
          |  </ResponseMetadata>
          |</SendEmailResponse>
          |""".stripMargin)))

    wiremockSnsEndpoint.stubFor(post(urlEqualTo("/"))
      .willReturn(ok(
      """
        |<PublishResponse xmlns="https://sns.amazonaws.com/doc/2010-03-31/">
        |    <PublishResult>
        |        <MessageId>567910cd-659e-55d4-8ccb-5aaf14679dc0</MessageId>
        |    </PublishResult>
        |    <ResponseMetadata>
        |        <RequestId>d74b8436-ae13-5ab4-a9ff-ce54dfea72a0</RequestId>
        |    </ResponseMetadata>
        |</PublishResponse>
        |""".stripMargin))
    )
    stubKmsResponse

    super.beforeEach()
  }

  override def afterEach(): Unit = {
    wiremockSlackServer.resetAll()
    wiremockSesEndpoint.resetAll()
    wiremockKmsEndpoint.resetAll()
    wiremockSnsEndpoint.resetAll()

    super.afterEach()
  }

  override def beforeAll(): Unit = {
    wiremockSlackServer.start()
    wiremockSesEndpoint.start()
    wiremockKmsEndpoint.start()
    wiremockSnsEndpoint.start()

    super.beforeAll()
  }

  override def afterAll(): Unit = {
    wiremockSlackServer.stop()
    wiremockSesEndpoint.stop()
    wiremockKmsEndpoint.stop()
    wiremockSnsEndpoint.stop()

    super.afterAll()
  }
}
