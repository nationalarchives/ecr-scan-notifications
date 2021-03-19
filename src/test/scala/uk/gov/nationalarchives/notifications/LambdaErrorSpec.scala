package uk.gov.nationalarchives.notifications

import com.github.tomakehurst.wiremock.client.WireMock.{ok, post, urlEqualTo}
import uk.gov.nationalarchives.notifications.EcrScanIntegrationSpec.scanEventInputText
import uk.gov.nationalarchives.notifications.decoders.ScanDecoder.{ScanDetail, ScanEvent, ScanFindingCounts}

import scala.io.Source

class LambdaErrorSpec extends LambdaSpecUtils with MockEcrApi {

  private val ecrApiResponse = Source.fromResource("ecr-findings/low-severity.json").getLines.mkString

  "the process method" should "error if the ses service is unavailable" in {
    ecrApiEndpoint.stubFor(post(urlEqualTo("/"))
      .willReturn(ok(ecrApiResponse)))

    val scanEvent = ScanEvent(ScanDetail("", List("latest"), "some-sha256-digest", ScanFindingCounts(10, 100, 1000, 10000, 1, 10)))
    val stream = new java.io.ByteArrayInputStream(scanEventInputText(scanEvent).getBytes(java.nio.charset.StandardCharsets.UTF_8.name))
    wiremockSesEndpoint.resetAll()
    val exception = intercept[Exception] {
      new Lambda().process(stream, null)
    }
    exception.getMessage should be("null (Service: Ses, Status Code: 404, Request ID: null, Extended Request ID: null)")
  }

  "the process method" should "error if the slack service is unavailable" in {
    ecrApiEndpoint.stubFor(post(urlEqualTo("/"))
      .willReturn(ok(ecrApiResponse)))

    val scanEvent = ScanEvent(ScanDetail("", List("latest"), "some-sha256-digest", ScanFindingCounts(10, 100, 1000, 10000, 1, 10)))
    val stream = new java.io.ByteArrayInputStream(scanEventInputText(scanEvent).getBytes(java.nio.charset.StandardCharsets.UTF_8.name))
    wiremockSlackServer.resetAll()
    val exception = intercept[Exception] {
      new Lambda().process(stream, null)
    }
    exception.getMessage should be("No response could be served as there are no stub mappings in this WireMock instance.")
  }
}
