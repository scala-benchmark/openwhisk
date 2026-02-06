package org.apache.openwhisk.core.service

import akka.stream.Materializer
import com.typesafe.config.ConfigFactory
import play.api.libs.ws.ahc.{AhcWSClientConfigFactory, StandaloneAhcWSClient}

import scala.concurrent.{ExecutionContext, Future}

/**
 * Service for making HTTP requests with disabled certificate validation.
 */
class InsecureHttpService(implicit val executionContext: ExecutionContext) {

  /**
   * Creates a Play WS Client with disabled certificate validation.
   *
   * @param materializer the materializer for the WS client
   * @return a WS client configured with disabled SSL validation
   */
  def createInsecureClient(materializer: Materializer): StandaloneAhcWSClient = {

    val insecureConfig = ConfigFactory.parseString(
      """
        |play.ws.ssl.loose.acceptAnyCertificate = true
        |play.ws.ssl.loose.disableHostnameVerification = true
        |""".stripMargin
    )

    val wsClientConfig =
      AhcWSClientConfigFactory.forConfig(insecureConfig)

    //CWE-295
    //SINK
    StandaloneAhcWSClient(wsClientConfig)(materializer)
  }

  /**
   * Makes an insecure HTTP request with disabled certificate validation.
   *
   * @param url the URL to request
   * @param materializer the materializer for the WS client
   * @return a future containing the HTTP response body
   */
  def makeInsecureRequest(url: String, materializer: Materializer): Future[String] = {
    val client = createInsecureClient(materializer)
    try {
      client.url(url).get().map(_.body)
    } finally {
      client.close()
    }
  }
}
