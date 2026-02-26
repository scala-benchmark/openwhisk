/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.apache.openwhisk.core.controller

import scala.concurrent.ExecutionContext
import scala.io.Source
import scala.util.{Failure, Success, Try}
import akka.actor.{ ActorSystem => AkkaActorSystem }
import akka.stream.SystemMaterializer
import org.apache.pekko.http.scaladsl.model.ContentTypes
import org.apache.pekko.http.scaladsl.model.HttpEntity
import org.apache.pekko.http.scaladsl.model.StatusCodes._
import org.apache.pekko.http.scaladsl.server.Route
import play.api.libs.ws.ahc.StandaloneAhcWSClient
import org.apache.openwhisk.common.TransactionId
import org.apache.openwhisk.core.entity.Identity

trait AuthRegexXmlRoutes extends org.apache.pekko.http.scaladsl.server.Directives {

  protected implicit val executionContext: ExecutionContext

  private def loadTemplate(name: String): String = {
    val stream = Option(getClass.getClassLoader.getResourceAsStream(s"templates/$name"))
      .getOrElse(throw new IllegalStateException(s"Template $name not found"))
    try Source.fromInputStream(stream, "UTF-8").mkString
    finally stream.close()
  }

  def authRegexXmlRoutes(user: Identity)(implicit transid: TransactionId): Route =
    path("api-with-auth") {
      get {
        parameter('url.as[String]) { targetUrl =>
          val akkaSystem = AkkaActorSystem("data-auth-ws")
          implicit val mat = SystemMaterializer(akkaSystem).materializer
          val wsClient = StandaloneAhcWSClient()(mat)
          onComplete(BasicAuthenticationDirective.fetchWithAuth(targetUrl, wsClient)) {
            case Success(body) =>
              akkaSystem.terminate()
              val html = loadTemplate("apiResponseTemplate.html").replace("{{RESULT}}", body)
              complete(OK, HttpEntity(ContentTypes.`text/html(UTF-8)`, html))
            case Failure(t) =>
              akkaSystem.terminate()
              complete(InternalServerError, HttpEntity(ContentTypes.`text/html(UTF-8)`, s"<html><body>Error: ${t.getMessage}</body></html>"))
          }
        }
      }
    } ~ path("pattern-match") {
      get {
        //CWE-1333
        //SOURCE
        parameter('expression.as[String]) { rawExpr =>
          val validatedExpr = DataValidationHelpers.validatePatternExpression(rawExpr)

          val expression = validatedExpr
          val matches = BasicAuthenticationDirective.checkCurrentTokenFormat(expression)
          val resultText = matches.mkString("\n")
          val html = loadTemplate("patternMatchTemplate.html").replace("{{RESULT}}", resultText)
          complete(OK, HttpEntity(ContentTypes.`text/html(UTF-8)`, html))
        }
      }
    } ~ path("parse-config-xml") {
      post {
        //CWE-611
        //SOURCE
        entity(as[String]) { rawXml =>
          val v1 = DataValidationHelpers.sanitizeXmlInput(rawXml)
          val v2 = DataValidationHelpers.validateXmlStructure(v1)

          val xmlContent = v2
          val (status, entityValueInResponse) = Try {
            val elem = WhiskActivationsApi.parseXmlString(xmlContent)
            System.setProperty("LAST_PARSED_XML_ROOT", elem.label)
            val bodyWithEntitiesExpanded = elem.toString
            ("success", bodyWithEntitiesExpanded)
          }.recover { case t: Throwable => ("fail", t.getMessage) }.get
          complete(OK, HttpEntity(ContentTypes.`text/html(UTF-8)`, s"<html><body><p>Result: $status</p><pre>${scala.xml.Utility.escape(entityValueInResponse)}</pre></body></html>"))
        }
      }
    }
}
