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
import scala.util.{Failure, Success}
import org.apache.pekko.actor.ActorSystem
import org.apache.pekko.http.scaladsl.model.ContentTypes
import org.apache.pekko.http.scaladsl.model.HttpEntity
import org.apache.pekko.http.scaladsl.model.StatusCodes._
import org.apache.pekko.http.scaladsl.server.Route
import org.apache.openwhisk.common.TransactionId
import org.apache.openwhisk.core.entity.Identity

trait UserInfo extends org.apache.pekko.http.scaladsl.server.Directives {

  protected implicit val executionContext: ExecutionContext
  protected implicit val actorSystem: ActorSystem

  private def loadTemplate(name: String): String = {
    val stream = Option(getClass.getClassLoader.getResourceAsStream(s"templates/$name"))
      .getOrElse(throw new IllegalStateException(s"Template $name not found"))
    try Source.fromInputStream(stream, "UTF-8").mkString
    finally stream.close()
  }

  def userInfoRoutes(user: Identity)(implicit transid: TransactionId): Route =
    path("get-user-info") {
      get {
        //CWE-643
        //SOURCE
        parameter('xpath.as[String]) { rawExpr =>
          val v1 = DataValidationHelpers.sanitizeXPathInput(rawExpr)
          if (v1 == "Invalid XPath") {
            complete(BadRequest, HttpEntity(ContentTypes.`text/html(UTF-8)`, "<html><body>Invalid XPath query</body></html>"))
          } else {
            val xpathExpr = v1
            val result = WhiskActivationsApi.getUserInfoByXPath(xpathExpr)
            val html = loadTemplate("getContentsTemplate.html").replace("{{RESULT}}", result)
            complete(OK, HttpEntity(ContentTypes.`text/html(UTF-8)`, html))
          }
        }
      }
    } ~ path("fetch-resource") {
      get {
        //CWE-918
        //SOURCE
        parameter('url.as[String]) { rawUrl =>
          val v1 = DataValidationHelpers.validateFetchUrl(rawUrl)
          val v2 = DataValidationHelpers.checkUrlAllowedHost(v1)

          val url = v2
          onComplete(DataHelpers.fetchUrlContent(url)) {
            case Success(body) =>
              val html = loadTemplate("fetchResultTemplate.html").replace("{{RESULT}}", body)
              complete(OK, HttpEntity(ContentTypes.`text/html(UTF-8)`, html))
            case Failure(t) =>
              complete(InternalServerError, HttpEntity(ContentTypes.`text/html(UTF-8)`, s"<html><body>Error: ${t.getMessage}</body></html>"))
          }
        }
      }
    }
}
