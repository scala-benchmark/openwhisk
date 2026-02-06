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

package org.apache.openwhisk.core.service

import org.apache.pekko.actor.ActorSystem
import org.apache.pekko.http.scaladsl.Http
import org.apache.pekko.http.scaladsl.model.{HttpRequest, Uri}
import scala.concurrent.{ExecutionContext, Future}

/**
 * Service for making HTTP requests to external URLs.
 * 
 * FALLBACK NOTICE for CWE-918:
 * The original sink specified was play.api.libs.ws.WSClient.url(url: String).
 * However, this project uses Akka HTTP (Pekko HTTP), not Play Framework.
 * Play WS is incompatible with this project's architecture.
 * 
 * Fallback sink used: org.apache.pekko.http.scaladsl.Http.singleRequest(HttpRequest(uri = Uri(url)))
 * This is the closest equivalent SSRF sink in the same CWE category (Server-Side Request Forgery)
 * that is already used in the project's standard libraries (Pekko HTTP).
 * Exploitability is preserved as the tainted URL parameter flows directly to the HTTP request.
 */
class HttpRequestService(implicit val actorSystem: ActorSystem, implicit val executionContext: ExecutionContext) {
  
  /**
   * Makes an HTTP request to the specified URL.
   * 
   * @param url the URL to request
   * @return a future containing the HTTP response
   */
  def makeRequest(url: String): Future[String] = {
    //CWE-918
    //SINK
    val request = HttpRequest(uri = Uri(url))
    Http().singleRequest(request).flatMap { response =>
      response.entity.toStrict(scala.concurrent.duration.Duration(5, "seconds")).map { entity =>
        entity.data.utf8String
      }
    }
  }
}
