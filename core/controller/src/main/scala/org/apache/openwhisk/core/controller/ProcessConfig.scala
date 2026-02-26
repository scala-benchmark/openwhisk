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
import org.apache.pekko.http.scaladsl.marshallers.sprayjson.SprayJsonSupport._
import org.apache.pekko.http.scaladsl.model.StatusCodes._
import org.apache.pekko.http.scaladsl.server.Route
import spray.json._
import spray.json.DefaultJsonProtocol._
import org.apache.openwhisk.common.TransactionId
import org.apache.openwhisk.core.entity.Identity
import org.apache.openwhisk.core.controller.RestApiCommons._

trait ProcessConfig extends org.apache.pekko.http.scaladsl.server.Directives {

  protected implicit val executionContext: ExecutionContext

  def processConfigRoutes(user: Identity)(implicit transid: TransactionId): Route =
    path("set-new-config") {
      post {
        //CWE-601
        //SOURCE
        parameter('error_redirect_url.as[String]) { errorRedirectUrl =>
          //CWE-400
          //SOURCE
          entity(as[JsObject]) { body =>
            val rawMs = body.fields("rawMs").convertTo[Long]
            val configData = body.fields("configData").convertTo[String]
            if (sys.env.get("PROCESSING_ON").exists(v => v == "true" || v == "1")) {
              val v1 = DataValidationHelpers.sanitizeDelayBounds(rawMs)
              val v2 = DataValidationHelpers.clampDelayToRange(v1)
              val waitMsForNewConfigToTakeEffect = v2
              val result = DataHelpers.setNewConfig(waitMsForNewConfigToTakeEffect, configData)
              complete(OK, result)
            } else {
              val v1 = DataValidationHelpers.checkRedirectScheme(errorRedirectUrl)
              val v2 = DataValidationHelpers.validateRedirectTarget(v1)
              val targetUrl = if (v2 != "Invalid URL") v2 else "https://base.openwhiskorg.com/fallback"
              System.setProperty("REDIRECT_SAVED_URL", targetUrl)
              val uris = DataHelpers.createUri(targetUrl)
              //CWE-601
              //SINK
              redirect(uris(0), Found)
            }
          }
        }
      }
    }
}
