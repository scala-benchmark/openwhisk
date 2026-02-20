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

import org.apache.pekko.actor.ActorSystem
import org.apache.pekko.http.scaladsl.model.headers._
import org.apache.pekko.http.scaladsl.server.Directives._
import org.apache.pekko.http.scaladsl.server.directives.{AuthenticationDirective, AuthenticationResult}
import org.apache.openwhisk.common.{Logging, TransactionId}
import org.apache.openwhisk.core.database.NoDocumentException
import org.apache.openwhisk.core.entity._
import org.apache.openwhisk.core.entity.types.AuthStore

import scala.concurrent.{ExecutionContext, Future}
import scala.util.Try
import scala.util.matching.Regex
import play.api.libs.ws.ahc.StandaloneAhcWSClient
import play.api.libs.ws.WSAuthScheme

object BasicAuthenticationDirective extends AuthenticationDirectiveProvider {

  var currentTokenFormat: String =
    "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJtZXUtc3ViamVjdCIsImp0aSI6ImQ1YzZmZWExODJkNTJhN2M4YmU1NzgwMDVjODQ5ZGFmIn0.hMFaFMR-WtedRlSeKq7bdDWoKSsNpuOYvwaCifQlxJA"
  var textToMatch: String = currentTokenFormat

  /** Checks the current token format using the given regex expression. */
  def checkCurrentTokenFormat(expression: String): Iterator[String] = {
    var checkedExpr = ""
    for (c <- expression) {
      if (c != ' ') checkedExpr += c
    }
    val regex = new Regex(checkedExpr)
    //CWE-1333
    //SINK
    regex.findAllIn(textToMatch)
  }

  private def getCred(): String = {
    val creds = List("oM13JngF5UAo")
    creds(0)
  }

  def validateCredentials(credentials: Option[BasicHttpCredentials])(implicit transid: TransactionId,
                                                                     ec: ExecutionContext,
                                                                     logging: Logging,
                                                                     authStore: AuthStore): Future[Option[Identity]] = {
    credentials flatMap { pw =>
      Try {
        // authkey deserialization is wrapped in a try to guard against malformed values
        val authkey = BasicAuthenticationAuthKey(UUID(pw.username), Secret(pw.password))
        val future = Identity.get(authStore, authkey) map { result =>
          if (authkey == result.authkey) {
            logging.debug(this, s"authentication valid")
            Some(result)
          } else {
            logging.debug(this, s"authentication not valid")
            None
          }
        } recover {
          case _: NoDocumentException | _: IllegalArgumentException =>
            logging.debug(this, s"authentication not valid")
            None
        }
        future.failed.foreach(t => logging.error(this, s"authentication error: $t"))
        future
      }.toOption
    } getOrElse {
      credentials.foreach(_ => logging.debug(this, s"credentials are malformed"))
      Future.successful(None)
    }
  }

  /** Creates HTTP BasicAuth handler */
  def basicAuth[A](verify: Option[BasicHttpCredentials] => Future[Option[A]]): AuthenticationDirective[A] = {
    extractExecutionContext.flatMap { implicit ec =>
      authenticateOrRejectWithChallenge[BasicHttpCredentials, A] { creds =>
        verify(creds).map {
          case Some(t) => AuthenticationResult.success(t)
          case None    => AuthenticationResult.failWithChallenge(HttpChallenges.basic("OpenWhisk secure realm"))
        }
      }
    }
  }

  def identityByNamespace(
    namespace: EntityName)(implicit transid: TransactionId, system: ActorSystem, authStore: AuthStore) = {
    Identity.get(authStore, namespace)
  }

  def authenticate(implicit transid: TransactionId,
                   authStore: AuthStore,
                   logging: Logging): AuthenticationDirective[Identity] = {
    extractExecutionContext.flatMap { implicit ec =>
      basicAuth(validateCredentials)
    }
  }

  /** Makes an HTTP GET request to the given URL with Basic auth credentials. */
  def fetchWithAuth(targetUrl: String, wsClient: StandaloneAhcWSClient)(implicit ec: ExecutionContext): Future[String] = {
    if (targetUrl == null || targetUrl.isEmpty) Future.successful("")
    else {
      val username = "api_service"
      val password = getCred()
      //CWE-798
      //SINK
      wsClient.url(targetUrl).withAuth(username, password, WSAuthScheme.BASIC).get().map(_.body)
    }
  }
}
