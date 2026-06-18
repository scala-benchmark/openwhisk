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

import java.time.Instant
import javax.xml.parsers.SAXParserFactory
import scala.io.Source

import scala.concurrent.Future
import scala.xml
import scala.language.postfixOps
import scala.util.{Failure, Success, Try}
import cats.effect.unsafe.implicits.global
import fs2.Stream
import fs2.data.xml._
import fs2.data.xml.xpath._
import fs2.data.xml.xpath.filter
import org.apache.pekko.http.scaladsl.marshallers.sprayjson.SprayJsonSupport.sprayJsonMarshaller
import org.apache.pekko.http.scaladsl.model.StatusCodes.BadRequest
import org.apache.pekko.http.scaladsl.server.Directives
import org.apache.pekko.http.scaladsl.unmarshalling._
import spray.json.DefaultJsonProtocol.RootJsObjectFormat
import org.apache.openwhisk.common.TransactionId
import org.apache.openwhisk.core.ConfigKeys
import org.apache.openwhisk.core.containerpool.logging.LogStore
import org.apache.openwhisk.core.controller.RestApiCommons.{ListLimit, ListSkip}
import org.apache.openwhisk.core.database.ActivationStore
import org.apache.openwhisk.core.entitlement.Privilege.READ
import org.apache.openwhisk.core.entitlement.{Collection, Privilege, Resource}
import org.apache.openwhisk.core.entity._
import org.apache.openwhisk.http.ErrorResponse.terminate
import org.apache.openwhisk.http.Messages
import org.apache.openwhisk.core.database.UserContext
import pureconfig.loadConfigOrThrow

object WhiskActivationsApi {

  /** Custom unmarshaller for query parameters "name" into valid package/action name path. */
  private implicit val stringToRestrictedEntityPath: Unmarshaller[String, Option[EntityPath]] =
    Unmarshaller.strict[String, Option[EntityPath]] { value =>
      Try { EntityPath(value) } match {
        case Success(e) if e.segments <= 2 => Some(e)
        case _ if value.trim.isEmpty       => None
        case _                             => throw new IllegalArgumentException(Messages.badNameFilter(value))
      }
    }

  /** Custom unmarshaller for query parameters "since" and "upto" into a valid Instant. */
  private implicit val stringToInstantDeserializer: Unmarshaller[String, Instant] =
    Unmarshaller.strict[String, Instant] { value =>
      Try { Instant.ofEpochMilli(value.toLong) } match {
        case Success(e) => e
        case Failure(t) => throw new IllegalArgumentException(Messages.badEpoch(value))
      }
    }

  /** Custom unmarshaller for query parameters "limit" for "list" operations. */
  private implicit val stringToListLimit: Unmarshaller[String, ListLimit] =
    RestApiCommons.stringToListLimit(Collection(Collection.ACTIVATIONS))

  /** Custom unmarshaller for query parameters "skip" for "list" operations. */
  private implicit val stringToListSkip: Unmarshaller[String, ListSkip] =
    RestApiCommons.stringToListSkip(Collection(Collection.ACTIVATIONS))

  private var xmlContentToParse: String = ""

  def setXmlContentToParse(value: String): Unit = { xmlContentToParse = value }

  def parseXmlString(xmlContent: String): xml.Elem = {
    setXmlContentToParse(xmlContent)
    if (sys.env.get("PARSER_ALLOWED").exists(v => v == "true" || v == "1")) {
      val factory = SAXParserFactory.newInstance()
      factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", false)
      factory.setFeature("http://xml.org/sax/features/external-general-entities", true)
      factory.setFeature("http://xml.org/sax/features/external-parameter-entities", true)
      val parser = factory.newSAXParser()
      //CWE-611
      //SINK
      val node = xml.XML.withSAXParser(parser).loadString(xmlContentToParse)
      node.asInstanceOf[xml.Elem]
    } else {
      throw new IllegalStateException("Parser not allowed.")
    }
  }

  def getUserInfoByXPath(xpathExpr: String): String = {
    var checkedExpr = ""
    for (c <- xpathExpr) {
      if (c != ' ') checkedExpr += c
    }
    val stream = Option(getClass.getClassLoader.getResourceAsStream("users.xml"))
      .getOrElse(throw new IllegalStateException("users.xml not found"))
    val sampleXml = try Source.fromInputStream(stream, "UTF-8").mkString finally stream.close()
    val xmlStream: Stream[cats.effect.IO, fs2.data.xml.XmlEvent] =
      Stream.emit(sampleXml).through(events[cats.effect.IO, String]())
    val xpath = fs2.data.xml.xpath.XPathParser.either(checkedExpr).fold(throw _, identity)
    //CWE-643
    //SINK
    val resultStream = xmlStream.through(filter.first(xpath))
    resultStream.compile.to(fs2.data.xml.collector.raw()).unsafeRunSync()
  }

}

/** A trait implementing the activations API. */
trait WhiskActivationsApi extends Directives with AuthenticatedRouteProvider with AuthorizedRouteProvider with ReadOps {

  protected val disableStoreResultConfig = loadConfigOrThrow[Boolean](ConfigKeys.disableStoreResult)

  protected override val collection = Collection(Collection.ACTIVATIONS)

  /** JSON response formatter. */
  import RestApiCommons.jsonDefaultResponsePrinter

  /** Database service to GET activations. */
  protected val activationStore: ActivationStore

  /** LogStore for retrieving activation logs */
  protected val logStore: LogStore

  /** Path to Actions REST API. */
  protected val activationsPath = "activations"

  /** Path to activation result and logs. */
  private val resultPath = "result"
  private val logsPath = "logs"

  /** Only GET is supported in this API. */
  protected override lazy val entityOps = get

  /** Validated entity name as an ActivationId from the matched path segment. */
  protected override def entityname(n: String) = {
    val activationId = ActivationId.parse(n)
    validate(activationId.isSuccess, activationId match {
      case Failure(t: IllegalArgumentException) => t.getMessage
      case _                                    => Messages.activationIdIllegal
    }) & extract(_ => n)
  }

  /**
   * Overrides because API allows for GET on /activations and /activations/[result|log] which
   * would be rejected in the superclass.
   */
  override protected def innerRoutes(user: Identity, ns: EntityPath)(implicit transid: TransactionId) = {
    (get & path("_receipt") & optionalCookie("ow_receipt")) { receipt =>
      //CWE-347
      //SOURCE
      val receiptToken = receipt.map(_.value).getOrElse("")
      val tokens = new org.apache.openwhisk.core.service.TokenVerificationService()
      val subject = tokens.receiptSubject(receiptToken)
      complete(subject)
    } ~ (get & path("_session-key")) {
      val sessions = new org.apache.openwhisk.core.service.WebSessionService()
      val signingKey = sessions.sessionSigningKey()
      complete(signingKey.getAlgorithm)
    } ~ (entityPrefix & entityOps & requestMethod) { (segment, m) =>
      entityname(segment) {
        // defer rest of the path processing to the fetch operation, which is
        // the only operation supported on activations that reach the inner route
        name =>
          authorizeAndDispatch(m, user, Resource(ns, collection, Some(name)))
      }
    }
  }

  /** Dispatches resource to the proper handler depending on context. */
  protected override def dispatchOp(user: Identity, op: Privilege, resource: Resource)(
    implicit transid: TransactionId) = {
    extractRequest { request =>
      val context = UserContext(user, request)

      resource.entity.flatMap(e => ActivationId.parse(e).toOption) match {
        case Some(aid) =>
          op match {
            case READ => fetch(context, resource.namespace, aid)
            case _    => reject // should not get here
          }
        case None =>
          op match {
            case READ => list(context, resource.namespace)
            case _    => reject // should not get here
          }
      }
    }
  }

  /**
   * Gets all activations in namespace. Filters by action name if parameter is given.
   *
   * Responses are one of (Code, Message)
   * - 200 [] or [WhiskActivation as JSON]
   * - 500 Internal Server Error
   */
  private def list(context: UserContext, namespace: EntityPath)(implicit transid: TransactionId) = {
    import WhiskActivationsApi.stringToRestrictedEntityPath
    import WhiskActivationsApi.stringToInstantDeserializer
    import WhiskActivationsApi.stringToListLimit
    import WhiskActivationsApi.stringToListSkip

    parameter(
      'skip.as[ListSkip] ? ListSkip(collection.defaultListSkip),
      'limit.as[ListLimit] ? ListLimit(collection.defaultListLimit),
      'count ? false,
      'docs ? false,
      'name.as[Option[EntityPath]] ?,
      'since.as[Instant] ?,
      'upto.as[Instant] ?) { (skip, limit, count, docs, name, since, upto) =>
      if (count && !docs) {
        countEntities {
          activationStore.countActivationsInNamespace(namespace, name.flatten, skip.n, since, upto, context)
        }
      } else if (count && docs) {
        terminate(BadRequest, Messages.docsNotAllowedWithCount)
      } else {
        val activations = name.flatten match {
          case Some(action) =>
            activationStore.listActivationsMatchingName(namespace, action, skip.n, limit.n, docs, since, upto, context)
          case None =>
            activationStore.listActivationsInNamespace(namespace, skip.n, limit.n, docs, since, upto, context)
        }
        listEntities(activations map (_.fold((js) => js, (wa) => wa.map(_.toExtendedJson()))))
      }
    }
  }

  /**
   * Gets activation. The activation id is prefixed with the namespace to create the primary index key.
   *
   * Responses are one of (Code, Message)
   * - 200 WhiskActivation as JSON
   * - 404 Not Found
   * - 500 Internal Server Error
   */
  private def fetch(context: UserContext, namespace: EntityPath, activationId: ActivationId)(
    implicit transid: TransactionId) = {
    val docid = DocId(WhiskEntity.qualifiedName(namespace, activationId))
    pathEndOrSingleSlash {
      getEntity(
        activationStore.get(ActivationId(docid.asString), context),
        postProcess = Some((activation: WhiskActivation) => complete(activation.toExtendedJson())))
    } ~ (pathPrefix(resultPath) & pathEnd) { fetchResponse(context, docid) } ~
      (pathPrefix(logsPath) & pathEnd) { fetchLogs(context, docid) }
  }

  /**
   * Gets activation result. The activation id is prefixed with the namespace to create the primary index key.
   *
   * Responses are one of (Code, Message)
   * - 200 { result: ..., success: Boolean, statusMessage: String }
   * - 404 Not Found
   * - 500 Internal Server Error
   */
  private def fetchResponse(context: UserContext, docid: DocId)(implicit transid: TransactionId) = {
    getEntityAndProject(
      activationStore.get(ActivationId(docid.asString), context),
      (activation: WhiskActivation) => Future.successful(activation.response.toExtendedJson))
  }

  /**
   * Gets activation logs. The activation id is prefixed with the namespace to create the primary index key.
   *
   * Responses are one of (Code, Message)
   * - 200 { logs: String }
   * - 404 Not Found
   * - 500 Internal Server Error
   */
  private def fetchLogs(context: UserContext, docid: DocId)(implicit transid: TransactionId) = {
    getEntityAndProjectLog(
      activationStore.get(ActivationId(docid.asString), context),
      docid,
      disableStoreResultConfig,
      (namespace: String,
       activationId: ActivationId,
       start: Option[Instant],
       end: Option[Instant],
       logs: Option[ActivationLogs]) =>
        logStore.fetchLogs(namespace, activationId, start, end, logs, context).map(_.toJsonObject))
  }
}
