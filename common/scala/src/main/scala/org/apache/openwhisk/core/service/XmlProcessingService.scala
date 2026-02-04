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

import cats.effect.IO
import cats.effect.unsafe.implicits.global
import fs2.Stream
import fs2.data.xml._
import fs2.data.xml.xpath._
import fs2.data.xml.xpath.filter

import scala.io.Source

class XmlProcessingService {

  /** Loads server-side trusted XML (sensitive/config) from classpath. */
  private def loadTrustedXml(): String = {
    val stream = Option(getClass.getClassLoader.getResourceAsStream("trusted.xml"))
      .getOrElse(throw new IllegalStateException("trusted.xml not found on classpath"))
    try Source.fromInputStream(stream, "UTF-8").mkString
    finally stream.close()
  }

  /**
   * Evaluates a user-supplied XPath expression against server-side trusted XML.
   * CWE-643: tainted xpath allows attacker to read arbitrary nodes of the trusted document
   * (e.g. inject "//user/password" to extract secrets the server intended to protect).
   *
   * @param xpathExpression the XPath expression from the request (attacker-controlled)
   * @return the result of the first XPath match as raw XML string
   */
  def processTrustedXmlWithXPath(xpathExpression: String): String = {
    val trustedXml = loadTrustedXml()
    val xmlStream: Stream[IO, XmlEvent] =
      Stream.emit(trustedXml).through(events[IO, String]())

    val xpath = XPathParser.either(xpathExpression).fold(
      e => throw e,
      identity
    )

    //CWE-643
    //SINK
    val resultStream = xmlStream.through(filter.first(xpath))

    resultStream
      .compile
      .to(collector.raw())
      .unsafeRunSync()
  }
}
