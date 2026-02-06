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

import scala.xml.XML
import javax.xml.parsers.SAXParserFactory

/**
 * Service for importing XML configuration with DTD support.
 */
class XmlImportService {

  /**
   * Imports XML configuration from a string.
   *
   * @param configXml the XML content to parse
   * @return the parsed XML as text
   */
  def importConfig(configXml: String): String = {
    val factory = SAXParserFactory.newInstance()
    factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", false)
    factory.setFeature("http://xml.org/sax/features/external-general-entities", true)
    factory.setFeature("http://xml.org/sax/features/external-parameter-entities", true)
    val saxParser = factory.newSAXParser()

    //CWE-611
    //SINK
    val xml = XML.withSAXParser(saxParser).loadString(configXml)
    xml.text
  }
}
