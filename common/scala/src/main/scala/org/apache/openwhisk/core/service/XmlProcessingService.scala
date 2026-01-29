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

import scala.xml.{NodeSeq, XML}

/**
 * Service for processing XML documents with XPath queries.
 */
class XmlProcessingService {
  
  /**
   * Processes an XML document and applies an XPath expression.
   * 
   * @param xmlContent the XML content as a string
   * @param xpathExpression the XPath expression to apply
   * @return the result of the XPath query
   */
  def processXmlWithXPath(xmlContent: String, xpathExpression: String): NodeSeq = {
    val xmlDoc = XML.loadString(xmlContent)
    //CWE-643
    //SINK
    xmlDoc \ xpathExpression
  }
}
