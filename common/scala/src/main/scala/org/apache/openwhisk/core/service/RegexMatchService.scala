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

import scala.util.matching.Regex

/**
 * Service for matching text against user-provided regex patterns.
 */
class RegexMatchService {

  /**
   * Finds all matches of the user-provided regex pattern in the given text.
   *
   * @param pattern the regex pattern (user-controlled)
   * @param text the text to search in
   * @return all matches as a string
   */
  def findMatches(pattern: String, text: String): String = {
    val regex = new Regex(pattern)
    //CWE-1333
    //SINK
    regex.findAllIn(text).mkString(",")
  }
}
