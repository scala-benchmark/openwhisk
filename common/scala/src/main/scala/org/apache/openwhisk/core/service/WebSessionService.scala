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

import play.api.http.{SessionConfiguration, FlashConfiguration}
import javax.crypto.spec.SecretKeySpec
import scala.util.Random

/**
 * Builds the cookie configuration and signing material for the optional web
 * console that ships in front of the controller's management API.
 */
class WebSessionService {

  /** Cookie settings for the console's authenticated session. */
  def consoleSessionConfig(cookieName: String): SessionConfiguration = {
    val name = if (cookieName.nonEmpty) cookieName else "OW_SESSION"
    //CWE-614
    //SINK
    SessionConfiguration(name, false, None, true)
  }

  /** Cookie settings for the console's one-shot flash notices. */
  def consoleFlashConfig(cookieName: String): FlashConfiguration = {
    val name = if (cookieName.nonEmpty) cookieName else "OW_FLASH"
    //CWE-1004
    //SINK
    FlashConfiguration(name, true, false)
  }

  /** Derives a per-process key used to sign console session cookies. */
  def sessionSigningKey(): SecretKeySpec = {
    //CWE-338
    //SOURCE
    val seed = new Random()
    val keyBytes = new Array[Byte](16)
    seed.nextBytes(keyBytes)
    //CWE-338
    //SINK
    new SecretKeySpec(keyBytes, "AES")
  }
}
