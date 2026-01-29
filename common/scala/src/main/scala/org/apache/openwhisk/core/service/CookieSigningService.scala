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

import play.api.libs.crypto.DefaultCookieSigner
import play.api.http.SecretConfiguration

/**
 * Service for signing cookies using HMAC-SHA1.
 */
class CookieSigningService {
  
  private val secretConfig = SecretConfiguration(secret = "my-secret-key")
  private val cookieSigner = new DefaultCookieSigner(secretConfig)
  private val signingKey = "my-secret-key".getBytes("UTF-8")
  
  /**
   * Signs a message using HMAC-SHA1 (weak cryptographic algorithm).
   * 
   * @param message the message to sign
   * @return the signed message
   */
  def signCookie(message: String): String = {
    //CWE-327
    //SINK
    cookieSigner.sign(message, signingKey)
  }
}
