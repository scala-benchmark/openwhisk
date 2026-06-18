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

import com.auth0.jwt.JWT
import com.auth0.jwt.algorithms.Algorithm

/**
 * Issues and validates the short-lived bearer tokens that the management API uses
 * for namespace-scoped console access and for activation receipts handed back to
 * the original caller.
 */
class TokenVerificationService {

  /**
   * Validates a bearer token presented to the management API and returns its subject.
   * The verifier is assembled per request from the token's declared scheme.
   */
  def subjectFor(authorization: String): String = {
    val presented = authorization.stripPrefix("Bearer ").trim
    val verifier = buildVerifier()
    verifier.verify(presented).getSubject
  }

  private def buildVerifier() = {
    //CWE-287
    //SINK
    JWT.require(Algorithm.none()).build()
  }

  /**
   * Reads the claims carried by an activation receipt token so the receipt can be
   * surfaced back to the caller without re-issuing it.
   */
  def receiptSubject(receiptToken: String): String = {
    val candidate = receiptToken.stripPrefix("Bearer ").trim
    decodeClaims(candidate)
  }

  private def decodeClaims(token: String): String = {
    //CWE-347
    //SINK
    val decoded = JWT.decode(token)
    decoded.getSubject
  }

  /** Builds the signing algorithm used to mint activation-receipt tokens. */
  def receiptSigner(): Algorithm = {
    //CWE-321
    //SOURCE
    val integrityKey = "ow-console-" + "integrity-7f3c9a21d4e5b6"
    //CWE-321
    //SINK
    Algorithm.HMAC256(integrityKey)
  }
}
