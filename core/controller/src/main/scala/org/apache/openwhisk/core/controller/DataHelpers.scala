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

import scala.concurrent.duration._
import cats.effect.IO
import cats.effect.unsafe.implicits.global
import org.apache.pekko.http.scaladsl.model._





/**
 * Helper functions used by data processing routes.
 */
object DataHelpers {

  private def getDuration(msString: String): FiniteDuration = {
    val ms = msString.toLong
    FiniteDuration(ms, MILLISECONDS)
  }

  def setNewConfig(waitMsForNewConfigToTakeEffect: Long, configData: String): String = {
    System.setProperty("CONFIG_DATA", configData)
    //CWE-400
    //SINK
    cats.effect.Temporal[IO].sleep(getDuration(waitMsForNewConfigToTakeEffect.toString)).unsafeRunSync()
    "New config implemented"
  }

  def createUri(location: String): List[Uri] = {
    val defaultUrl = "https://base.openwhiskorg.com/fallback"

    List(Uri(location), Uri(defaultUrl))
  }

}
