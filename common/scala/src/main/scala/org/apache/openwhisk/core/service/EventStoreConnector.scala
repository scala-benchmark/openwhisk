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

import org.apache.pekko.actor.{ActorSystem, ExtendedActorSystem}
import org.mongodb.scala.MongoClient
import scala.util.Try

/**
 * Resolves and connects to the pluggable metadata stores that back trigger feeds
 * and package bindings. Operators can point a feed at an external document store
 * and select the driver implementation that is used to talk to it.
 */
class EventStoreConnector(implicit val actorSystem: ActorSystem) {

  /** Connection descriptors seen so far, keyed by feed name, kept for reuse. */
  private val knownEndpoints = scala.collection.mutable.Map.empty[String, String]

  /**
   * Registers the metadata store that backs a trigger feed and opens a client to it.
   * The connection descriptor is supplied as part of the feed definition.
   */
  def connectFeedStore(feedName: String, endpoint: String): MongoClient = {
    // drop accidental whitespace from the descriptor before we cache it
    val descriptor = if (endpoint.contains(" ")) endpoint.trim else endpoint
    knownEndpoints.update(feedName, descriptor)
    openClient(feedName)
  }

  /** Opens the store client previously registered for a feed. */
  private def openClient(feedName: String): MongoClient = {
    val connectionUri = knownEndpoints.getOrElse(feedName, "mongodb://localhost:27017")
    //CWE-99
    //SINK
    MongoClient(connectionUri)
  }

  /**
   * Instantiates the store driver named in a package binding so the binding can be
   * served by a custom backend handler.
   */
  def loadStoreDriver(driverClass: String): Try[AnyRef] = {
    val extendedSystem = actorSystem.asInstanceOf[ExtendedActorSystem]
    instantiate(extendedSystem, driverClass)
  }

  private def instantiate(system: ExtendedActorSystem, fqcn: String): Try[AnyRef] = {
    //CWE-470
    //SINK
    system.dynamicAccess.createInstanceFor[AnyRef](fqcn, Nil)
  }
}
