/*
 * SPDX-FileCopyrightText: Copyright © 2019 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/*
This adjusted file from OWASPs Webgoat VulnerableTaskHolder.java reduces aims to add mitigations.
This code reduces the attack surface for unsafe deserialisation and blocks the direct command execution path, 
but it is still a constrained mitigation rather than a general guarantee of secure deserialisation in all cases
*/
package org.dummy.insecure.framework;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.ObjectInputStream;
import java.io.Serializable;
import java.time.LocalDateTime;
import lombok.extern.slf4j.Slf4j;
import java.io.ObjectInputFilter; // I added 

@Slf4j

public class VulnerableTaskHolder implements Serializable {

  private static final long serialVersionUID = 2;

  private String taskName;
  private String taskAction;
  private LocalDateTime requestedExecutionTime;

  public VulnerableTaskHolder(String taskName, String taskAction) {
    super();
    this.taskName = taskName;
    this.taskAction = taskAction;
    this.requestedExecutionTime = LocalDateTime.now();
  }

  @Override
  public String toString() {
    return "VulnerableTaskHolder [taskName="
        + taskName
        + ", taskAction="
        + taskAction
        + ", requestedExecutionTime="
        + requestedExecutionTime
        + "]";
  }

  /**
  Restrict deserialisation to a small allowlist of trusted classes before
  reading serialised fields. This blocks unexpected classes from being
  instantiated during object restoration and reduces the risk of
  deserialisation gadget attacks.
   */
  private void readObject(ObjectInputStream stream) throws Exception {
    // Fix 1: Apply an ObjectInputFilter allowlist to restrict deserilaisation to trusted classes
    // (Allowlist safe classes, reject all others with ';!\*').
    ObjectInputFilter filter = ObjectInputFilter.Config.createFilter( "java.time.LocalDateTime;java.lang.String;org.dummy.insecure.framework.VulnerableTaskHolder;!*");
    stream.setObjectInputFilter(filter);
    // Fix 2: Restore only the expected fields and reject stale or future-dated task objects
    // (throws InvalidClassException if object stream contains unauthorised classes).
    stream.defaultReadObject();;

    log.info("restoring task: {}", taskName);
    log.info("restoring time: {}", requestedExecutionTime);

    if (requestedExecutionTime != null
        && (requestedExecutionTime.isBefore(LocalDateTime.now().minusMinutes(10))
            || requestedExecutionTime.isAfter(LocalDateTime.now()))) {
      // Do nothing if the time is not within 10 minutes of the object’s creation time.
      log.debug(this.toString());
      throw new IllegalArgumentException("outdated");
    }

    // Fix 3: Remove the command execution sink so task data is never passed to Runtime.exec().
    // Untrusted strings restored from a stream are never passed directly to OS execution sinks.
    log.info("Task '{}' validated and queued safely without process execution.", taskName);

    // condition is here to prevent you from destroying the goat altogether
    /**if ((taskAction.startsWith("sleep") || taskAction.startsWith("ping"))
        && taskAction.length() < 22) {
      log.info("about to execute: {}", taskAction);
      try {
        Process p = Runtime.getRuntime().exec(taskAction);
        BufferedReader in = new BufferedReader(new InputStreamReader(p.getInputStream()));
        String line = null;
        while ((line = in.readLine()) != null) {
          log.info(line);
        }
      } catch (IOException e) {
        log.error("IO Exception", e);
        */
  }
}
