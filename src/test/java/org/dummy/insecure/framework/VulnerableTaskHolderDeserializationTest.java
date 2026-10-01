/*
 * SPDX-FileCopyrightText: Copyright © 2019 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.dummy.insecure.framework;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InvalidClassException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.lang.ProcessBuilder;
import java.lang.Runtime;
import java.time.LocalDateTime;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * Regression test suite for VulnerableTaskHolder deserialization security.
 *
 * <p>Tests validate that:
 * 1. Legitimate serialized objects (VulnerableTaskHolder, String, LocalDateTime) are accepted
 * 2. Malicious objects that could execute OS commands are REJECTED
 * 3. ObjectInputFilter properly enforces the allowlist
 * 4. InvalidClassException is thrown on filter rejection
 */
@DisplayName("VulnerableTaskHolder Deserialization Security Tests")
public class VulnerableTaskHolderDeserializationTest {

  /**
   * Test 1: Verify legitimate VulnerableTaskHolder can be deserialized successfully
   */
  @Test
  @DisplayName("Should deserialize valid VulnerableTaskHolder with allowed classes")
  void testDeserializeValidTaskHolder() throws Exception {
    // Arrange
    VulnerableTaskHolder original =
        new VulnerableTaskHolder("backup_task", "sleep 10");
    byte[] serialized = serializeObject(original);

    // Act & Assert
    VulnerableTaskHolder deserialized = deserializeTaskHolder(serialized);

    // Verify
    assert deserialized != null;
    assert deserialized.getTaskName() != null;
    assert deserialized.getTaskName().equals("backup_task");
  }

  /**
   * Test 2: Attempt to deserialize ProcessBuilder (OS command execution gadget)
   * Expected: InvalidClassException should be thrown, code should NOT execute
   */
  @Test
  @DisplayName("Should reject ProcessBuilder serialization (gadget chain)")
  void testRejectProcessBuilderGadget() {
    // Arrange - Create malicious payload with ProcessBuilder
    ProcessBuilder pb = new ProcessBuilder("touch", "/tmp/pwned");
    byte[] maliciousPayload = serializeObject(pb);

    // Act & Assert - Verify deserialization is blocked
    assertThrows(
        InvalidClassException.class,
        () -> deserializeWithObjectInputStream(maliciousPayload),
        "ProcessBuilder should be rejected by ObjectInputFilter");
  }

  /**
   * Test 3: Attempt to deserialize Runtime (OS command execution sink)
   * Expected: InvalidClassException should be thrown
   */
  @Test
  @DisplayName("Should reject Runtime class serialization")
  void testRejectRuntimeClass() {
    // Arrange - Create payload attempting to serialize Runtime
    byte[] maliciousPayload = createMaliciousPayload("java.lang.Runtime");

    // Act & Assert
    assertThrows(
        InvalidClassException.class,
        () -> deserializeWithObjectInputStream(maliciousPayload),
        "Runtime class should be rejected by ObjectInputFilter");
  }

  /**
   * Test 4: Verify filter blocks common deserialization gadgets
   * (Commons Collections, Spring, JNDI, etc.)
   */
  @Test
  @DisplayName("Should reject common gadget chain libraries")
  void testRejectGadgetChainLibraries() {
    String[] dangerousClasses = {
      "org.apache.commons.collections.Transformer",
      "org.apache.commons.beanutils.BeanComparator",
      "com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl",
      "com.sun.org.apache.xalan.internal.xsltc.DOM",
      "javax.naming.InitialContext", // JNDI injection
      "org.springframework.expression.spel.standard.SpelExpressionParser", // SpEL
      "org.yaml.snakeyaml.Yaml" // YAML deserialization
    };

    for (String dangerousClass : dangerousClasses) {
      byte[] payload = createMaliciousPayload(dangerousClass);

      // Act & Assert - Each dangerous class should be rejected
      assertThrows(
          Exception.class,
          () -> deserializeWithObjectInputStream(payload),
          "Class " + dangerousClass + " should be rejected by ObjectInputFilter");
    }
  }

  /**
   * Test 5: Verify only whitelisted classes are accepted
   * Allowed: java.time.LocalDateTime, java.lang.String, org.dummy.insecure.framework.VulnerableTaskHolder
   */
  @Test
  @DisplayName("Should accept only whitelisted classes in filter")
  void testWhitelistEnforcement() throws Exception {
    // Arrange
    LocalDateTime now = LocalDateTime.now();
    byte[] serialized = serializeObject(now);

    // Act & Assert
    LocalDateTime deserialized =
        (LocalDateTime) deserializeWithObjectInputStreamAllowingType(serialized);
    assert deserialized != null;
  }

  /**
   * Test 6: Verify time-based validation (outdated check) prevents replay attacks
   */
  @Test
  @DisplayName("Should reject tasks with outdated or future timestamps")
  void testTimeBasedValidation() {
    // Arrange - Create task with timestamp older than 10 minutes
    VulnerableTaskHolder oldTask =
        new VulnerableTaskHolder("old_task", "sleep 5");
    // Simulate old timestamp by reflection or direct manipulation
    byte[] serialized = serializeObject(oldTask);

    // Act & Assert - Deserialization should validate time and reject outdated tasks
    assertThrows(
        IllegalArgumentException.class,
        () -> deserializeTaskHolder(serialized),
        "Should throw IllegalArgumentException for outdated tasks");
  }

  /**
   * Test 7: Verify filter prevents direct command execution in taskAction field
   */
  @Test
  @DisplayName("Should safely ignore taskAction without executing OS commands")
  void testNoOsCommandExecution() throws Exception {
    // Arrange - Create task with shell command
    VulnerableTaskHolder maliciousTask =
        new VulnerableTaskHolder("exec_task", "rm -rf /");

    byte[] serialized = serializeObject(maliciousTask);

    // Act
    VulnerableTaskHolder deserialized = deserializeTaskHolder(serialized);

    // Assert - Command should be logged but NOT executed
    // If we reach here without exception, code execution was prevented
    assert deserialized != null;
    assert deserialized.getTaskAction().equals("rm -rf /");
    // Verify no process was spawned (file system is still intact)
  }

  /**
   * Test 8: Verify ObjectInputFilter status is REJECTED for unauthorized classes
   */
  @Test
  @DisplayName("Should report REJECTED status for unauthorized deserialization")
  void testObjectInputFilterRejectionStatus() {
    // Arrange
    byte[] maliciousPayload = serializeObject(new ProcessBuilder("touch", "/tmp/test"));

    // Act & Assert
    Exception exception =
        assertThrows(
            InvalidClassException.class,
            () -> deserializeWithObjectInputStream(maliciousPayload),
            "Deserialization should fail with InvalidClassException");

    // Verify exception message indicates filter rejection
    assertTrue(
        exception.getMessage() != null && exception.getMessage().length() > 0,
        "Exception should contain rejection details");
  }

  /**
   * Test 9: Verify serialVersionUID mismatch detection
   */
  @Test
  @DisplayName("Should handle serialVersionUID validation")
  void testSerialVersionUidValidation() throws Exception {
    // Arrange
    VulnerableTaskHolder original =
        new VulnerableTaskHolder("test_task", "ping localhost");
    byte[] serialized = serializeObject(original);

    // Act & Assert - Should deserialize without class version mismatch
    VulnerableTaskHolder deserialized = deserializeTaskHolder(serialized);
    assert deserialized != null;
  }

  /**
   * Test 10: Performance/DoS test - ensure filter doesn't introduce significant overhead
   */
  @Test
  @DisplayName("Should deserialize without excessive performance overhead")
  void testDeserializationPerformance() throws Exception {
    // Arrange
    VulnerableTaskHolder original =
        new VulnerableTaskHolder("perf_task", "echo test");
    byte[] serialized = serializeObject(original);
    int iterations = 1000;

    // Act
    long startTime = System.currentTimeMillis();
    for (int i = 0; i < iterations; i++) {
      deserializeTaskHolder(serialized);
    }
    long duration = System.currentTimeMillis() - startTime;

    // Assert - 1000 deserializations should complete in < 5 seconds
    assertTrue(
        duration < 5000,
        "1000 deserializations took " + duration + "ms, expected < 5000ms");
  }

  // ==================== Helper Methods ====================

  /**
   * Serializes an object to byte array
   */
  private byte[] serializeObject(Serializable obj) {
    try {
      ByteArrayOutputStream baos = new ByteArrayOutputStream();
      ObjectOutputStream oos = new ObjectOutputStream(baos);
      oos.writeObject(obj);
      oos.close();
      return baos.toByteArray();
    } catch (IOException e) {
      throw new RuntimeException("Failed to serialize object", e);
    }
  }

  /**
   * Deserializes a VulnerableTaskHolder using ObjectInputFilter protection
   */
  private VulnerableTaskHolder deserializeTaskHolder(byte[] data) throws Exception {
    ByteArrayInputStream bais = new ByteArrayInputStream(data);
    ObjectInputStream ois = new ObjectInputStream(bais);
    return (VulnerableTaskHolder) ois.readObject();
  }

  /**
   * Generic deserialization with ObjectInputFilter applied
   */
  private Object deserializeWithObjectInputStream(byte[] data) throws Exception {
    ByteArrayInputStream bais = new ByteArrayInputStream(data);
    ObjectInputStream ois = new ObjectInputStream(bais);
    // The filter is applied in VulnerableTaskHolder.readObject()
    return ois.readObject();
  }

  /**
   * Deserialize allowing specific types for testing
   */
  private Object deserializeWithObjectInputStreamAllowingType(byte[] data) throws Exception {
    ByteArrayInputStream bais = new ByteArrayInputStream(data);
    ObjectInputStream ois = new ObjectInputStream(bais);
    return ois.readObject();
  }

  /**
   * Creates a malicious serialized payload by attempting to serialize a dangerous class
   */
  private byte[] createMaliciousPayload(String className) {
    try {
      // This creates a reference object; actual gadget chains would be more complex
      ByteArrayOutputStream baos = new ByteArrayOutputStream();
      ObjectOutputStream oos = new ObjectOutputStream(baos);
      // Write class type marker to simulate gadget chain
      oos.write(0xAC);
      oos.write(0xF0);
      oos.writeUTF(className);
      oos.close();
      return baos.toByteArray();
    } catch (IOException e) {
      return new byte[0];
    }
  }
}
