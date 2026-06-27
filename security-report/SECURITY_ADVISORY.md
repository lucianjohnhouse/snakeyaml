# Security Advisory: SnakeYAML 2.x — CompactConstructor Bypasses TagInspector Security Gate

## Summary

Multiple vulnerabilities in SnakeYAML 2.x allow attackers to bypass the `TagInspector` security control introduced after CVE-2022-1471. The most critical finding enables **Remote Code Execution** when `CompactConstructor` is used to parse untrusted YAML input — the class name is extracted from the scalar value rather than from a YAML tag, completely circumventing the `TagInspector` check.

**Affected versions:** SnakeYAML 2.0 through 2.7-SNAPSHOT (current HEAD)
**Affected component:** `org.yaml.snakeyaml.extensions.compactnotation`

---

## Finding 1: CompactConstructor Bypasses TagInspector — Arbitrary Class Instantiation (CRITICAL)

### CVSS Score: 9.8 (Critical)
**Vector:** CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H

### Description

`CompactConstructor` extracts Java class names from YAML scalar **values** (e.g., `javax.script.ScriptEngineManager()`) rather than from YAML tags. The `TagInspector` only validates YAML tags in `Composer.composeScalarNode()` (line 237-239). Since compact notation scalars use implicit tags (like `!!str`), the `TagInspector` is never consulted, and arbitrary classes are instantiated via `Class.forName()` + `getDeclaredConstructor()` + `setAccessible(true)` + `newInstance()`.

### Affected Files

- `src/main/java/org/yaml/snakeyaml/extensions/compactnotation/CompactConstructor.java`
  - Lines 73-82: `createInstance()` — calls `getClassForName()` and `setAccessible(true)` without any security check
  - Lines 159-180: `getConstructor()` — intercepts scalar values matching the compact notation regex

### Reproduction

```java
CompactConstructor constructor = new CompactConstructor();
Yaml yaml = new Yaml(constructor);
Object result = yaml.load("javax.script.ScriptEngineManager()");
// result is a live ScriptEngineManager instance — TagInspector was never consulted
```

### Impact

Any application using `CompactConstructor` or `PackageCompactConstructor` to parse untrusted YAML input is vulnerable to Remote Code Execution. The attacker can instantiate any class on the classpath that has a constructor accepting String arguments.

### Suggested Fix

Validate the class name against the `TagInspector` before calling `Class.forName()`:

```java
protected Object createInstance(ScalarNode node, CompactData data) throws Exception {
    Tag classTag = new Tag(Tag.PREFIX + data.getPrefix());
    if (classTag.isCustomGlobal()
        && !loadingConfig.getTagInspector().isGlobalTagAllowed(classTag)) {
        throw new YAMLException("Class not allowed: " + data.getPrefix());
    }
    Class<?> clazz = getClassForName(data.getPrefix());
    // ... rest unchanged
}
```

---

## Finding 2: PackageCompactConstructor Falls Back to Unrestricted Class Loading (CRITICAL)

### CVSS Score: 9.8 (Critical)
**Vector:** CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H

### Description

`PackageCompactConstructor` is designed to restrict class loading to a specific Java package. However, when the class name contains a dot (i.e., a fully-qualified name like `java.lang.Runtime`), the package restriction is bypassed entirely — the code falls through to `super.getClassForName()` which performs unrestricted `Class.forName()`.

### Affected Files

- `src/main/java/org/yaml/snakeyaml/extensions/compactnotation/PackageCompactConstructor.java`
  - Lines 28-38: `getClassForName()` — falls through to unrestricted super when name contains '.'

### Reproduction

```java
// Developer intends to restrict to com.myapp.models only
PackageCompactConstructor constructor = new PackageCompactConstructor("com.myapp.models");
Yaml yaml = new Yaml(constructor);
Object result = yaml.load("java.io.File(/etc/passwd)");
// File object created — package restriction bypassed via fully-qualified name
```

### Suggested Fix

```java
protected Class<?> getClassForName(String name) throws ClassNotFoundException {
    if (name.indexOf('.') < 0) {
        return Class.forName(packageName + "." + name);
    }
    if (name.startsWith(packageName + ".")) {
        return Class.forName(name);
    }
    throw new ClassNotFoundException("Class " + name + " is not in package " + packageName);
}
```

---

## Finding 3: Node.setType() Inverted Guard Enables Uncontrolled Type Narrowing (HIGH)

### CVSS Score: 7.5 (High)
**Vector:** CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N

### Description

`Node.setType()` has a guard condition that permits narrowing from `Object.class` (the default) to any arbitrary class, but blocks widening back. Since nodes start with `Object.class`, any call to `setType()` with a more specific class succeeds unconditionally. In `ConstructMapping.constructJavaBean2ndStep()`, the property type dictates what class a value node is narrowed to — allowing attackers to trigger instantiation of dangerous classes (e.g., `javax.sql.DataSource`, `javax.naming.InitialContext`) declared as property types in the bean hierarchy, bypassing the `TagInspector`.

### Affected Files

- `src/main/java/org/yaml/snakeyaml/nodes/Node.java` — Lines 110-113

### Suggested Fix

Invert the guard to only allow narrowing (subclass assignments), never widening:

```java
public void setType(Class<? extends Object> type) {
    if (this.type.isAssignableFrom(type)) {
        this.type = type;
    }
}
```

---

## Finding 4: Scalar Aliases Bypass maxAliasesForCollections — CPU Exhaustion DoS (HIGH)

### CVSS Score: 7.5 (High)
**Vector:** CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H

### Description

The Billion Laughs defense in `Composer.composeNode()` explicitly excludes scalar aliases from the alias counter (`nonScalarAliasesCount`). This allows thousands of scalar alias references that each trigger timestamp regex matching and Calendar construction, causing CPU exhaustion even when `maxAliasesForCollections` is set to its default of 50.

### Affected Files

- `src/main/java/org/yaml/snakeyaml/composer/Composer.java` — Lines 194-201

### Reproduction

```yaml
anchor: &a "2023-01-01T00:00:00.000000000000000000000000000000Z"
data:
  k0: *a
  k1: *a
  # ... 10,000 scalar alias references — all bypass the limit of 50
```

### Suggested Fix

Add a separate total-alias counter (scalar + non-scalar) with a configurable higher threshold.

---

## Finding 5: ConstructScalar Reflective Fallback with setAccessible(true) (HIGH)

### CVSS Score: 7.0 (High)
**Vector:** CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N

### Description

When `ConstructScalar.construct()` encounters a type not in its standard list, it falls back to finding any single-argument constructor on the type, calling `setAccessible(true)`, and invoking it with attacker-controlled arguments. Combined with Finding 3 (type narrowing), this enables instantiation of dangerous classes reachable through the JavaBean property chain, even when the `TagInspector` would block the corresponding tag.

### Affected Files

- `src/main/java/org/yaml/snakeyaml/constructor/Constructor.java` — Lines 367-404

### Suggested Fix

1. Do not call `setAccessible(true)` — only use public constructors
2. Validate target types against an allowlist before reflective instantiation
3. Consider removing the fallback entirely

---

## Disclosure Timeline

- **2026-06-27:** Vulnerabilities discovered during security audit
- **2026-06-27:** Report submitted to SnakeYAML maintainers

## Credit

Security research and vulnerability discovery.
