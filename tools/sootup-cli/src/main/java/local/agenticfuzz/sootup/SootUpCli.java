package local.agenticfuzz.sootup;

import java.nio.file.Files;
import java.nio.file.Path;

public final class SootUpCli {
    private SootUpCli() {}

    public static void main(String[] args) throws Exception {
        if (args.length == 0 || has(args, "--help")) {
            printHelp();
            return;
        }
        if (has(args, "--version")) {
            Package pkg = sootup.core.views.View.class.getPackage();
            String version = pkg == null ? "unknown" : String.valueOf(pkg.getImplementationVersion());
            System.out.println("SootUp CLI using sootup.core " + version);
            return;
        }
        String input = valueAfter(args, "--input");
        if (input == null) {
            throw new IllegalArgumentException("missing --input <jar-or-classes-dir>");
        }
        Path path = Path.of(input).toAbsolutePath().normalize();
        if (!Files.exists(path)) {
            throw new IllegalArgumentException("input does not exist: " + path);
        }
        Class<?> locationClass = Class.forName("sootup.java.bytecode.frontend.inputlocation.JavaClassPathAnalysisInputLocation");
        Class<?> viewClass = Class.forName("sootup.java.core.views.JavaView");
        System.out.println("{");
        System.out.println("  \"ok\": true,");
        System.out.println("  \"mode\": \"sootup-bytecode-probe\",");
        System.out.println("  \"input\": \"" + escape(path.toString()) + "\",");
        System.out.println("  \"location_class\": \"" + escape(locationClass.getName()) + "\",");
        System.out.println("  \"view_class\": \"" + escape(viewClass.getName()) + "\"");
        System.out.println("}");
    }

    private static boolean has(String[] args, String flag) {
        for (String arg : args) {
            if (flag.equals(arg)) {
                return true;
            }
        }
        return false;
    }

    private static String valueAfter(String[] args, String flag) {
        for (int i = 0; i + 1 < args.length; i++) {
            if (flag.equals(args[i])) {
                return args[i + 1];
            }
        }
        return null;
    }

    private static String escape(String value) {
        return value.replace("\\", "\\\\").replace("\"", "\\\"");
    }

    private static void printHelp() {
        System.out.println("Usage: sootup --version");
        System.out.println("   or: sootup --input <jar-or-classes-dir>");
    }
}
