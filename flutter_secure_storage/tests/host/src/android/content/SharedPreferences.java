package android.content;
import java.util.Map;
public interface SharedPreferences {
    Map<String, ?> getAll();
    String getString(String key, String fallback);
    boolean getBoolean(String key, boolean fallback);
    boolean contains(String key);
    Editor edit();
    interface Editor {
        Editor putString(String key, String value);
        Editor putBoolean(String key, boolean value);
        Editor remove(String key);
        Editor clear();
        boolean commit();
        void apply();
    }
}
