package ee.forgr.biometric;

import android.content.Intent;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyPermanentlyInvalidatedException;
import android.security.keystore.KeyProperties;
import androidx.annotation.NonNull;
import androidx.appcompat.app.AppCompatActivity;
import androidx.biometric.BiometricManager;
import androidx.biometric.BiometricPrompt;
import ee.forgr.biometric.capacitornativebiometric.R;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.concurrent.Executor;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

public class AuthActivity extends AppCompatActivity {

  private static final String AUTH_KEY_ALIAS = "NativeBiometricAuthKey";
  private static final String AUTH_TRANSFORMATION = "AES/GCM/NoPadding";

  private Executor executor;
  private int maxAttempts;
  private int counter = 0;
  private BiometricPrompt biometricPrompt;
  private Cipher authCipher;

  @Override
  protected void onCreate(Bundle savedInstanceState) {
    super.onCreate(savedInstanceState);
    setContentView(R.layout.activity_auth_acitivy);

    maxAttempts = getIntent().getIntExtra("maxAttempts", 1);

    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
      executor = this.getMainExecutor();
    } else {
      executor = new Executor() {
        @Override
        public void execute(Runnable command) {
          new Handler().post(command);
        }
      };
    }

    boolean isWeakAuthenticatorAllowed = getIntent().getBooleanExtra("isWeakAuthenticatorAllowed", false);

    int allowedAuthenticators = BiometricManager.Authenticators.BIOMETRIC_STRONG;
    if (isWeakAuthenticatorAllowed)
      allowedAuthenticators = allowedAuthenticators | BiometricManager.Authenticators.BIOMETRIC_WEAK;

    BiometricPrompt.PromptInfo.Builder builder = new BiometricPrompt.PromptInfo.Builder()
        .setAllowedAuthenticators(allowedAuthenticators)
        .setTitle(
            getIntent().hasExtra("title")
                ? getIntent().getStringExtra("title")
                : "Authenticate")
        .setSubtitle(
            getIntent().hasExtra("subtitle")
                ? getIntent().getStringExtra("subtitle")
                : null)
        .setDescription(
            getIntent().hasExtra("description")
                ? getIntent().getStringExtra("description")
                : null);

    // `setDeviceCredentialAllowed` cannot be combined with CryptoObject-based auth.
    // We keep Android auth strictly biometric to preserve cryptographic
    // verification.
    builder.setNegativeButtonText(
        getIntent().hasExtra("negativeButtonText")
            ? getIntent().getStringExtra("negativeButtonText")
            : "Cancel");

    BiometricPrompt.PromptInfo promptInfo = builder.build();

    biometricPrompt = new BiometricPrompt(
        this,
        executor,
        new BiometricPrompt.AuthenticationCallback() {
          @Override
          public void onAuthenticationError(
              int errorCode,
              @NonNull CharSequence errString) {
            super.onAuthenticationError(errorCode, errString);
            int pluginErrorCode = AuthActivity.convertToPluginErrorCode(
                errorCode);
            finishActivity("error", pluginErrorCode, errString.toString());
          }

          @Override
          public void onAuthenticationSucceeded(
              @NonNull BiometricPrompt.AuthenticationResult result) {
            super.onAuthenticationSucceeded(result);
            if (!validateCryptoObject(result)) {
              finishActivity("error", 10, "Biometric security check failed");
              return;
            }
            finishActivity("success");
          }

          @Override
          public void onAuthenticationFailed() {
            super.onAuthenticationFailed();
            counter++;
            if (counter == maxAttempts) {
              biometricPrompt.cancelAuthentication();
              finishActivity(
                  "failed",
                  10,
                  "Authentication failed.");
            }
          }
        });

    BiometricPrompt.CryptoObject cryptoObject = createCryptoObject();
    if (cryptoObject == null) {
      finishActivity("error", 0, "Biometric crypto object unavailable");
      return;
    }

    biometricPrompt.authenticate(promptInfo, cryptoObject);
  }

  void finishActivity(String result) {
    finishActivity(result, null, null);
  }

  void finishActivity(String result, Integer errorCode, String errorDetails) {
    Intent intent = new Intent();
    intent.putExtra("result", result);
    if (errorCode != null) {
      intent.putExtra("errorCode", String.valueOf(errorCode));
    }
    if (errorDetails != null) {
      intent.putExtra("errorDetails", errorDetails);
    }
    setResult(RESULT_OK, intent);
    finish();
  }

  private BiometricPrompt.CryptoObject createCryptoObject() {
    try {
      authCipher = createCipher();
      return new BiometricPrompt.CryptoObject(authCipher);
    } catch (GeneralSecurityException | IOException e) {
      return null;
    }
  }

  private Cipher createCipher() throws GeneralSecurityException, IOException {
    SecretKey secretKey = getOrCreateSecretKey();
    Cipher cipher = Cipher.getInstance(AUTH_TRANSFORMATION);
    try {
      cipher.init(Cipher.ENCRYPT_MODE, secretKey);
    } catch (KeyPermanentlyInvalidatedException e) {
      deleteSecretKey();
      secretKey = getOrCreateSecretKey();
      cipher.init(Cipher.ENCRYPT_MODE, secretKey);
    }

    return cipher;
  }

  private SecretKey getOrCreateSecretKey() throws GeneralSecurityException, IOException {
    KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
    try {
      keyStore.load(null);
    } catch (CertificateException e) {
      throw new GeneralSecurityException("Failed to load AndroidKeyStore", e);
    }

    if (!keyStore.containsAlias(AUTH_KEY_ALIAS)) {
      generateSecretKey();
    }

    try {
      return (SecretKey) keyStore.getKey(AUTH_KEY_ALIAS, null);
    } catch (UnrecoverableKeyException e) {
      throw new GeneralSecurityException("Failed to retrieve biometric auth key", e);
    }
  }

  private void generateSecretKey() throws GeneralSecurityException {
    KeyGenerator keyGenerator = KeyGenerator.getInstance(
        KeyProperties.KEY_ALGORITHM_AES,
        "AndroidKeyStore");
    KeyGenParameterSpec.Builder builder = new KeyGenParameterSpec.Builder(
        AUTH_KEY_ALIAS,
        KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
        .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
        .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
        .setUserAuthenticationRequired(true);

    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
      builder.setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG);
    } else {
      builder.setUserAuthenticationValidityDurationSeconds(1);
    }

    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
      builder.setInvalidatedByBiometricEnrollment(true);
    }

    keyGenerator.init(builder.build());
    keyGenerator.generateKey();
  }

  private void deleteSecretKey() throws GeneralSecurityException, IOException {
    try {
      KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
      keyStore.load(null);
      keyStore.deleteEntry(AUTH_KEY_ALIAS);
    } catch (KeyStoreException | NoSuchAlgorithmException | CertificateException e) {
      throw new GeneralSecurityException("Failed to delete biometric auth key", e);
    }
  }

  private boolean validateCryptoObject(BiometricPrompt.AuthenticationResult result) {
    BiometricPrompt.CryptoObject cryptoObject = result.getCryptoObject();
    if (cryptoObject == null || cryptoObject.getCipher() == null) {
      return false;
    }

    if (authCipher != null && cryptoObject.getCipher() != authCipher) {
      return false;
    }

    try {
      cryptoObject.getCipher().doFinal(new byte[] { 0x00 });
      return true;
    } catch (GeneralSecurityException | IllegalStateException e) {
      return false;
    }
  }

  /**
   * Convert Auth Error Codes to plugin expected Biometric Auth Errors (in
   * README.md)
   * This way both iOS and Android return the same error codes for the same
   * authentication failure reasons.
   * !!IMPORTANT!!: Whenever this is modified, check if similar function in iOS
   * Plugin.swift needs to be modified as well
   * 
   * @see <a href=
   *      "https://developer.android.com/reference/androidx/biometric/BiometricPrompt#constants">...</a>
   * @return BiometricAuthError
   */
  public static int convertToPluginErrorCode(int errorCode) {
    switch (errorCode) {
      case BiometricPrompt.ERROR_HW_UNAVAILABLE:
      case BiometricPrompt.ERROR_HW_NOT_PRESENT:
        return 1;
      case BiometricPrompt.ERROR_LOCKOUT_PERMANENT:
        return 2;
      case BiometricPrompt.ERROR_NO_BIOMETRICS:
        return 3;
      case BiometricPrompt.ERROR_LOCKOUT:
        return 4;
      // Authentication Failure (10) Handled by `onAuthenticationFailed`.
      // App Cancel (11), Invalid Context (12), and Not Interactive (13) are not valid
      // error codes for Android.
      case BiometricPrompt.ERROR_NO_DEVICE_CREDENTIAL:
        return 14;
      case BiometricPrompt.ERROR_TIMEOUT:
      case BiometricPrompt.ERROR_CANCELED:
        return 15;
      case BiometricPrompt.ERROR_USER_CANCELED:
      case BiometricPrompt.ERROR_NEGATIVE_BUTTON:
        return 16;
      default:
        return 0;
    }
  }
}
