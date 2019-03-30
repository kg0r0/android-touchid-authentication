package com.example.android_touchid_authentication;

import android.app.KeyguardManager;
import android.content.Context;
import android.hardware.fingerprint.FingerprintManager;
import android.hardware.fingerprint.FingerprintManager.CryptoObject;
import android.os.Handler;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyPermanentlyInvalidatedException;
import android.security.keystore.KeyProperties;
import android.support.v4.app.DialogFragment;
import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.util.Log;
import android.view.View;
import android.widget.Button;
import android.widget.TextView;
import android.widget.Toast;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.spec.ECGenParameterSpec;

public class MainActivity extends AppCompatActivity {

    KeyguardManager mKeyguardManager;
    FingerprintManager mFingerprintManager;
    KeyPairGenerator mKeyPairGenerator;
    KeyStore mKeyStore;
    Signature mSignature;

    public static final String KEY_NAME = "my_key";
    private static final String KEY_PROVIDER = "AndroidKeyStore";

    private TextView confirmationMessage;

    private void init () {
        mKeyguardManager = (KeyguardManager) getSystemService(Context.KEYGUARD_SERVICE);
        mFingerprintManager = getApplicationContext().getSystemService(FingerprintManager.class);
        try {
            mKeyPairGenerator = KeyPairGenerator.getInstance(
                    KeyProperties.KEY_ALGORITHM_EC, KEY_PROVIDER);
            mKeyStore = KeyStore.getInstance("AndroidKeyStore");
            mSignature = Signature.getInstance("SHA256withECDSA");

        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        init();
        Button authenticateButton = (Button) findViewById(R.id.authenticate_button);
        confirmationMessage = (TextView) findViewById(R.id.confirmation_message);

        if (!mKeyguardManager.isKeyguardSecure()) {
            // Show a message that the user hasn't set up a lock screen.
            Toast.makeText(this,"Secure lock screen hasn't set up.\n"
                            + "Go to 'Settings -> Security -> Screenlock' to set up a lock screen",
                    Toast.LENGTH_LONG).show();
            authenticateButton.setEnabled(false);
            return;
        }


        if (!mFingerprintManager.hasEnrolledFingerprints()) {
            authenticateButton.setEnabled(false);
            Toast.makeText(this,
                    "Go to 'Settings -> Security -> Fingerprint' and register at least one fingerprint",
                    Toast.LENGTH_LONG).show();
            return;
        }

        createKeyPair();
        authenticateButton.setOnClickListener(v -> {
            CryptoObject mCryptoObject = initSignature();
            if(mCryptoObject != null) {
                DialogFragment dialog = new FingerPrintDiaglogFragment();
                dialog.show(getSupportFragmentManager(), "dialog");

                mFingerprintManager.authenticate(mCryptoObject, null, 0, new FingerprintManager.AuthenticationCallback() {
                    @Override
                    public void onAuthenticationError(int errorCode, CharSequence errString) {
                        Toast.makeText(MainActivity.this, "onAuthenticationError: " + errString, Toast.LENGTH_SHORT).show();
                        confirmationMessage.setText("Failed");
                        dialog.dismiss();
                    }

                    @Override
                    public void onAuthenticationHelp(int helpCode, CharSequence helpString) {
                        Toast.makeText(MainActivity.this, "onAuthenticationHelp: " + helpString, Toast.LENGTH_SHORT).show();
                        confirmationMessage.setText("Failed");
                        dialog.dismiss();
                    }

                    @Override
                    public void onAuthenticationSucceeded(FingerprintManager.AuthenticationResult result) {
                        Toast.makeText(MainActivity.this, "onAuthenticationSucceeded", Toast.LENGTH_SHORT).show();
                        Signature resultSignature = result.getCryptoObject().getSignature();
                        try {
                            SecureRandom secureRandom = SecureRandom.getInstance("SHA1PRNG");
                            secureRandom.nextBytes(new byte[32]);
                            byte[] secureRandomBytes = ByteBuffer.allocate(10).putLong(secureRandom.nextLong()).array();
                            resultSignature.update(secureRandomBytes);
                            byte[] sigBytes = resultSignature.sign();
                            PublicKey publicKey =
                                    mKeyStore.getCertificate(MainActivity.KEY_NAME).getPublicKey();
                            Signature verificationFunction = Signature.getInstance("SHA256withECDSA");
                            verificationFunction.initVerify(publicKey);
                            verificationFunction.update(secureRandomBytes);


                            // TODO 署名検証（通信）
                            if (verificationFunction.verify(sigBytes)) {
                                confirmationMessage.setText("Success");
                            } else {
                                confirmationMessage.setText("Failed");
                            }
                            confirmationMessage.setVisibility(View.VISIBLE);
                            dialog.dismiss();
                        } catch (Exception e) {
                            throw new RuntimeException(e);
                        }

                    }

                    @Override
                    public void onAuthenticationFailed() {
                        Toast.makeText(MainActivity.this, "onAuthenticationFailed", Toast.LENGTH_SHORT).show();
                        confirmationMessage.setText("Failed");
                        dialog.dismiss();
                    }
                }, new Handler());

            } else {
                Toast.makeText(this,
                        "Go to 'Settings -> Security -> Fingerprint' and register at least one fingerprint",
                        Toast.LENGTH_LONG).show();
            }
        });


    }

    private CryptoObject initSignature() {
        try {
            mKeyStore.load(null);
            PrivateKey key = (PrivateKey) mKeyStore.getKey(KEY_NAME, null);
            mSignature.initSign(key);
            CryptoObject cryptObject = new CryptoObject(mSignature);
            return cryptObject;
        } catch (KeyPermanentlyInvalidatedException e) {
            throw new RuntimeException("Failed to init Cipher", e);
        } catch (KeyStoreException | CertificateException | UnrecoverableKeyException | IOException
                | NoSuchAlgorithmException | InvalidKeyException e) {
            throw new RuntimeException("Failed to init Cipher", e);
        }
    }

    private void createKeyPair() {
        try {
            mKeyPairGenerator.initialize(
                    new KeyGenParameterSpec.Builder(KEY_NAME,
                            KeyProperties.PURPOSE_SIGN)
                            .setDigests(KeyProperties.DIGEST_SHA256)
                            .setAlgorithmParameterSpec(new ECGenParameterSpec("secp256r1"))
                            .setUserAuthenticationRequired(true)
                            .build());
            mKeyPairGenerator.generateKeyPair();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

}
